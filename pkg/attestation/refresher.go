package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	agentv1 "github.com/gobeyondidentity/cobalt/gen/go/agent/v1"
	"github.com/gobeyondidentity/cobalt/pkg/grpcclient"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// AttestationClient defines the interface for fetching attestation from DPUs.
// This abstraction enables testing without real gRPC connections.
type AttestationClient interface {
	GetAttestation(ctx context.Context, target string) (*agentv1.GetAttestationResponse, error)
	Close() error
}

// AttestationClientFactory creates AttestationClient instances.
// The default implementation wraps grpcclient.NewClient.
type AttestationClientFactory func(address string) (AttestationClient, error)

// RefreshResult contains the outcome of an attestation refresh.
type RefreshResult struct {
	Success     bool
	Attestation *store.Attestation
	Error       error
	Message     string // Human-readable status
}

// DefaultRefreshTimeout is the default timeout for attestation refresh RPCs.
const DefaultRefreshTimeout = 10 * time.Second

// Refresher handles auto-refreshing attestation from DPUs.
type Refresher struct {
	store         *store.Store
	Timeout       time.Duration // RPC timeout; defaults to DefaultRefreshTimeout
	clientFactory AttestationClientFactory
}

// NewRefresher creates a new attestation refresher.
func NewRefresher(s *store.Store) *Refresher {
	return &Refresher{
		store:         s,
		Timeout:       DefaultRefreshTimeout,
		clientFactory: defaultClientFactory,
	}
}

// WithClientFactory sets a custom client factory for testing.
func (r *Refresher) WithClientFactory(f AttestationClientFactory) *Refresher {
	r.clientFactory = f
	return r
}

// defaultClientFactory wraps grpcclient.NewClient to implement AttestationClientFactory.
func defaultClientFactory(address string) (AttestationClient, error) {
	return grpcclient.NewClient(address)
}

// Refresh fetches fresh attestation from a DPU and saves it.
// The trigger indicates how the refresh was initiated (e.g., "auto:distribution").
// The triggeredBy field should be the operator email for audit trail.
func (r *Refresher) Refresh(ctx context.Context, dpuAddress, dpuName, trigger, triggeredBy string) *RefreshResult {
	// Connect to DPU via gRPC
	factory := r.clientFactory
	if factory == nil {
		factory = defaultClientFactory
	}
	client, err := factory(dpuAddress)
	if err != nil {
		return &RefreshResult{
			Success: false,
			Error:   err,
			Message: fmt.Sprintf("connection failed: %v", err),
		}
	}
	defer client.Close()

	// Set timeout for attestation request
	timeout := r.Timeout
	if timeout == 0 {
		timeout = DefaultRefreshTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Call GetAttestation with target "IRoT" (DPU attestation)
	resp, err := client.GetAttestation(reqCtx, "IRoT")
	if err != nil {
		// Save failed attestation state
		att := r.saveAttestationResult(dpuName, store.AttestationStatusFailed, nil, nil, map[string]any{
			"error":        err.Error(),
			"trigger":      trigger,
			"triggered_by": triggeredBy,
		})
		return &RefreshResult{
			Success:     false,
			Attestation: att,
			Error:       err,
			Message:     fmt.Sprintf("attestation failed: %v", err),
		}
	}

	// No certificates means unavailable
	if len(resp.Certificates) == 0 {
		att := r.saveAttestationResult(dpuName, store.AttestationStatusUnavailable, nil, nil, map[string]any{
			"reason":       "no certificates",
			"trigger":      trigger,
			"triggered_by": triggeredBy,
		})
		return &RefreshResult{
			Success:     false,
			Attestation: att,
			Error:       fmt.Errorf("no certificates available"),
			Message:     "attestation unavailable: no certificates",
		}
	}

	// Check attestation status from response
	if resp.Status != agentv1.AttestationStatus_ATTESTATION_STATUS_VALID {
		att := r.saveAttestationResult(dpuName, store.AttestationStatusFailed, nil, nil, map[string]any{
			"status":       resp.Status.String(),
			"reason":       "attestation verification failed",
			"trigger":      trigger,
			"triggered_by": triggeredBy,
		})
		return &RefreshResult{
			Success:     false,
			Attestation: att,
			Error:       fmt.Errorf("attestation status: %s", resp.Status.String()),
			Message:     fmt.Sprintf("attestation failed: %s", resp.Status.String()),
		}
	}

	// Compute hashes for DICE chain and measurements
	diceHash, measHash := r.computeAttestationHashes(resp)

	// Save successful attestation
	att := r.saveAttestationResult(dpuName, store.AttestationStatusVerified, diceHash, measHash, map[string]any{
		"target":       "IRoT",
		"status":       resp.Status.String(),
		"certificates": len(resp.Certificates),
		"measurements": len(resp.Measurements),
		"trigger":      trigger,
		"triggered_by": triggeredBy,
	})

	return &RefreshResult{
		Success:     true,
		Attestation: att,
		Error:       nil,
		Message:     "attestation verified",
	}
}

// computeAttestationHashes computes SHA256 hashes for DICE chain and measurements.
func (r *Refresher) computeAttestationHashes(resp *agentv1.GetAttestationResponse) (*string, *string) {
	var diceHash, measHash *string

	// Hash DICE chain (concatenate all certificate PEMs)
	if len(resp.Certificates) > 0 {
		h := sha256.New()
		for _, cert := range resp.Certificates {
			h.Write([]byte(cert.Pem))
		}
		hash := hex.EncodeToString(h.Sum(nil))
		diceHash = &hash
	}

	// Hash measurements
	if len(resp.Measurements) > 0 {
		// Serialize measurements to JSON for consistent hashing
		measJSON, err := json.Marshal(resp.Measurements)
		if err == nil {
			h := sha256.Sum256(measJSON)
			hash := hex.EncodeToString(h[:])
			measHash = &hash
		}
	}

	return diceHash, measHash
}

// saveAttestationResult persists attestation result to the database and returns the attestation.
func (r *Refresher) saveAttestationResult(dpuName string, status store.AttestationStatus, diceHash, measHash *string, rawData map[string]any) *store.Attestation {
	att := &store.Attestation{
		DPUName:       dpuName,
		Status:        status,
		LastValidated: time.Now(),
		RawData:       rawData,
	}

	if diceHash != nil {
		att.DICEChainHash = *diceHash
	}
	if measHash != nil {
		att.MeasurementsHash = *measHash
	}

	// Save to store (ignore errors, attestation is still returned)
	_ = r.store.SaveAttestation(att)

	return att
}
