package attestation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// DefaultFreshnessWindow is the default maximum age for attestations.
const DefaultFreshnessWindow = time.Hour

// GateDecision represents the result of an attestation gate check.
type GateDecision struct {
	Allowed     bool
	Reason      string
	Attestation *store.Attestation
	Forced      bool
}

// Gate enforces attestation requirements before credential distribution.
// Implements fail-secure: unknown or invalid attestations block distribution.
type Gate struct {
	store           *store.Store
	Refresher       *Refresher // Exported for test configuration
	FreshnessWindow time.Duration
}

// NewGate creates a new attestation gate with default settings.
func NewGate(s *store.Store) *Gate {
	return &Gate{
		store:           s,
		Refresher:       NewRefresher(s),
		FreshnessWindow: DefaultFreshnessWindow,
	}
}

// CanDistribute checks if credentials can be distributed to the target DPU.
// Returns a decision with the result and reason.
//
// Gate logic (fail-secure):
//   - Attestation not found: blocked with "attestation unavailable"
//   - Status != verified: blocked with "status: {status}"
//   - Age > FreshnessWindow: blocked with "stale: {age}"
//   - Otherwise: allowed
func (g *Gate) CanDistribute(targetDPU string) (*GateDecision, error) {
	att, err := g.store.GetAttestation(targetDPU)
	if err != nil {
		// Check if it's a "not found" error
		if strings.Contains(err.Error(), "not found") {
			return &GateDecision{
				Allowed:     false,
				Reason:      "attestation unavailable",
				Attestation: nil,
			}, nil
		}
		// Actual error accessing the store
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}

	// Check attestation status
	if att.Status != store.AttestationStatusVerified {
		return &GateDecision{
			Allowed:     false,
			Reason:      fmt.Sprintf("status: %s", att.Status),
			Attestation: att,
		}, nil
	}

	// Check freshness
	age := att.Age()
	if age > g.FreshnessWindow {
		return &GateDecision{
			Allowed:     false,
			Reason:      fmt.Sprintf("stale: %s", age.Round(time.Second)),
			Attestation: att,
		}, nil
	}

	// All checks passed
	return &GateDecision{
		Allowed:     true,
		Reason:      "",
		Attestation: att,
	}, nil
}

// CanDistributeWithAutoRefresh checks attestation and auto-refreshes if stale or unavailable.
// Returns the decision, whether a refresh was attempted, and any error.
//
// Behavior:
//   - If attestation is fresh and verified: returns allowed, no refresh
//   - If attestation is stale or unavailable: triggers refresh, returns new decision
//   - If attestation has status "failed": blocks distribution (no force allowed)
//   - If refresh fails: blocks distribution with the failure reason
func (g *Gate) CanDistributeWithAutoRefresh(ctx context.Context, dpu *store.DPU, trigger, triggeredBy string) (*GateDecision, bool, error) {
	// First check current attestation state
	decision, err := g.CanDistribute(dpu.Name)
	if err != nil {
		return nil, false, err
	}

	// If allowed, no refresh needed
	if decision.Allowed {
		return decision, false, nil
	}

	// If blocked due to status "failed", do not refresh or allow force
	// A failed attestation means the device failed verification, and we should not proceed
	if decision.Attestation != nil && decision.Attestation.Status == store.AttestationStatusFailed {
		return &GateDecision{
			Allowed:     false,
			Reason:      "attestation failed: device failed integrity verification",
			Attestation: decision.Attestation,
			Forced:      false,
		}, false, nil
	}

	// Blocked due to stale or unavailable attestation: attempt refresh
	result := g.Refresher.Refresh(ctx, dpu.Address(), dpu.Name, trigger, triggeredBy)

	if result.Success {
		// Refresh succeeded, return allowed
		return &GateDecision{
			Allowed:     true,
			Reason:      "",
			Attestation: result.Attestation,
			Forced:      false,
		}, true, nil
	}

	// Refresh failed
	// Determine if the failure was due to a verification failure (status failed)
	// or just unavailability (network error, no certs, etc.)
	if result.Attestation != nil && result.Attestation.Status == store.AttestationStatusFailed {
		// Device failed attestation verification: hard block, no force allowed
		return &GateDecision{
			Allowed:     false,
			Reason:      fmt.Sprintf("attestation failed: %s", result.Message),
			Attestation: result.Attestation,
			Forced:      false,
		}, true, nil
	}

	// Unavailable (network, no certs, etc.): blocked but could potentially be forced
	return &GateDecision{
		Allowed:     false,
		Reason:      fmt.Sprintf("attestation unavailable: %s", result.Message),
		Attestation: result.Attestation,
		Forced:      false,
	}, true, nil
}

// IsAttestationFailed returns true if the decision is blocked due to a failed attestation.
// This is used to determine if --force should be allowed.
func (d *GateDecision) IsAttestationFailed() bool {
	if d.Attestation == nil {
		return false
	}
	return d.Attestation.Status == store.AttestationStatusFailed
}
