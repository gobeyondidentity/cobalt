// Package attestation provides attestation verification and gating logic.
package attestation

import (
	"fmt"
	"strings"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/store"
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
	FreshnessWindow time.Duration
}

// NewGate creates a new attestation gate with default settings.
func NewGate(s *store.Store) *Gate {
	return &Gate{
		store:           s,
		FreshnessWindow: DefaultFreshnessWindow,
	}
}

// CanDistribute checks if credentials can be distributed to the target DPU.
// Returns a decision with the result and reason.
//
// Gate logic (fail-secure):
//   - Attestation not found: blocked with "attestation unknown"
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
				Reason:      "attestation unknown",
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
