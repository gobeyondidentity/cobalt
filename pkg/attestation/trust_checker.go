package attestation

import (
	"fmt"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// TrustCheckResult summarizes what changed when checking trust for a DPU.
type TrustCheckResult struct {
	DPUName         string
	AttestationOK   bool   // True if attestation is valid and fresh
	Reason          string // Why attestation failed (if applicable)
	Suspended       int    // Number of relationships suspended
	Reactivated     int    // Number of relationships reactivated
}

// TrustChecker monitors DPU attestation status and updates trust relationships accordingly.
// When a DPU's attestation becomes invalid or stale, related trust relationships are
// automatically suspended. When attestation returns to valid, relationships are reactivated.
type TrustChecker struct {
	store           *store.Store
	FreshnessWindow time.Duration
}

// NewTrustChecker creates a new TrustChecker with default freshness window.
func NewTrustChecker(s *store.Store) *TrustChecker {
	return &TrustChecker{
		store:           s,
		FreshnessWindow: DefaultFreshnessWindow,
	}
}

// CheckAndUpdateTrust checks the attestation status for a DPU and updates
// trust relationships accordingly:
//   - If attestation is invalid/stale/unknown, suspends related trust relationships
//   - If attestation is valid, reactivates any suspended relationships for that DPU
//
// Returns a summary of what was changed.
func (tc *TrustChecker) CheckAndUpdateTrust(dpuName string) (*TrustCheckResult, error) {
	result := &TrustCheckResult{
		DPUName: dpuName,
	}

	// Create a gate to check attestation status
	gate := &Gate{
		store:           tc.store,
		FreshnessWindow: tc.FreshnessWindow,
	}

	decision, err := gate.CanDistribute(dpuName)
	if err != nil {
		return nil, fmt.Errorf("failed to check attestation: %w", err)
	}

	result.AttestationOK = decision.Allowed
	result.Reason = decision.Reason

	if decision.Allowed {
		// Attestation is valid: reactivate any suspended trust relationships
		count, err := tc.store.ReactivateTrustRelationshipsForDPU(dpuName)
		if err != nil {
			return nil, fmt.Errorf("failed to reactivate trust relationships: %w", err)
		}
		result.Reactivated = count
	} else {
		// Attestation is invalid: suspend related trust relationships
		reason := fmt.Sprintf("%s: %s", dpuName, decision.Reason)
		count, err := tc.store.SuspendTrustRelationshipsForDPU(dpuName, reason)
		if err != nil {
			return nil, fmt.Errorf("failed to suspend trust relationships: %w", err)
		}
		result.Suspended = count
	}

	return result, nil
}
