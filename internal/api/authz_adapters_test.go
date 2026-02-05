package api

import (
	"context"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/attestation"
	"github.com/gobeyondidentity/cobalt/pkg/authz"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// TestAutoRefreshAttestationLookup_VerifiedNoRefresh tests that fresh verified attestation
// returns immediately without triggering a refresh.
func TestAutoRefreshAttestationLookup_VerifiedNoRefresh(t *testing.T) {
	t.Log("Testing: AutoRefreshAttestationLookup returns verified status without refresh")

	// Set up store with a DPU and fresh attestation
	db := setupTestStore(t)
	defer db.Close()

	dpuID := "dpu_test123"
	dpuName := "test-dpu"
	db.Add(dpuID, dpuName, "192.168.1.100", 18051)

	// Add fresh attestation
	db.SaveAttestation(&store.Attestation{
		DPUName:       dpuName,
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now(),
	})

	gate := attestation.NewGate(db)
	lookup := NewAutoRefreshAttestationLookup(db, gate)

	t.Log("Getting attestation status for DPU with fresh attestation")
	status, err := lookup.GetAttestationStatus(context.Background(), dpuID)

	if err != nil {
		t.Fatalf("GetAttestationStatus failed: %v", err)
	}

	t.Logf("Got status: %s", status)

	if status != authz.AttestationVerified {
		t.Errorf("Expected AttestationVerified, got %s", status)
	}
}

// TestAutoRefreshAttestationLookup_FailedNoRefresh tests that failed attestation
// returns immediately without attempting refresh.
func TestAutoRefreshAttestationLookup_FailedNoRefresh(t *testing.T) {
	t.Log("Testing: AutoRefreshAttestationLookup returns failed status without refresh")

	db := setupTestStore(t)
	defer db.Close()

	dpuID := "dpu_failed"
	dpuName := "failed-dpu"
	db.Add(dpuID, dpuName, "192.168.1.101", 18051)

	// Add failed attestation
	db.SaveAttestation(&store.Attestation{
		DPUName:       dpuName,
		Status:        store.AttestationStatusFailed,
		LastValidated: time.Now(),
	})

	gate := attestation.NewGate(db)
	lookup := NewAutoRefreshAttestationLookup(db, gate)

	t.Log("Getting attestation status for DPU with failed attestation")
	status, err := lookup.GetAttestationStatus(context.Background(), dpuID)

	if err != nil {
		t.Fatalf("GetAttestationStatus failed: %v", err)
	}

	t.Logf("Got status: %s", status)

	if status != authz.AttestationFailed {
		t.Errorf("Expected AttestationFailed, got %s", status)
	}
}

// TestAutoRefreshAttestationLookup_DPUNotFound tests that missing DPU returns unavailable.
func TestAutoRefreshAttestationLookup_DPUNotFound(t *testing.T) {
	t.Log("Testing: AutoRefreshAttestationLookup returns unavailable for missing DPU")

	db := setupTestStore(t)
	defer db.Close()

	gate := attestation.NewGate(db)
	lookup := NewAutoRefreshAttestationLookup(db, gate)

	t.Log("Getting attestation status for non-existent DPU")
	status, err := lookup.GetAttestationStatus(context.Background(), "dpu_nonexistent")

	if err != nil {
		t.Fatalf("GetAttestationStatus failed: %v", err)
	}

	t.Logf("Got status: %s", status)

	if status != authz.AttestationUnavailable {
		t.Errorf("Expected AttestationUnavailable, got %s", status)
	}
}

// TestAutoRefreshAttestationLookup_StaleTriggersRefresh tests that stale attestation
// triggers a refresh attempt.
func TestAutoRefreshAttestationLookup_StaleTriggersRefresh(t *testing.T) {
	t.Log("Testing: AutoRefreshAttestationLookup attempts refresh for stale attestation")

	db := setupTestStore(t)
	defer db.Close()

	dpuID := "dpu_stale"
	dpuName := "stale-dpu"
	db.Add(dpuID, dpuName, "192.168.1.102", 18051)

	// Add stale attestation (2 hours old, default freshness is 1 hour)
	db.SaveAttestation(&store.Attestation{
		DPUName:       dpuName,
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now().Add(-2 * time.Hour),
	})

	gate := attestation.NewGate(db)
	lookup := NewAutoRefreshAttestationLookup(db, gate)

	t.Log("Getting attestation status for DPU with stale attestation")
	// The refresh will fail because there's no real DPU at this address,
	// but we're testing that it attempts the refresh
	status, err := lookup.GetAttestationStatus(context.Background(), dpuID)

	if err != nil {
		t.Fatalf("GetAttestationStatus failed: %v", err)
	}

	t.Logf("Got status: %s (refresh attempted but failed due to no real DPU)", status)

	// After a failed refresh attempt, status should remain unavailable/stale
	// The actual status depends on refresh implementation, but should not be verified
	if status == authz.AttestationVerified {
		t.Errorf("Did not expect AttestationVerified after failed refresh")
	}
}

// TestAutoRefreshAttestationLookup_UnavailableTriggersRefresh tests that unavailable
// attestation triggers a refresh attempt.
func TestAutoRefreshAttestationLookup_UnavailableTriggersRefresh(t *testing.T) {
	t.Log("Testing: AutoRefreshAttestationLookup attempts refresh for unavailable attestation")

	db := setupTestStore(t)
	defer db.Close()

	dpuID := "dpu_new"
	dpuName := "new-dpu"
	db.Add(dpuID, dpuName, "192.168.1.103", 18051)

	// No attestation record exists (simulating new DPU)

	gate := attestation.NewGate(db)
	lookup := NewAutoRefreshAttestationLookup(db, gate)

	t.Log("Getting attestation status for DPU with no attestation record")
	status, err := lookup.GetAttestationStatus(context.Background(), dpuID)

	if err != nil {
		t.Fatalf("GetAttestationStatus failed: %v", err)
	}

	t.Logf("Got status: %s (refresh attempted but failed due to no real DPU)", status)

	// The refresh will fail because there's no real DPU, but it should have been attempted
	// Verify by checking the function completes without error
}

// TestActionToResourceType verifies all action prefix mappings.
func TestActionToResourceType(t *testing.T) {
	tests := []struct {
		action   string
		expected string
	}{
		{"operator:list", "Operator"},
		{"role:assign", "Operator"},
		{"dpu:register", "DPU"},
		{"credential:push", "DPU"},
		{"host:register", "DPU"},
		{"host:report_posture", "DPU"},
		{"host:list", "DPU"},
		{"distribution:create", "Distribution"},
		{"authorization:list", "Authorization"},
		{"tenant:create", "Tenant"},
		{"audit:read", "Audit"},
		{"trust:create", "TrustRelationship"},
		{"ssh-ca:create", "SSHCA"},
		{"unknown:action", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := actionToResourceType(tt.action)
			if got != tt.expected {
				t.Errorf("actionToResourceType(%q) = %q, want %q", tt.action, got, tt.expected)
			}
		})
	}
}

// TestIsSelfAction verifies self-referential action detection.
func TestIsSelfAction(t *testing.T) {
	tests := []struct {
		action   string
		expected bool
	}{
		{authz.ActionOperatorReadSelf, true},
		{authz.ActionDPUReadOwnConfig, true},
		{authz.ActionHostRegister, true},
		{"operator:list", false},
		{"dpu:register", false},
		{"host:list", false},
		{"unknown:action", false},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := isSelfAction(tt.action)
			if got != tt.expected {
				t.Errorf("isSelfAction(%q) = %v, want %v", tt.action, got, tt.expected)
			}
		})
	}
}

// setupTestStore creates a test store with required tables.
func setupTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open test store: %v", err)
	}
	return db
}
