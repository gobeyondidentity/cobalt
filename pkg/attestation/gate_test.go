package attestation

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/store"
)

func setupTestStore(t *testing.T) (*store.Store, func()) {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "gate_test_*.db")
	if err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("failed to open store: %v", err)
	}

	cleanup := func() {
		s.Close()
		os.Remove(tmpFile.Name())
	}
	return s, cleanup
}

func TestGate_FreshVerifiedAttestationAllows(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	// Save a fresh verified attestation
	att := &store.Attestation{
		DPUName:       "bf3-prod-01",
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	gate := NewGate(s)
	decision, err := gate.CanDistribute("bf3-prod-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}

	if !decision.Allowed {
		t.Errorf("expected Allowed=true for fresh verified attestation, got Reason=%q", decision.Reason)
	}
	if decision.Attestation == nil {
		t.Error("expected Attestation to be populated")
	}
	if decision.Attestation.DPUName != "bf3-prod-01" {
		t.Errorf("expected DPUName=bf3-prod-01, got %q", decision.Attestation.DPUName)
	}
}

func TestGate_StaleAttestationBlocks(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	// Save an attestation older than 1 hour
	att := &store.Attestation{
		DPUName:       "bf3-stale-01",
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now().Add(-2 * time.Hour),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	gate := NewGate(s)
	decision, err := gate.CanDistribute("bf3-stale-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected Allowed=false for stale attestation")
	}
	if !strings.HasPrefix(decision.Reason, "stale:") {
		t.Errorf("expected Reason to start with 'stale:', got %q", decision.Reason)
	}
}

func TestGate_FailedAttestationBlocks(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	// Save a failed attestation
	att := &store.Attestation{
		DPUName:       "bf3-failed-01",
		Status:        store.AttestationStatusFailed,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	gate := NewGate(s)
	decision, err := gate.CanDistribute("bf3-failed-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected Allowed=false for failed attestation")
	}
	if decision.Reason != "status: failed" {
		t.Errorf("expected Reason='status: failed', got %q", decision.Reason)
	}
}

func TestGate_UnavailableAttestationBlocks(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	gate := NewGate(s)
	decision, err := gate.CanDistribute("bf3-unknown-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected Allowed=false for unavailable attestation (fail-secure)")
	}
	if decision.Reason != "attestation unavailable" {
		t.Errorf("expected Reason='attestation unavailable', got %q", decision.Reason)
	}
	if decision.Attestation != nil {
		t.Error("expected Attestation to be nil for unavailable DPU")
	}
}

func TestGate_CustomFreshnessWindow(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	// Save an attestation 30 minutes old
	att := &store.Attestation{
		DPUName:       "bf3-custom-01",
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now().Add(-30 * time.Minute),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	gate := NewGate(s)

	// With default 1h window, should be allowed
	decision, err := gate.CanDistribute("bf3-custom-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("expected Allowed=true with 1h window, got Reason=%q", decision.Reason)
	}

	// With 15m window, should be blocked
	gate.FreshnessWindow = 15 * time.Minute
	decision, err = gate.CanDistribute("bf3-custom-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}
	if decision.Allowed {
		t.Error("expected Allowed=false with 15m window for 30m old attestation")
	}
	if !strings.HasPrefix(decision.Reason, "stale:") {
		t.Errorf("expected Reason to start with 'stale:', got %q", decision.Reason)
	}
}

func TestGate_UnavailableStatusBlocks(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	// Save an attestation with unavailable status
	att := &store.Attestation{
		DPUName:       "bf3-unavailable-status-01",
		Status:        store.AttestationStatusUnavailable,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	gate := NewGate(s)
	decision, err := gate.CanDistribute("bf3-unavailable-status-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected Allowed=false for unavailable status attestation")
	}
	if decision.Reason != "status: unavailable" {
		t.Errorf("expected Reason='status: unavailable', got %q", decision.Reason)
	}
}

func TestGate_DefaultFreshnessWindow(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	gate := NewGate(s)
	if gate.FreshnessWindow != time.Hour {
		t.Errorf("expected default FreshnessWindow=1h, got %v", gate.FreshnessWindow)
	}
}

// Tests for CanDistributeWithAutoRefresh

func TestGate_AutoRefresh_FreshAttestationNoRefresh(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	// Register a DPU
	if err := s.Add("dpu-1", "bf3-fresh-01", "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}

	// Save a fresh verified attestation
	att := &store.Attestation{
		DPUName:       "bf3-fresh-01",
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	dpu, err := s.Get("bf3-fresh-01")
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}

	gate := NewGate(s)
	decision, refreshed, err := gate.CanDistributeWithAutoRefresh(
		context.Background(),
		dpu,
		"auto:distribution",
		"test@example.com",
	)
	if err != nil {
		t.Fatalf("CanDistributeWithAutoRefresh failed: %v", err)
	}

	if !decision.Allowed {
		t.Errorf("expected Allowed=true for fresh attestation, got Reason=%q", decision.Reason)
	}
	if refreshed {
		t.Error("expected refreshed=false for fresh attestation")
	}
}

func TestGate_AutoRefresh_FailedAttestationBlocksNoRefresh(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	// Register a DPU
	if err := s.Add("dpu-2", "bf3-failed-02", "192.168.1.101", 50051); err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}

	// Save a failed attestation (device failed verification)
	att := &store.Attestation{
		DPUName:       "bf3-failed-02",
		Status:        store.AttestationStatusFailed,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	dpu, err := s.Get("bf3-failed-02")
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}

	gate := NewGate(s)
	decision, refreshed, err := gate.CanDistributeWithAutoRefresh(
		context.Background(),
		dpu,
		"auto:distribution",
		"test@example.com",
	)
	if err != nil {
		t.Fatalf("CanDistributeWithAutoRefresh failed: %v", err)
	}

	// Failed attestation should block without attempting refresh
	if decision.Allowed {
		t.Error("expected Allowed=false for failed attestation")
	}
	if refreshed {
		t.Error("expected refreshed=false for failed attestation (should not attempt refresh)")
	}
	if !strings.Contains(decision.Reason, "failed") {
		t.Errorf("expected Reason to contain 'failed', got %q", decision.Reason)
	}
}

func TestGate_IsAttestationFailed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		decision *GateDecision
		want     bool
	}{
		{
			name: "nil attestation",
			decision: &GateDecision{
				Allowed:     false,
				Attestation: nil,
			},
			want: false,
		},
		{
			name: "verified attestation",
			decision: &GateDecision{
				Allowed: true,
				Attestation: &store.Attestation{
					Status: store.AttestationStatusVerified,
				},
			},
			want: false,
		},
		{
			name: "failed attestation",
			decision: &GateDecision{
				Allowed: false,
				Attestation: &store.Attestation{
					Status: store.AttestationStatusFailed,
				},
			},
			want: true,
		},
		{
			name: "stale attestation",
			decision: &GateDecision{
				Allowed: false,
				Attestation: &store.Attestation{
					Status: store.AttestationStatusVerified, // verified but stale
				},
			},
			want: false,
		},
		{
			name: "unavailable status attestation",
			decision: &GateDecision{
				Allowed: false,
				Attestation: &store.Attestation{
					Status: store.AttestationStatusUnavailable,
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.decision.IsAttestationFailed()
			if got != tt.want {
				t.Errorf("IsAttestationFailed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRefresher_SavesAttestationResult(t *testing.T) {
	t.Parallel()
	s, cleanup := setupTestStore(t)
	defer cleanup()

	refresher := NewRefresher(s)

	// Use private method to test saving attestation
	rawData := map[string]any{
		"trigger":      "auto:distribution",
		"triggered_by": "test@example.com",
	}

	att := refresher.saveAttestationResult(
		"bf3-test-save",
		store.AttestationStatusVerified,
		strPtr("dice-hash-123"),
		strPtr("meas-hash-456"),
		rawData,
	)

	if att.DPUName != "bf3-test-save" {
		t.Errorf("expected DPUName=bf3-test-save, got %q", att.DPUName)
	}
	if att.Status != store.AttestationStatusVerified {
		t.Errorf("expected Status=verified, got %q", att.Status)
	}
	if att.DICEChainHash != "dice-hash-123" {
		t.Errorf("expected DICEChainHash=dice-hash-123, got %q", att.DICEChainHash)
	}
	if att.MeasurementsHash != "meas-hash-456" {
		t.Errorf("expected MeasurementsHash=meas-hash-456, got %q", att.MeasurementsHash)
	}

	// Verify it was saved to the store
	saved, err := s.GetAttestation("bf3-test-save")
	if err != nil {
		t.Fatalf("GetAttestation failed: %v", err)
	}
	if saved.Status != store.AttestationStatusVerified {
		t.Errorf("expected saved Status=verified, got %q", saved.Status)
	}

	// Check raw data includes trigger info
	if saved.RawData["trigger"] != "auto:distribution" {
		t.Errorf("expected trigger=auto:distribution, got %v", saved.RawData["trigger"])
	}
	if saved.RawData["triggered_by"] != "test@example.com" {
		t.Errorf("expected triggered_by=test@example.com, got %v", saved.RawData["triggered_by"])
	}
}

func TestRefreshResult_Success(t *testing.T) {
	t.Parallel()
	result := &RefreshResult{
		Success: true,
		Attestation: &store.Attestation{
			DPUName: "bf3-test",
			Status:  store.AttestationStatusVerified,
		},
		Error:   nil,
		Message: "attestation verified",
	}

	if !result.Success {
		t.Error("expected Success=true")
	}
	if result.Error != nil {
		t.Errorf("expected Error=nil, got %v", result.Error)
	}
}

func TestRefreshResult_Failure(t *testing.T) {
	t.Parallel()
	result := &RefreshResult{
		Success: false,
		Attestation: &store.Attestation{
			DPUName: "bf3-test",
			Status:  store.AttestationStatusFailed,
		},
		Error:   fmt.Errorf("connection failed"),
		Message: "attestation failed: connection failed",
	}

	if result.Success {
		t.Error("expected Success=false")
	}
	if result.Error == nil {
		t.Error("expected Error to be set")
	}
}

// strPtr is a helper for tests
func strPtr(s string) *string {
	return &s
}

// Tests for attestation rejection (negative cases)
// These tests verify the acceptance criteria from bead si-jgp.6

func TestGate_RejectionLeavesNoState(t *testing.T) {
	t.Parallel()
	// Test: denied enrollment does not create any state (no partial DPU registration)
	s, cleanup := setupTestStore(t)
	defer cleanup()

	// Save a failed attestation for a known DPU
	att := &store.Attestation{
		DPUName:       "bf3-failed-state-01",
		Status:        store.AttestationStatusFailed,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	// Record the initial attestation state
	initialAtt, err := s.GetAttestation("bf3-failed-state-01")
	if err != nil {
		t.Fatalf("GetAttestation failed: %v", err)
	}
	initialUpdatedAt := initialAtt.UpdatedAt

	// Attempt distribution (should be denied)
	gate := NewGate(s)
	decision, err := gate.CanDistribute("bf3-failed-state-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}

	if decision.Allowed {
		t.Fatal("expected distribution to be denied for failed attestation")
	}

	// Verify no state change occurred: attestation record should be unchanged
	afterAtt, err := s.GetAttestation("bf3-failed-state-01")
	if err != nil {
		t.Fatalf("GetAttestation after denial failed: %v", err)
	}

	// Attestation should not have been modified by the gate check
	if !afterAtt.UpdatedAt.Equal(initialUpdatedAt) {
		t.Errorf("attestation UpdatedAt changed after denial: before=%v, after=%v",
			initialUpdatedAt, afterAtt.UpdatedAt)
	}
	if afterAtt.Status != store.AttestationStatusFailed {
		t.Errorf("attestation status changed after denial: expected=failed, got=%s", afterAtt.Status)
	}

	// Verify no new records were created for unknown DPUs
	_, err = s.GetAttestation("bf3-unknown-never-existed")
	if err == nil {
		t.Error("expected error for unknown DPU, but found attestation record")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestGate_RejectionDecisionContainsAuditDetails(t *testing.T) {
	t.Parallel()
	// Test: denied enrollment logged with full details for audit
	// Verifies GateDecision contains sufficient information for audit logging

	tests := []struct {
		name              string
		setupAttestation  *store.Attestation
		dpuName           string
		expectedAllowed   bool
		expectedHasAtt    bool   // should decision.Attestation be populated?
		expectedReasonPfx string // prefix to check in Reason
		verifyAuditFields func(t *testing.T, d *GateDecision)
	}{
		{
			name: "failed attestation has full audit details",
			setupAttestation: &store.Attestation{
				DPUName:          "bf3-audit-failed",
				Status:           store.AttestationStatusFailed,
				LastValidated:    time.Now(),
				DICEChainHash:    "sha256:abc123",
				MeasurementsHash: "sha256:def456",
			},
			dpuName:           "bf3-audit-failed",
			expectedAllowed:   false,
			expectedHasAtt:    true,
			expectedReasonPfx: "status: failed",
			verifyAuditFields: func(t *testing.T, d *GateDecision) {
				// Verify attestation snapshot is included for audit
				if d.Attestation.DICEChainHash != "sha256:abc123" {
					t.Errorf("DICEChainHash not preserved: got %s", d.Attestation.DICEChainHash)
				}
				if d.Attestation.MeasurementsHash != "sha256:def456" {
					t.Errorf("MeasurementsHash not preserved: got %s", d.Attestation.MeasurementsHash)
				}
				if d.Attestation.Status != store.AttestationStatusFailed {
					t.Errorf("Status not preserved: got %s", d.Attestation.Status)
				}
			},
		},
		{
			name: "stale attestation has timestamp for audit",
			setupAttestation: &store.Attestation{
				DPUName:          "bf3-audit-stale",
				Status:           store.AttestationStatusVerified,
				LastValidated:    time.Now().Add(-2 * time.Hour),
				DICEChainHash:    "sha256:old123",
				MeasurementsHash: "sha256:old456",
			},
			dpuName:           "bf3-audit-stale",
			expectedAllowed:   false,
			expectedHasAtt:    true,
			expectedReasonPfx: "stale:",
			verifyAuditFields: func(t *testing.T, d *GateDecision) {
				// Verify reason includes age information
				if !strings.Contains(d.Reason, "h") && !strings.Contains(d.Reason, "m") {
					t.Errorf("stale reason should include duration, got: %s", d.Reason)
				}
				// Verify attestation age can be computed for audit
				age := d.Attestation.Age()
				if age < time.Hour {
					t.Errorf("attestation age should be >1h for audit, got: %v", age)
				}
			},
		},
		{
			name:              "unavailable attestation has clear reason for audit",
			setupAttestation:  nil, // no attestation exists
			dpuName:           "bf3-audit-unavailable",
			expectedAllowed:   false,
			expectedHasAtt:    false,
			expectedReasonPfx: "attestation unavailable",
			verifyAuditFields: func(t *testing.T, d *GateDecision) {
				// For unavailable, we verify the reason is clear and actionable
				if d.Reason != "attestation unavailable" {
					t.Errorf("expected exact reason 'attestation unavailable', got: %s", d.Reason)
				}
				// Attestation should be nil (fail-secure)
				if d.Attestation != nil {
					t.Error("expected nil Attestation for unavailable DPU")
				}
			},
		},
		{
			name: "pending attestation has status for audit",
			setupAttestation: &store.Attestation{
				DPUName:       "bf3-audit-pending",
				Status:        store.AttestationStatusPending,
				LastValidated: time.Now(),
			},
			dpuName:           "bf3-audit-pending",
			expectedAllowed:   false,
			expectedHasAtt:    true,
			expectedReasonPfx: "status: pending",
			verifyAuditFields: func(t *testing.T, d *GateDecision) {
				// Verify pending status is visible for audit
				if d.Attestation.Status != store.AttestationStatusPending {
					t.Errorf("expected pending status, got: %s", d.Attestation.Status)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, cleanup := setupTestStore(t)
			defer cleanup()

			// Setup attestation if provided
			if tt.setupAttestation != nil {
				if err := s.SaveAttestation(tt.setupAttestation); err != nil {
					t.Fatalf("SaveAttestation failed: %v", err)
				}
			}

			gate := NewGate(s)
			decision, err := gate.CanDistribute(tt.dpuName)
			if err != nil {
				t.Fatalf("CanDistribute failed: %v", err)
			}

			// Verify basic decision fields
			if decision.Allowed != tt.expectedAllowed {
				t.Errorf("Allowed: got %v, want %v", decision.Allowed, tt.expectedAllowed)
			}

			if tt.expectedHasAtt && decision.Attestation == nil {
				t.Error("expected Attestation to be populated for audit")
			}
			if !tt.expectedHasAtt && decision.Attestation != nil {
				t.Error("expected Attestation to be nil")
			}

			if !strings.HasPrefix(decision.Reason, tt.expectedReasonPfx) {
				t.Errorf("Reason: got %q, want prefix %q", decision.Reason, tt.expectedReasonPfx)
			}

			// Run custom audit field verification
			if tt.verifyAuditFields != nil {
				tt.verifyAuditFields(t, decision)
			}
		})
	}
}

func TestGate_MultipleRejectionScenariosNoSideEffects(t *testing.T) {
	t.Parallel()
	// Comprehensive test: multiple rejection scenarios in sequence
	// Verifies that consecutive denials don't accumulate state
	s, cleanup := setupTestStore(t)
	defer cleanup()

	gate := NewGate(s)

	// Attempt 1: Unknown DPU (should not create any state)
	decision1, err := gate.CanDistribute("unknown-dpu-1")
	if err != nil {
		t.Fatalf("CanDistribute unknown-dpu-1 failed: %v", err)
	}
	if decision1.Allowed {
		t.Error("expected denial for unknown-dpu-1")
	}

	// Attempt 2: Another unknown DPU
	decision2, err := gate.CanDistribute("unknown-dpu-2")
	if err != nil {
		t.Fatalf("CanDistribute unknown-dpu-2 failed: %v", err)
	}
	if decision2.Allowed {
		t.Error("expected denial for unknown-dpu-2")
	}

	// Verify neither created any attestation records
	atts, err := s.ListAttestations()
	if err != nil {
		t.Fatalf("ListAttestations failed: %v", err)
	}
	if len(atts) != 0 {
		t.Errorf("expected 0 attestation records, got %d", len(atts))
		for _, a := range atts {
			t.Logf("  unexpected attestation: %s (status=%s)", a.DPUName, a.Status)
		}
	}

	// Now add a failed attestation and verify denial doesn't change it
	failedAtt := &store.Attestation{
		DPUName:       "multi-test-dpu",
		Status:        store.AttestationStatusFailed,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(failedAtt); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	// Multiple denial attempts
	for i := 0; i < 3; i++ {
		decision, err := gate.CanDistribute("multi-test-dpu")
		if err != nil {
			t.Fatalf("CanDistribute attempt %d failed: %v", i, err)
		}
		if decision.Allowed {
			t.Errorf("attempt %d: expected denial", i)
		}
	}

	// Verify only the one attestation exists (no duplicates created)
	atts, err = s.ListAttestations()
	if err != nil {
		t.Fatalf("ListAttestations failed: %v", err)
	}
	if len(atts) != 1 {
		t.Errorf("expected 1 attestation record, got %d", len(atts))
	}
	if atts[0].DPUName != "multi-test-dpu" {
		t.Errorf("unexpected DPU name: %s", atts[0].DPUName)
	}
}
