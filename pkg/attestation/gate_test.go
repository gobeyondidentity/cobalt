package attestation

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nmelo/secure-infra/pkg/store"
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
	s, cleanup := setupTestStore(t)
	defer cleanup()

	gate := NewGate(s)
	if gate.FreshnessWindow != time.Hour {
		t.Errorf("expected default FreshnessWindow=1h, got %v", gate.FreshnessWindow)
	}
}

// Tests for CanDistributeWithAutoRefresh

func TestGate_AutoRefresh_FreshAttestationNoRefresh(t *testing.T) {
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
