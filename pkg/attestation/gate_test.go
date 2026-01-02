package attestation

import (
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
