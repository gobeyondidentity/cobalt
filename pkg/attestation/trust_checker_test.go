package attestation

import (
	"os"
	"testing"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/store"
)

// setupTrustCheckerTest creates a test store and returns it along with test data helpers.
func setupTrustCheckerTest(t *testing.T) (*store.Store, func()) {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "trust_checker_test_*.db")
	if err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("failed to open store: %v", err)
	}

	// Create test tenant
	if err := s.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		s.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("failed to create tenant: %v", err)
	}

	cleanup := func() {
		s.Close()
		os.Remove(tmpFile.Name())
	}
	return s, cleanup
}

// createTestTrustRelationship is a helper to create trust relationships for testing.
func createTestTrustRelationship(t *testing.T, s *store.Store, id, sourceDPUName, targetDPUName string) {
	t.Helper()
	tr := &store.TrustRelationship{
		ID:            id,
		SourceHost:    sourceDPUName + "-host.example.com",
		TargetHost:    targetDPUName + "-host.example.com",
		SourceDPUID:   sourceDPUName + "-id",
		SourceDPUName: sourceDPUName,
		TargetDPUID:   targetDPUName + "-id",
		TargetDPUName: targetDPUName,
		TenantID:      "tenant1",
		TrustType:     store.TrustTypeSSHHost,
	}
	if err := s.CreateTrustRelationship(tr); err != nil {
		t.Fatalf("failed to create trust relationship: %v", err)
	}
}

// createVerifiedAttestation saves a fresh verified attestation for a DPU.
func createVerifiedAttestation(t *testing.T, s *store.Store, dpuName string) {
	t.Helper()
	att := &store.Attestation{
		DPUName:       dpuName,
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("failed to save attestation: %v", err)
	}
}

// createStaleAttestation saves a stale verified attestation for a DPU.
func createStaleAttestation(t *testing.T, s *store.Store, dpuName string, age time.Duration) {
	t.Helper()
	att := &store.Attestation{
		DPUName:       dpuName,
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now().Add(-age),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("failed to save attestation: %v", err)
	}
}

// createFailedAttestation saves a failed attestation for a DPU.
func createFailedAttestation(t *testing.T, s *store.Store, dpuName string) {
	t.Helper()
	att := &store.Attestation{
		DPUName:       dpuName,
		Status:        store.AttestationStatusFailed,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("failed to save attestation: %v", err)
	}
}

func TestTrustChecker_SuspendsOnFailedAttestation(t *testing.T) {
	s, cleanup := setupTrustCheckerTest(t)
	defer cleanup()

	// Create trust relationships involving bf3-01
	createTestTrustRelationship(t, s, "tr_test1", "bf3-01", "bf3-02")
	createTestTrustRelationship(t, s, "tr_test2", "bf3-03", "bf3-01") // bf3-01 as target

	// Create a failed attestation for bf3-01
	createFailedAttestation(t, s, "bf3-01")

	// Create TrustChecker and check
	checker := NewTrustChecker(s)
	result, err := checker.CheckAndUpdateTrust("bf3-01")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}

	// Verify result indicates suspensions
	if result.Suspended != 2 {
		t.Errorf("expected 2 suspended relationships, got %d", result.Suspended)
	}
	if result.Reactivated != 0 {
		t.Errorf("expected 0 reactivated relationships, got %d", result.Reactivated)
	}

	// Verify both trust relationships are now suspended
	tr1, _ := s.GetTrustRelationship("tr_test1")
	if tr1.Status != store.TrustStatusSuspended {
		t.Errorf("expected tr_test1 status 'suspended', got '%s'", tr1.Status)
	}
	if tr1.SuspendReason == nil || *tr1.SuspendReason == "" {
		t.Error("expected tr_test1 to have a suspend reason")
	}

	tr2, _ := s.GetTrustRelationship("tr_test2")
	if tr2.Status != store.TrustStatusSuspended {
		t.Errorf("expected tr_test2 status 'suspended', got '%s'", tr2.Status)
	}
}

func TestTrustChecker_SuspendsOnStaleAttestation(t *testing.T) {
	s, cleanup := setupTrustCheckerTest(t)
	defer cleanup()

	// Create trust relationship
	createTestTrustRelationship(t, s, "tr_stale1", "bf3-stale", "bf3-other")

	// Create a stale attestation (older than 1 hour)
	createStaleAttestation(t, s, "bf3-stale", 2*time.Hour)

	// Create TrustChecker and check
	checker := NewTrustChecker(s)
	result, err := checker.CheckAndUpdateTrust("bf3-stale")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}

	// Verify suspension occurred
	if result.Suspended != 1 {
		t.Errorf("expected 1 suspended relationship, got %d", result.Suspended)
	}

	tr, _ := s.GetTrustRelationship("tr_stale1")
	if tr.Status != store.TrustStatusSuspended {
		t.Errorf("expected status 'suspended', got '%s'", tr.Status)
	}
	if tr.SuspendReason == nil {
		t.Error("expected non-nil suspend reason for stale attestation")
	}
}

func TestTrustChecker_ReactivatesOnValidAttestation(t *testing.T) {
	s, cleanup := setupTrustCheckerTest(t)
	defer cleanup()

	// Create trust relationships that are already suspended
	createTestTrustRelationship(t, s, "tr_react1", "bf3-react", "bf3-other1")
	createTestTrustRelationship(t, s, "tr_react2", "bf3-other2", "bf3-react")

	// Suspend them manually
	reason := "bf3-react attestation failed"
	s.UpdateTrustStatus("tr_react1", store.TrustStatusSuspended, &reason)
	s.UpdateTrustStatus("tr_react2", store.TrustStatusSuspended, &reason)

	// Create a fresh verified attestation
	createVerifiedAttestation(t, s, "bf3-react")

	// Create TrustChecker and check
	checker := NewTrustChecker(s)
	result, err := checker.CheckAndUpdateTrust("bf3-react")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}

	// Verify reactivation occurred
	if result.Reactivated != 2 {
		t.Errorf("expected 2 reactivated relationships, got %d", result.Reactivated)
	}
	if result.Suspended != 0 {
		t.Errorf("expected 0 suspended relationships, got %d", result.Suspended)
	}

	// Verify both trust relationships are now active
	tr1, _ := s.GetTrustRelationship("tr_react1")
	if tr1.Status != store.TrustStatusActive {
		t.Errorf("expected tr_react1 status 'active', got '%s'", tr1.Status)
	}
	if tr1.SuspendReason != nil {
		t.Errorf("expected nil suspend reason after reactivation, got '%s'", *tr1.SuspendReason)
	}

	tr2, _ := s.GetTrustRelationship("tr_react2")
	if tr2.Status != store.TrustStatusActive {
		t.Errorf("expected tr_react2 status 'active', got '%s'", tr2.Status)
	}
}

func TestTrustChecker_OnlyAffectsRelatedDPU(t *testing.T) {
	s, cleanup := setupTrustCheckerTest(t)
	defer cleanup()

	// Create trust relationships:
	// - One involving the target DPU (bf3-target)
	// - One NOT involving the target DPU
	createTestTrustRelationship(t, s, "tr_target", "bf3-target", "bf3-other")
	createTestTrustRelationship(t, s, "tr_unrelated", "bf3-a", "bf3-b")

	// Create failed attestation for bf3-target
	createFailedAttestation(t, s, "bf3-target")

	// Create TrustChecker and check
	checker := NewTrustChecker(s)
	result, err := checker.CheckAndUpdateTrust("bf3-target")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}

	// Only the related relationship should be suspended
	if result.Suspended != 1 {
		t.Errorf("expected 1 suspended relationship, got %d", result.Suspended)
	}

	// Verify the target relationship is suspended
	trTarget, _ := s.GetTrustRelationship("tr_target")
	if trTarget.Status != store.TrustStatusSuspended {
		t.Errorf("expected tr_target status 'suspended', got '%s'", trTarget.Status)
	}

	// Verify the unrelated relationship is still active
	trUnrelated, _ := s.GetTrustRelationship("tr_unrelated")
	if trUnrelated.Status != store.TrustStatusActive {
		t.Errorf("expected tr_unrelated status 'active', got '%s'", trUnrelated.Status)
	}
}

func TestTrustChecker_NoChangeForAlreadySuspended(t *testing.T) {
	s, cleanup := setupTrustCheckerTest(t)
	defer cleanup()

	// Create trust relationship and suspend it
	createTestTrustRelationship(t, s, "tr_presuspend", "bf3-pre", "bf3-other")
	reason := "already suspended"
	s.UpdateTrustStatus("tr_presuspend", store.TrustStatusSuspended, &reason)

	// Create failed attestation
	createFailedAttestation(t, s, "bf3-pre")

	// Create TrustChecker and check
	checker := NewTrustChecker(s)
	result, err := checker.CheckAndUpdateTrust("bf3-pre")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}

	// No new suspensions should occur (already suspended)
	if result.Suspended != 0 {
		t.Errorf("expected 0 suspended (already was), got %d", result.Suspended)
	}
}

func TestTrustChecker_NoChangeForAlreadyActive(t *testing.T) {
	s, cleanup := setupTrustCheckerTest(t)
	defer cleanup()

	// Create trust relationship (defaults to active)
	createTestTrustRelationship(t, s, "tr_active", "bf3-active", "bf3-other")

	// Create fresh verified attestation
	createVerifiedAttestation(t, s, "bf3-active")

	// Create TrustChecker and check
	checker := NewTrustChecker(s)
	result, err := checker.CheckAndUpdateTrust("bf3-active")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}

	// No reactivations should occur (already active)
	if result.Reactivated != 0 {
		t.Errorf("expected 0 reactivated (already was), got %d", result.Reactivated)
	}
}

func TestTrustChecker_UnknownAttestationSuspends(t *testing.T) {
	s, cleanup := setupTrustCheckerTest(t)
	defer cleanup()

	// Create trust relationship but NO attestation for the DPU
	createTestTrustRelationship(t, s, "tr_unknown", "bf3-unknown", "bf3-other")

	// Create TrustChecker and check
	checker := NewTrustChecker(s)
	result, err := checker.CheckAndUpdateTrust("bf3-unknown")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}

	// Should suspend due to unknown attestation
	if result.Suspended != 1 {
		t.Errorf("expected 1 suspended relationship, got %d", result.Suspended)
	}

	tr, _ := s.GetTrustRelationship("tr_unknown")
	if tr.Status != store.TrustStatusSuspended {
		t.Errorf("expected status 'suspended', got '%s'", tr.Status)
	}
}

func TestTrustChecker_CustomFreshnessWindow(t *testing.T) {
	s, cleanup := setupTrustCheckerTest(t)
	defer cleanup()

	// Create trust relationship
	createTestTrustRelationship(t, s, "tr_custom", "bf3-custom", "bf3-other")

	// Create attestation 30 minutes old
	createStaleAttestation(t, s, "bf3-custom", 30*time.Minute)

	// Default freshness window (1h) should consider this valid
	checker := NewTrustChecker(s)
	result, err := checker.CheckAndUpdateTrust("bf3-custom")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}
	if result.Suspended != 0 {
		t.Errorf("expected 0 suspended with default 1h window, got %d", result.Suspended)
	}

	// Now use a tighter window (15 minutes)
	checker.FreshnessWindow = 15 * time.Minute
	result, err = checker.CheckAndUpdateTrust("bf3-custom")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}
	if result.Suspended != 1 {
		t.Errorf("expected 1 suspended with 15m window, got %d", result.Suspended)
	}
}

func TestTrustChecker_NoRelationshipsForDPU(t *testing.T) {
	s, cleanup := setupTrustCheckerTest(t)
	defer cleanup()

	// Create attestation but no trust relationships
	createVerifiedAttestation(t, s, "bf3-lonely")

	// Create TrustChecker and check
	checker := NewTrustChecker(s)
	result, err := checker.CheckAndUpdateTrust("bf3-lonely")
	if err != nil {
		t.Fatalf("CheckAndUpdateTrust failed: %v", err)
	}

	// Should report 0 changes
	if result.Suspended != 0 || result.Reactivated != 0 {
		t.Errorf("expected 0 changes for DPU with no relationships, got suspended=%d reactivated=%d",
			result.Suspended, result.Reactivated)
	}
}
