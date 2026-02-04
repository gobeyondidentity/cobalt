package attestation

import (
	"strings"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/audit"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// TestAttestationGating_FreshAttestationAllows verifies that a fresh verified
// attestation allows credential distribution.
func TestAttestationGating_FreshAttestationAllows(t *testing.T) {
	t.Log("Testing fresh attestation allows distribution")

	s, cleanup := setupTestStore(t)
	defer cleanup()

	t.Log("Saving fresh verified attestation")
	att := &store.Attestation{
		DPUName:       "bf3-e2e-fresh-01",
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now(),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	gate := NewGate(s)

	t.Log("Verifying gate allows distribution")
	decision, err := gate.CanDistribute("bf3-e2e-fresh-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}

	if !decision.Allowed {
		t.Errorf("expected Allowed=true for fresh verified attestation, got Allowed=false, Reason=%q", decision.Reason)
	}
}

// TestAttestationGating_StaleAttestationBlocks verifies that a stale attestation
// (older than DefaultFreshnessWindow) blocks credential distribution.
func TestAttestationGating_StaleAttestationBlocks(t *testing.T) {
	t.Log("Testing stale attestation blocks distribution")

	s, cleanup := setupTestStore(t)
	defer cleanup()

	t.Log("Saving stale attestation (2 hours old)")
	att := &store.Attestation{
		DPUName:       "bf3-e2e-stale-01",
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now().Add(-2 * time.Hour),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	gate := NewGate(s)

	t.Log("Verifying gate blocks with stale reason")
	decision, err := gate.CanDistribute("bf3-e2e-stale-01")
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

// TestAttestationGating_ForceBypassWithAudit verifies that when an operator forces
// a bypass of a stale attestation, an audit entry is logged with operator identity.
func TestAttestationGating_ForceBypassWithAudit(t *testing.T) {
	t.Log("Testing force bypass logs audit entry")

	s, cleanup := setupTestStore(t)
	defer cleanup()

	// Save stale attestation (2 hours old)
	att := &store.Attestation{
		DPUName:       "bf3-e2e-bypass-01",
		Status:        store.AttestationStatusVerified,
		LastValidated: time.Now().Add(-2 * time.Hour),
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	gate := NewGate(s)
	auditLogger := audit.NewLogger(s)

	t.Log("Gate blocks stale attestation")
	decision, err := gate.CanDistribute("bf3-e2e-bypass-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}

	if decision.Allowed {
		t.Fatal("expected gate to block stale attestation before force bypass")
	}

	t.Log("Simulating force bypass - logging audit entry")
	// When an operator uses --force, the CLI logs an audit entry with decision="forced"
	auditEntry := audit.AuditEntry{
		Timestamp: time.Now(),
		Action:    "gate_decision",
		Target:    "bf3-e2e-bypass-01",
		Decision:  "forced",
		AttestationSnapshot: &audit.AttestationSnapshot{
			DPUName:       decision.Attestation.DPUName,
			Status:        string(decision.Attestation.Status),
			LastValidated: decision.Attestation.LastValidated,
			Age:           decision.Attestation.Age(),
		},
		Details: map[string]string{
			"operator_email": "admin@example.com",
			"reason":         "emergency maintenance window",
		},
	}
	if err := auditLogger.Log(auditEntry); err != nil {
		t.Fatalf("failed to log audit entry: %v", err)
	}

	t.Log("Querying audit log for forced entry")
	entries, err := auditLogger.Query(audit.AuditFilter{
		Action: "gate_decision",
		Target: "bf3-e2e-bypass-01",
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("failed to query audit entries: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry, got none")
	}

	t.Log("Verifying audit entry contains operator identity")
	found := false
	for _, entry := range entries {
		if entry.Decision == "forced" {
			found = true
			if entry.Details["operator_email"] != "admin@example.com" {
				t.Errorf("expected operator_email=admin@example.com, got %q", entry.Details["operator_email"])
			}
			if entry.Target != "bf3-e2e-bypass-01" {
				t.Errorf("expected target=bf3-e2e-bypass-01, got %q", entry.Target)
			}
			if entry.AttestationSnapshot == nil {
				t.Error("expected attestation snapshot in audit entry")
			} else if entry.AttestationSnapshot.Status != "verified" {
				t.Errorf("expected snapshot status=verified, got %q", entry.AttestationSnapshot.Status)
			}
			break
		}
	}
	if !found {
		t.Error("did not find forced decision in audit log")
	}
}

// TestAttestationGating_FailedAttestationBlocksEvenForce verifies that a failed
// attestation (device failed integrity verification) blocks distribution and
// cannot be bypassed with --force.
func TestAttestationGating_FailedAttestationBlocksEvenForce(t *testing.T) {
	t.Log("Testing failed attestation blocks even with force")

	s, cleanup := setupTestStore(t)
	defer cleanup()

	t.Log("Saving failed attestation (device failed integrity)")
	att := &store.Attestation{
		DPUName:       "bf3-e2e-failed-01",
		Status:        store.AttestationStatusFailed,
		LastValidated: time.Now(), // Fresh timestamp but failed status
	}
	if err := s.SaveAttestation(att); err != nil {
		t.Fatalf("SaveAttestation failed: %v", err)
	}

	gate := NewGate(s)

	t.Log("Verifying gate blocks distribution")
	decision, err := gate.CanDistribute("bf3-e2e-failed-01")
	if err != nil {
		t.Fatalf("CanDistribute failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected Allowed=false for failed attestation")
	}

	t.Log("Verifying IsAttestationFailed=true (force not allowed)")
	if !decision.IsAttestationFailed() {
		t.Error("expected IsAttestationFailed()=true for failed attestation, indicating --force should NOT be allowed")
	}

	// Verify the reason indicates failed status
	if !strings.Contains(decision.Reason, "failed") {
		t.Errorf("expected Reason to contain 'failed', got %q", decision.Reason)
	}
}
