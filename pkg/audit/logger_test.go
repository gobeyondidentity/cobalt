package audit

import (
	"os"
	"testing"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/store"
)

func setupTestStore(t *testing.T) (*store.Store, func()) {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "audit_test_*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpFile.Close()

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

func TestLogger_LogGateDecision(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	logger := NewLogger(s)

	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    "gate_decision",
		Target:    "dpu-1",
		Decision:  "allowed",
		Details: map[string]string{
			"reason": "valid attestation",
			"user":   "admin",
		},
	}

	err := logger.Log(entry)
	if err != nil {
		t.Fatalf("failed to log entry: %v", err)
	}

	// Verify the entry was stored
	entries, err := logger.Query(AuditFilter{Action: "gate_decision"})
	if err != nil {
		t.Fatalf("failed to query entries: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	result := entries[0]
	if result.Action != "gate_decision" {
		t.Errorf("expected action 'gate_decision', got '%s'", result.Action)
	}
	if result.Target != "dpu-1" {
		t.Errorf("expected target 'dpu-1', got '%s'", result.Target)
	}
	if result.Decision != "allowed" {
		t.Errorf("expected decision 'allowed', got '%s'", result.Decision)
	}
	if result.Details["reason"] != "valid attestation" {
		t.Errorf("expected details reason 'valid attestation', got '%s'", result.Details["reason"])
	}
}

func TestLogger_LogWithAttestationSnapshot(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	logger := NewLogger(s)

	now := time.Now()
	lastValidated := now.Add(-5 * time.Minute)

	entry := AuditEntry{
		Timestamp: now,
		Action:    "attestation_verified",
		Target:    "dpu-2",
		Decision:  "allowed",
		AttestationSnapshot: &AttestationSnapshot{
			DPUName:       "dpu-2",
			Status:        "valid",
			LastValidated: lastValidated,
			Age:           5 * time.Minute,
		},
	}

	err := logger.Log(entry)
	if err != nil {
		t.Fatalf("failed to log entry: %v", err)
	}

	entries, err := logger.Query(AuditFilter{Target: "dpu-2"})
	if err != nil {
		t.Fatalf("failed to query entries: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	result := entries[0]
	if result.AttestationSnapshot == nil {
		t.Fatal("expected attestation snapshot, got nil")
	}
	if result.AttestationSnapshot.DPUName != "dpu-2" {
		t.Errorf("expected DPU name 'dpu-2', got '%s'", result.AttestationSnapshot.DPUName)
	}
	if result.AttestationSnapshot.Status != "valid" {
		t.Errorf("expected status 'valid', got '%s'", result.AttestationSnapshot.Status)
	}
	if result.AttestationSnapshot.Age != 5*time.Minute {
		t.Errorf("expected age 5m, got %v", result.AttestationSnapshot.Age)
	}
}

func TestLogger_QueryByAction(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	logger := NewLogger(s)

	// Log multiple entries with different actions
	entries := []AuditEntry{
		{Timestamp: time.Now(), Action: "gate_decision", Target: "dpu-1", Decision: "allowed"},
		{Timestamp: time.Now(), Action: "credential_distributed", Target: "dpu-2", Decision: "allowed"},
		{Timestamp: time.Now(), Action: "gate_decision", Target: "dpu-3", Decision: "blocked"},
		{Timestamp: time.Now(), Action: "attestation_verified", Target: "dpu-1", Decision: "allowed"},
	}

	for _, e := range entries {
		if err := logger.Log(e); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}

	// Query by action
	result, err := logger.Query(AuditFilter{Action: "gate_decision"})
	if err != nil {
		t.Fatalf("failed to query entries: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 gate_decision entries, got %d", len(result))
	}

	for _, r := range result {
		if r.Action != "gate_decision" {
			t.Errorf("expected action 'gate_decision', got '%s'", r.Action)
		}
	}
}

func TestLogger_QueryByTarget(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	logger := NewLogger(s)

	entries := []AuditEntry{
		{Timestamp: time.Now(), Action: "gate_decision", Target: "dpu-1", Decision: "allowed"},
		{Timestamp: time.Now(), Action: "credential_distributed", Target: "dpu-2", Decision: "allowed"},
		{Timestamp: time.Now(), Action: "gate_decision", Target: "dpu-1", Decision: "blocked"},
		{Timestamp: time.Now(), Action: "attestation_verified", Target: "dpu-3", Decision: "allowed"},
	}

	for _, e := range entries {
		if err := logger.Log(e); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}

	// Query by target
	result, err := logger.Query(AuditFilter{Target: "dpu-1"})
	if err != nil {
		t.Fatalf("failed to query entries: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 entries for dpu-1, got %d", len(result))
	}

	for _, r := range result {
		if r.Target != "dpu-1" {
			t.Errorf("expected target 'dpu-1', got '%s'", r.Target)
		}
	}
}

func TestLogger_QueryWithLimit(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	logger := NewLogger(s)

	// Log 10 entries
	for i := 0; i < 10; i++ {
		entry := AuditEntry{
			Timestamp: time.Now(),
			Action:    "gate_decision",
			Target:    "dpu-1",
			Decision:  "allowed",
		}
		if err := logger.Log(entry); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}

	// Query with limit
	result, err := logger.Query(AuditFilter{Limit: 5})
	if err != nil {
		t.Fatalf("failed to query entries: %v", err)
	}

	if len(result) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(result))
	}
}

func TestLogger_QueryWithCombinedFilters(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	logger := NewLogger(s)

	entries := []AuditEntry{
		{Timestamp: time.Now(), Action: "gate_decision", Target: "dpu-1", Decision: "allowed"},
		{Timestamp: time.Now(), Action: "gate_decision", Target: "dpu-2", Decision: "blocked"},
		{Timestamp: time.Now(), Action: "credential_distributed", Target: "dpu-1", Decision: "allowed"},
		{Timestamp: time.Now(), Action: "gate_decision", Target: "dpu-1", Decision: "forced"},
	}

	for _, e := range entries {
		if err := logger.Log(e); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}

	// Query with combined action and target filter
	result, err := logger.Query(AuditFilter{
		Action: "gate_decision",
		Target: "dpu-1",
	})
	if err != nil {
		t.Fatalf("failed to query entries: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}

	for _, r := range result {
		if r.Action != "gate_decision" {
			t.Errorf("expected action 'gate_decision', got '%s'", r.Action)
		}
		if r.Target != "dpu-1" {
			t.Errorf("expected target 'dpu-1', got '%s'", r.Target)
		}
	}
}
