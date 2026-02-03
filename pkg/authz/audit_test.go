package authz

import (
	"context"
	"sync"
	"testing"
	"time"
)

// mockAuditStore implements AuditStore for testing.
type mockAuditStore struct {
	entries []*AuditEntry
	mu      sync.Mutex
}

func (m *mockAuditStore) InsertAuditEntry(entry *AuditEntry) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entry)
	return int64(len(m.entries)), nil
}

func TestStoreAuditLogger_LogDecision(t *testing.T) {
	t.Log("Testing StoreAuditLogger records authorization decisions")

	store := &mockAuditStore{}
	logger := NewStoreAuditLogger(store)

	entry := AuthzAuditEntry{
		Timestamp:     time.Now(),
		RequestID:     "req-123",
		Principal:     "km_abc123",
		PrincipalType: "Operator",
		Role:          "tenant:admin",
		Action:        "credential:push",
		Resource:      "dpu_xyz",
		ResourceType:  "DPU",
		TenantID:      "tenant_1",
		Decision:      "allow",
		Reason:        "access permitted",
		PolicyID:      "policy-1",
		DurationUS:    150,
	}

	t.Log("Calling LogDecision with valid entry")
	err := logger.LogDecision(context.Background(), entry)
	if err != nil {
		t.Fatalf("LogDecision failed: %v", err)
	}

	t.Log("Verifying entry was stored")
	if len(store.entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(store.entries))
	}

	stored := store.entries[0]
	if stored.Action != "authorization_decision" {
		t.Errorf("Expected action=authorization_decision, got %s", stored.Action)
	}
	if stored.Target != "dpu_xyz" {
		t.Errorf("Expected target=dpu_xyz, got %s", stored.Target)
	}
	if stored.Decision != "allow" {
		t.Errorf("Expected decision=allow, got %s", stored.Decision)
	}
	if stored.Details["principal"] != "km_abc123" {
		t.Errorf("Expected principal=km_abc123, got %s", stored.Details["principal"])
	}
	if stored.Details["request_id"] != "req-123" {
		t.Errorf("Expected request_id=req-123, got %s", stored.Details["request_id"])
	}
}

func TestStoreAuditLogger_ForceBypass(t *testing.T) {
	t.Log("Testing StoreAuditLogger records force bypass events")

	store := &mockAuditStore{}
	logger := NewStoreAuditLogger(store)

	entry := AuthzAuditEntry{
		Timestamp:         time.Now(),
		RequestID:         "req-456",
		Principal:         "adm_super",
		PrincipalType:     "Operator",
		Role:              "super:admin",
		Action:            "credential:push",
		Resource:          "dpu_stale",
		ResourceType:      "DPU",
		Decision:          "allow",
		Reason:            "force bypass: maintenance window",
		ForceBypass:       true,
		BypassReason:      "maintenance window",
		AttestationStatus: "stale",
	}

	t.Log("Calling LogDecision with force bypass entry")
	err := logger.LogDecision(context.Background(), entry)
	if err != nil {
		t.Fatalf("LogDecision failed: %v", err)
	}

	t.Log("Verifying force bypass fields were stored")
	stored := store.entries[0]
	if stored.Details["force_bypass"] != "true" {
		t.Errorf("Expected force_bypass=true, got %s", stored.Details["force_bypass"])
	}
	if stored.Details["bypass_reason"] != "maintenance window" {
		t.Errorf("Expected bypass_reason='maintenance window', got %s", stored.Details["bypass_reason"])
	}
	if stored.Details["attestation_status"] != "stale" {
		t.Errorf("Expected attestation_status=stale, got %s", stored.Details["attestation_status"])
	}
}

func TestSlogAuditLogger_LogDecision(t *testing.T) {
	t.Log("Testing SlogAuditLogger writes to structured log")

	logger := NewSlogAuditLogger(nil) // Uses default logger

	entry := AuthzAuditEntry{
		Timestamp:     time.Now(),
		RequestID:     "req-789",
		Principal:     "km_xyz",
		PrincipalType: "Operator",
		Role:          "operator",
		Action:        "dpu:read",
		Resource:      "dpu_test",
		ResourceType:  "DPU",
		Decision:      "deny",
		Reason:        "no matching permit policy",
		DurationUS:    50,
	}

	// This should not panic/error
	t.Log("Calling LogDecision - should not fail")
	err := logger.LogDecision(context.Background(), entry)
	if err != nil {
		t.Fatalf("LogDecision failed: %v", err)
	}
}

func TestMultiAuditLogger(t *testing.T) {
	t.Log("Testing MultiAuditLogger writes to multiple destinations")

	store1 := &mockAuditStore{}
	store2 := &mockAuditStore{}
	logger1 := NewStoreAuditLogger(store1)
	logger2 := NewStoreAuditLogger(store2)

	multi := NewMultiAuditLogger(logger1, logger2)

	entry := AuthzAuditEntry{
		Timestamp: time.Now(),
		Principal: "test",
		Action:    "test:action",
		Resource:  "test-resource",
		Decision:  "allow",
	}

	t.Log("Calling LogDecision on multi logger")
	err := multi.LogDecision(context.Background(), entry)
	if err != nil {
		t.Fatalf("LogDecision failed: %v", err)
	}

	t.Log("Verifying both stores received the entry")
	if len(store1.entries) != 1 {
		t.Errorf("Expected store1 to have 1 entry, got %d", len(store1.entries))
	}
	if len(store2.entries) != 1 {
		t.Errorf("Expected store2 to have 1 entry, got %d", len(store2.entries))
	}
}

func TestNopAuditLogger(t *testing.T) {
	t.Log("Testing NopAuditLogger discards entries without error")

	logger := NopAuditLogger{}

	entry := AuthzAuditEntry{
		Timestamp: time.Now(),
		Principal: "test",
		Action:    "test:action",
		Resource:  "test-resource",
		Decision:  "allow",
	}

	err := logger.LogDecision(context.Background(), entry)
	if err != nil {
		t.Fatalf("NopAuditLogger.LogDecision should not return error, got: %v", err)
	}
}
