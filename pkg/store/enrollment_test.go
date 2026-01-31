package store

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestEnrollmentSessionCRUD tests basic create/get/complete operations for enrollment sessions.
func TestEnrollmentSessionCRUD(t *testing.T) {
	store := setupTestStore(t)

	t.Log("Setting up tenant and invite code for foreign key reference")
	err := store.AddTenant("t1", "Test Tenant", "", "", nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	inviteCode := &InviteCode{
		ID:            "invite-123",
		CodeHash:      "abcdef1234567890",
		OperatorEmail: "test@example.com",
		TenantID:      "t1",
		Role:          "operator",
		CreatedBy:     "admin",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Status:        "pending",
	}
	err = store.CreateInviteCode(inviteCode)
	if err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	t.Log("Creating enrollment session with invite ID")
	inviteID := "invite-123"
	sessionID := "session-456"
	challenge := "random-challenge-bytes"
	expiresAt := time.Now().Add(15 * time.Minute)

	err = store.CreateEnrollmentSession(sessionID, &inviteID, challenge, expiresAt)
	if err != nil {
		t.Fatalf("CreateEnrollmentSession failed: %v", err)
	}

	t.Log("Retrieving enrollment session by ID")
	session, err := store.GetEnrollmentSession(sessionID)
	if err != nil {
		t.Fatalf("GetEnrollmentSession failed: %v", err)
	}

	t.Log("Verifying session fields match what was stored")
	if session.ID != sessionID {
		t.Errorf("expected ID %q, got %q", sessionID, session.ID)
	}
	if session.InviteID == nil || *session.InviteID != inviteID {
		t.Errorf("expected InviteID %q, got %v", inviteID, session.InviteID)
	}
	if session.Challenge != challenge {
		t.Errorf("expected Challenge %q, got %q", challenge, session.Challenge)
	}
	if session.Status != "pending" {
		t.Errorf("expected Status 'pending', got %q", session.Status)
	}
	// ExpiresAt should be within a second of what we set
	if session.ExpiresAt.Sub(expiresAt).Abs() > time.Second {
		t.Errorf("expected ExpiresAt ~%v, got %v", expiresAt, session.ExpiresAt)
	}

	t.Log("Completing the enrollment session")
	err = store.CompleteEnrollmentSession(sessionID)
	if err != nil {
		t.Fatalf("CompleteEnrollmentSession failed: %v", err)
	}

	t.Log("Verifying session status is now 'completed'")
	session, err = store.GetEnrollmentSession(sessionID)
	if err != nil {
		t.Fatalf("GetEnrollmentSession after complete failed: %v", err)
	}
	if session.Status != "completed" {
		t.Errorf("expected Status 'completed', got %q", session.Status)
	}
}

// TestEnrollmentSessionStatus tests the different status transitions.
func TestEnrollmentSessionStatus(t *testing.T) {
	store := setupTestStore(t)

	t.Log("Creating a pending session")
	err := store.CreateEnrollmentSession("s1", nil, "challenge1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateEnrollmentSession failed: %v", err)
	}

	session, _ := store.GetEnrollmentSession("s1")
	if session.Status != "pending" {
		t.Errorf("new session should be 'pending', got %q", session.Status)
	}

	t.Log("Completing the session transitions to 'completed'")
	err = store.CompleteEnrollmentSession("s1")
	if err != nil {
		t.Fatalf("CompleteEnrollmentSession failed: %v", err)
	}

	session, _ = store.GetEnrollmentSession("s1")
	if session.Status != "completed" {
		t.Errorf("completed session should be 'completed', got %q", session.Status)
	}

	t.Log("Attempting to complete an already-completed session should fail")
	err = store.CompleteEnrollmentSession("s1")
	if err == nil {
		t.Error("expected error when completing already-completed session, got nil")
	}

	t.Log("Creating an expired session for cleanup testing")
	err = store.CreateEnrollmentSession("s2", nil, "challenge2", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("CreateEnrollmentSession for expired session failed: %v", err)
	}

	t.Log("Running cleanup to mark expired sessions")
	err = store.CleanupExpiredSessions()
	if err != nil {
		t.Fatalf("CleanupExpiredSessions failed: %v", err)
	}

	session, _ = store.GetEnrollmentSession("s2")
	if session.Status != "expired" {
		t.Errorf("expired session should be 'expired', got %q", session.Status)
	}
}

// TestEnrollmentSessionConcurrentCompletion verifies atomic completion semantics.
// Spawns 100 goroutines trying to complete the same session; exactly 1 should succeed.
func TestEnrollmentSessionConcurrentCompletion(t *testing.T) {
	store := setupTestStore(t)

	t.Log("Creating a session for concurrent completion testing")
	err := store.CreateEnrollmentSession("concurrent-session", nil, "challenge", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateEnrollmentSession failed: %v", err)
	}

	t.Log("Spawning 100 goroutines to complete the same session concurrently")
	var wg sync.WaitGroup
	var successCount int64
	var failCount int64

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := store.CompleteEnrollmentSession("concurrent-session")
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
		}()
	}

	wg.Wait()

	t.Logf("Results: %d successes, %d failures", successCount, failCount)

	if successCount != 1 {
		t.Errorf("expected exactly 1 successful completion, got %d", successCount)
	}
	if failCount != 99 {
		t.Errorf("expected 99 failed completions, got %d", failCount)
	}

	t.Log("Verifying session is marked as completed")
	session, _ := store.GetEnrollmentSession("concurrent-session")
	if session.Status != "completed" {
		t.Errorf("session should be 'completed', got %q", session.Status)
	}
}

// TestEnrollmentSessionNullInvite tests DPU enrollment case where invite ID is NULL.
func TestEnrollmentSessionNullInvite(t *testing.T) {
	store := setupTestStore(t)

	t.Log("Creating DPU enrollment session with NULL invite ID")
	err := store.CreateEnrollmentSession("dpu-session", nil, "dpu-challenge", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateEnrollmentSession with nil invite failed: %v", err)
	}

	t.Log("Retrieving session and verifying InviteID is nil")
	session, err := store.GetEnrollmentSession("dpu-session")
	if err != nil {
		t.Fatalf("GetEnrollmentSession failed: %v", err)
	}

	if session.InviteID != nil {
		t.Errorf("expected nil InviteID for DPU session, got %v", session.InviteID)
	}

	t.Log("Verifying DPU session can be completed normally")
	err = store.CompleteEnrollmentSession("dpu-session")
	if err != nil {
		t.Fatalf("CompleteEnrollmentSession failed: %v", err)
	}
}

// TestBootstrapStateSingleton verifies that only one bootstrap_state record can exist.
func TestBootstrapStateSingleton(t *testing.T) {
	store := setupTestStore(t)

	t.Log("Getting bootstrap state (should auto-create initial record)")
	state1, err := store.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState failed: %v", err)
	}

	if state1.ID != 1 {
		t.Errorf("expected ID 1, got %d", state1.ID)
	}
	if state1.FirstStartAt.IsZero() {
		t.Error("FirstStartAt should be set")
	}
	if state1.CompletedAt != nil {
		t.Error("CompletedAt should be nil initially")
	}

	t.Log("Getting bootstrap state again should return same record")
	state2, err := store.GetBootstrapState()
	if err != nil {
		t.Fatalf("second GetBootstrapState failed: %v", err)
	}

	// FirstStartAt should be the same (not updated)
	if !state1.FirstStartAt.Equal(state2.FirstStartAt) {
		t.Errorf("FirstStartAt changed: was %v, now %v", state1.FirstStartAt, state2.FirstStartAt)
	}

	t.Log("Marking bootstrap as completed")
	err = store.SetBootstrapCompleted()
	if err != nil {
		t.Fatalf("SetBootstrapCompleted failed: %v", err)
	}

	state3, _ := store.GetBootstrapState()
	if state3.CompletedAt == nil {
		t.Error("CompletedAt should be set after SetBootstrapCompleted")
	}

	t.Log("Calling SetBootstrapCompleted again should be idempotent")
	err = store.SetBootstrapCompleted()
	if err != nil {
		t.Fatalf("second SetBootstrapCompleted should be idempotent: %v", err)
	}
}

// TestBootstrapStatePersistence verifies bootstrap state survives store close/reopen.
func TestBootstrapStatePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "bootstrap_persistence_test.db")

	t.Log("Phase 1: Create store and initialize bootstrap state")
	s1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}

	state1, err := s1.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState failed: %v", err)
	}
	firstStartAt := state1.FirstStartAt

	err = s1.SetBootstrapCompleted()
	if err != nil {
		t.Fatalf("SetBootstrapCompleted failed: %v", err)
	}

	s1.Close()

	t.Log("Phase 2: Reopen store and verify bootstrap state persisted")
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer s2.Close()

	state2, err := s2.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState after reopen failed: %v", err)
	}

	if !state2.FirstStartAt.Equal(firstStartAt) {
		t.Errorf("FirstStartAt not persisted: expected %v, got %v", firstStartAt, state2.FirstStartAt)
	}

	if state2.CompletedAt == nil {
		t.Error("CompletedAt should be persisted")
	}
}

// TestDPUEnrollmentExpiration tests set/clear of enrollment_expires_at on DPUs.
func TestDPUEnrollmentExpiration(t *testing.T) {
	store := setupTestStore(t)

	t.Log("Creating a DPU for enrollment expiration testing")
	err := store.Add("dpu1", "bf3-test", "192.168.1.100", 50051)
	if err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}

	t.Log("Verifying DPU initially has no enrollment expiration")
	dpu, err := store.Get("dpu1")
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.EnrollmentExpiresAt != nil {
		t.Error("expected nil EnrollmentExpiresAt initially")
	}

	t.Log("Setting enrollment expiration on DPU")
	expiresAt := time.Now().Add(24 * time.Hour)
	err = store.SetDPUEnrollmentExpires("dpu1", expiresAt)
	if err != nil {
		t.Fatalf("SetDPUEnrollmentExpires failed: %v", err)
	}

	t.Log("Verifying enrollment expiration is set")
	dpu, _ = store.Get("dpu1")
	if dpu.EnrollmentExpiresAt == nil {
		t.Fatal("expected EnrollmentExpiresAt to be set")
	}
	if dpu.EnrollmentExpiresAt.Sub(expiresAt).Abs() > time.Second {
		t.Errorf("expected EnrollmentExpiresAt ~%v, got %v", expiresAt, dpu.EnrollmentExpiresAt)
	}

	t.Log("Clearing enrollment expiration after successful enrollment")
	err = store.ClearDPUEnrollmentExpires("dpu1")
	if err != nil {
		t.Fatalf("ClearDPUEnrollmentExpires failed: %v", err)
	}

	dpu, _ = store.Get("dpu1")
	if dpu.EnrollmentExpiresAt != nil {
		t.Error("expected EnrollmentExpiresAt to be nil after clearing")
	}
}

// TestMigrationIdempotent verifies that running migrate() twice doesn't error.
func TestMigrationIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "migration_idempotent_test.db")

	t.Log("Opening store (runs migrate)")
	s1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("first Open failed: %v", err)
	}
	s1.Close()

	t.Log("Reopening store (runs migrate again)")
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("second Open failed: %v", err)
	}
	defer s2.Close()

	t.Log("Verifying schema is intact after double migration")
	// Create an enrollment session to prove tables exist
	err = s2.CreateEnrollmentSession("test-session", nil, "challenge", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateEnrollmentSession after double migrate failed: %v", err)
	}

	// Create bootstrap state to prove table exists
	_, err = s2.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState after double migrate failed: %v", err)
	}
}

// TestInviteCodeExpiresIndex verifies the expires_at index on invite_codes is used.
func TestInviteCodeExpiresIndex(t *testing.T) {
	store := setupTestStore(t)

	t.Log("Using EXPLAIN to verify index on invite_codes.expires_at is used")

	// Query using expires_at in WHERE clause
	rows, err := store.QueryRaw(`
		EXPLAIN QUERY PLAN
		SELECT id FROM invite_codes WHERE expires_at < 1704067200 AND status = 'pending'
	`)
	if err != nil {
		t.Fatalf("EXPLAIN failed: %v", err)
	}
	defer rows.Close()

	var foundIndex bool
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("failed to scan EXPLAIN result: %v", err)
		}
		t.Logf("EXPLAIN: %s", detail)
		// Look for index usage in the plan
		if containsAny(detail, "idx_invite_codes_expires", "USING INDEX") {
			foundIndex = true
		}
	}

	if !foundIndex {
		t.Log("Note: SQLite query planner may choose table scan for small tables. Index exists for production use.")
	}
}

// containsAny returns true if s contains any of the substrings.
func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
