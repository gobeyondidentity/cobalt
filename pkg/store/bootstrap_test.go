package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============== Bootstrap State Tests ==============

// TestGetBootstrapState_Empty tests that GetBootstrapState returns nil when no row exists.
func TestGetBootstrapState_Empty(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Getting bootstrap state from empty database")
	state, err := store.GetBootstrapState()

	t.Log("Verifying nil state is returned with no error")
	assert.NoError(t, err, "should not error when no row exists")
	assert.Nil(t, state, "should return nil when no bootstrap state exists")
}

// TestInitBootstrapWindow_Success tests successful bootstrap window initialization.
func TestInitBootstrapWindow_Success(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Initializing bootstrap window")
	// SQLite stores timestamps in seconds, so truncate to second precision for comparison
	before := time.Now().Truncate(time.Second)
	err := store.InitBootstrapWindow()
	after := time.Now().Add(time.Second).Truncate(time.Second) // Add 1s to account for timing

	t.Log("Verifying bootstrap window was created")
	require.NoError(t, err, "InitBootstrapWindow should succeed")

	t.Log("Retrieving bootstrap state to verify")
	state, err := store.GetBootstrapState()
	require.NoError(t, err, "GetBootstrapState should succeed")
	require.NotNil(t, state, "state should exist after init")

	t.Log("Verifying window_opened_at timestamp is set correctly")
	assert.True(t, !state.WindowOpenedAt.Before(before),
		"WindowOpenedAt should be at or after test start")
	assert.True(t, !state.WindowOpenedAt.After(after),
		"WindowOpenedAt should be at or before test end")

	t.Log("Verifying completed_at and first_admin_id are nil")
	assert.Nil(t, state.CompletedAt, "CompletedAt should be nil for fresh window")
	assert.Nil(t, state.FirstAdminID, "FirstAdminID should be nil for fresh window")
}

// TestInitBootstrapWindow_AlreadyExists tests that initializing twice fails.
func TestInitBootstrapWindow_AlreadyExists(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Initializing bootstrap window first time")
	err := store.InitBootstrapWindow()
	require.NoError(t, err, "first init should succeed")

	t.Log("Attempting second initialization (should fail)")
	err = store.InitBootstrapWindow()

	t.Log("Verifying error is returned")
	assert.Error(t, err, "second init should fail due to singleton constraint")
	assert.Contains(t, err.Error(), "already", "error should indicate bootstrap already exists")
}

// TestCompleteBootstrap_Success tests successful bootstrap completion.
func TestCompleteBootstrap_Success(t *testing.T) {
	t.Log("Setting up test store and initializing bootstrap window")
	store := setupTestStore(t)
	err := store.InitBootstrapWindow()
	require.NoError(t, err)

	t.Log("Completing bootstrap with first admin ID")
	// SQLite stores timestamps in seconds, so truncate to second precision for comparison
	before := time.Now().Truncate(time.Second)
	err = store.CompleteBootstrap("adm_first-admin-123")
	after := time.Now().Add(time.Second).Truncate(time.Second) // Add 1s to account for timing

	t.Log("Verifying completion succeeded")
	require.NoError(t, err, "CompleteBootstrap should succeed")

	t.Log("Retrieving state to verify completion")
	state, err := store.GetBootstrapState()
	require.NoError(t, err)
	require.NotNil(t, state)

	t.Log("Verifying completed_at is set correctly")
	require.NotNil(t, state.CompletedAt, "CompletedAt should be set")
	assert.True(t, !state.CompletedAt.Before(before),
		"CompletedAt should be at or after completion call")
	assert.True(t, !state.CompletedAt.After(after),
		"CompletedAt should be at or before completion call end")

	t.Log("Verifying first_admin_id is set")
	require.NotNil(t, state.FirstAdminID, "FirstAdminID should be set")
	assert.Equal(t, "adm_first-admin-123", *state.FirstAdminID)
}

// TestCompleteBootstrap_NoWindow tests completing without an initialized window.
func TestCompleteBootstrap_NoWindow(t *testing.T) {
	t.Log("Setting up test store (no bootstrap window)")
	store := setupTestStore(t)

	t.Log("Attempting to complete bootstrap without init (should fail)")
	err := store.CompleteBootstrap("adm_test")

	t.Log("Verifying error is returned")
	assert.Error(t, err, "should fail when no bootstrap window exists")
	assert.Contains(t, err.Error(), "not found", "error should indicate bootstrap state not found")
}

// TestCompleteBootstrap_AlreadyCompleted tests that completing twice fails.
func TestCompleteBootstrap_AlreadyCompleted(t *testing.T) {
	t.Log("Setting up test store and completing bootstrap")
	store := setupTestStore(t)
	err := store.InitBootstrapWindow()
	require.NoError(t, err)
	err = store.CompleteBootstrap("adm_first")
	require.NoError(t, err)

	t.Log("Attempting second completion (should fail)")
	err = store.CompleteBootstrap("adm_second")

	t.Log("Verifying error is returned")
	assert.Error(t, err, "completing twice should fail")
	assert.Contains(t, err.Error(), "already completed", "error should indicate already completed")
}

// TestResetBootstrapWindow_Success tests successful bootstrap window reset.
func TestResetBootstrapWindow_Success(t *testing.T) {
	t.Log("Setting up test store and initializing bootstrap window")
	store := setupTestStore(t)
	err := store.InitBootstrapWindow()
	require.NoError(t, err)

	t.Log("Resetting bootstrap window")
	err = store.ResetBootstrapWindow()

	t.Log("Verifying reset succeeded")
	require.NoError(t, err, "ResetBootstrapWindow should succeed")

	t.Log("Verifying bootstrap state is now nil")
	state, err := store.GetBootstrapState()
	assert.NoError(t, err)
	assert.Nil(t, state, "state should be nil after reset")
}

// TestResetBootstrapWindow_NoState tests reset when no state exists.
func TestResetBootstrapWindow_NoState(t *testing.T) {
	t.Log("Setting up test store (no bootstrap state)")
	store := setupTestStore(t)

	t.Log("Resetting bootstrap window when no state exists")
	err := store.ResetBootstrapWindow()

	t.Log("Verifying no error (idempotent operation)")
	assert.NoError(t, err, "reset should be idempotent and not error when no state exists")
}

// TestResetBootstrapWindow_CanReinitialize tests that reset allows re-initialization.
func TestResetBootstrapWindow_CanReinitialize(t *testing.T) {
	t.Log("Setting up test store and initializing bootstrap window")
	store := setupTestStore(t)
	err := store.InitBootstrapWindow()
	require.NoError(t, err)

	t.Log("Resetting bootstrap window")
	err = store.ResetBootstrapWindow()
	require.NoError(t, err)

	t.Log("Re-initializing bootstrap window (should succeed after reset)")
	err = store.InitBootstrapWindow()

	t.Log("Verifying re-initialization succeeded")
	assert.NoError(t, err, "should be able to re-init after reset")

	state, err := store.GetBootstrapState()
	require.NoError(t, err)
	require.NotNil(t, state)
}

// TestHasFirstAdmin_False tests HasFirstAdmin returns false when no admin enrolled.
func TestHasFirstAdmin_False(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Checking HasFirstAdmin with no state")
	has, err := store.HasFirstAdmin()
	assert.NoError(t, err)
	assert.False(t, has, "should return false when no bootstrap state")

	t.Log("Initializing bootstrap window")
	err = store.InitBootstrapWindow()
	require.NoError(t, err)

	t.Log("Checking HasFirstAdmin with open window but no completion")
	has, err = store.HasFirstAdmin()
	assert.NoError(t, err)
	assert.False(t, has, "should return false when window open but not completed")
}

// TestHasFirstAdmin_True tests HasFirstAdmin returns true when first admin enrolled.
func TestHasFirstAdmin_True(t *testing.T) {
	t.Log("Setting up test store and completing bootstrap")
	store := setupTestStore(t)
	err := store.InitBootstrapWindow()
	require.NoError(t, err)
	err = store.CompleteBootstrap("adm_first")
	require.NoError(t, err)

	t.Log("Checking HasFirstAdmin after completion")
	has, err := store.HasFirstAdmin()

	t.Log("Verifying true is returned")
	assert.NoError(t, err)
	assert.True(t, has, "should return true when first admin is enrolled")
}

// TestBootstrapState_SingletonConstraint tests the id=1 constraint enforces singleton.
func TestBootstrapState_SingletonConstraint(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Inserting bootstrap state row")
	err := store.InitBootstrapWindow()
	require.NoError(t, err)

	t.Log("Attempting direct SQL insert with different ID (should fail)")
	_, err = store.db.Exec(`INSERT INTO bootstrap_state (id, window_opened_at) VALUES (2, ?)`, time.Now().Unix())

	t.Log("Verifying constraint violation")
	assert.Error(t, err, "inserting with id!=1 should fail due to CHECK constraint")
}

// ============== Enrollment Session Tests ==============

// TestCreateEnrollmentSession_Success tests successful session creation.
func TestCreateEnrollmentSession_Success(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Creating enrollment session")
	session := &EnrollmentSession{
		ID:            "sess_bootstrap_123",
		SessionType:   "bootstrap",
		ChallengeHash: "sha256_challenge_hash_here",
		IPAddress:     "192.168.1.100",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := store.CreateEnrollmentSession(session)

	t.Log("Verifying session was created")
	require.NoError(t, err, "CreateEnrollmentSession should succeed")

	t.Log("Retrieving session to verify")
	retrieved, err := store.GetEnrollmentSession("sess_bootstrap_123")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, "sess_bootstrap_123", retrieved.ID)
	assert.Equal(t, "bootstrap", retrieved.SessionType)
	assert.Equal(t, "sha256_challenge_hash_here", retrieved.ChallengeHash)
	assert.Equal(t, "192.168.1.100", retrieved.IPAddress)
	assert.Nil(t, retrieved.PublicKeyB64, "public key should be nil for bootstrap init")
}

// TestCreateEnrollmentSession_WithPublicKey tests session creation with public key.
func TestCreateEnrollmentSession_WithPublicKey(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Creating enrollment session with public key")
	pubKey := "base64_encoded_public_key"
	session := &EnrollmentSession{
		ID:            "sess_dpu_456",
		SessionType:   "dpu",
		ChallengeHash: "sha256_hash",
		PublicKeyB64:  &pubKey,
		IPAddress:     "10.0.0.50",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := store.CreateEnrollmentSession(session)
	require.NoError(t, err)

	t.Log("Retrieving session to verify public key")
	retrieved, err := store.GetEnrollmentSession("sess_dpu_456")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.NotNil(t, retrieved.PublicKeyB64)
	assert.Equal(t, "base64_encoded_public_key", *retrieved.PublicKeyB64)
}

// TestGetEnrollmentSession_NotFound tests retrieval of non-existent session.
func TestGetEnrollmentSession_NotFound(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Getting non-existent session")
	session, err := store.GetEnrollmentSession("nonexistent")

	t.Log("Verifying nil is returned with no error")
	assert.NoError(t, err, "should not error for non-existent session")
	assert.Nil(t, session, "should return nil for non-existent session")
}

// TestDeleteEnrollmentSession_Success tests successful session deletion.
func TestDeleteEnrollmentSession_Success(t *testing.T) {
	t.Log("Setting up test store and creating session")
	store := setupTestStore(t)
	session := &EnrollmentSession{
		ID:            "sess_to_delete",
		SessionType:   "admin_invite",
		ChallengeHash: "hash",
		IPAddress:     "127.0.0.1",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := store.CreateEnrollmentSession(session)
	require.NoError(t, err)

	t.Log("Deleting session")
	err = store.DeleteEnrollmentSession("sess_to_delete")

	t.Log("Verifying deletion succeeded")
	require.NoError(t, err, "DeleteEnrollmentSession should succeed")

	t.Log("Verifying session no longer exists")
	retrieved, err := store.GetEnrollmentSession("sess_to_delete")
	assert.NoError(t, err)
	assert.Nil(t, retrieved, "session should not exist after deletion")
}

// TestDeleteEnrollmentSession_NotFound tests deletion of non-existent session.
func TestDeleteEnrollmentSession_NotFound(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Deleting non-existent session (should be idempotent)")
	err := store.DeleteEnrollmentSession("nonexistent")

	t.Log("Verifying no error (idempotent)")
	assert.NoError(t, err, "deleting non-existent session should be idempotent")
}

// TestCleanupExpiredSessions_Success tests cleanup of expired sessions.
func TestCleanupExpiredSessions_Success(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Creating expired sessions")
	expiredTime := time.Now().Add(-1 * time.Hour) // 1 hour ago
	for i := 0; i < 3; i++ {
		session := &EnrollmentSession{
			ID:            "expired_" + string(rune('a'+i)),
			SessionType:   "bootstrap",
			ChallengeHash: "hash",
			IPAddress:     "127.0.0.1",
			CreatedAt:     expiredTime.Add(-5 * time.Minute),
			ExpiresAt:     expiredTime,
		}
		err := store.CreateEnrollmentSession(session)
		require.NoError(t, err)
	}

	t.Log("Creating valid (non-expired) session")
	validSession := &EnrollmentSession{
		ID:            "valid_session",
		SessionType:   "admin_invite",
		ChallengeHash: "hash",
		IPAddress:     "127.0.0.1",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := store.CreateEnrollmentSession(validSession)
	require.NoError(t, err)

	t.Log("Running cleanup of expired sessions")
	count, err := store.CleanupExpiredSessions()

	t.Log("Verifying cleanup results")
	require.NoError(t, err, "CleanupExpiredSessions should succeed")
	assert.Equal(t, int64(3), count, "should have cleaned up 3 expired sessions")

	t.Log("Verifying valid session still exists")
	retrieved, err := store.GetEnrollmentSession("valid_session")
	assert.NoError(t, err)
	assert.NotNil(t, retrieved, "valid session should still exist")

	t.Log("Verifying expired sessions are gone")
	for i := 0; i < 3; i++ {
		retrieved, err = store.GetEnrollmentSession("expired_" + string(rune('a'+i)))
		assert.NoError(t, err)
		assert.Nil(t, retrieved, "expired session should be deleted")
	}
}

// TestCleanupExpiredSessions_NoExpired tests cleanup when no sessions are expired.
func TestCleanupExpiredSessions_NoExpired(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Creating only valid sessions")
	for i := 0; i < 2; i++ {
		session := &EnrollmentSession{
			ID:            "valid_" + string(rune('a'+i)),
			SessionType:   "bootstrap",
			ChallengeHash: "hash",
			IPAddress:     "127.0.0.1",
			CreatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(5 * time.Minute),
		}
		err := store.CreateEnrollmentSession(session)
		require.NoError(t, err)
	}

	t.Log("Running cleanup (should clean nothing)")
	count, err := store.CleanupExpiredSessions()

	t.Log("Verifying no sessions were cleaned")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "should not clean any sessions")
}

// TestEnrollmentSession_AllTypes tests all session types can be stored.
func TestEnrollmentSession_AllTypes(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	sessionTypes := []string{"bootstrap", "admin_invite", "dpu"}

	for _, st := range sessionTypes {
		t.Run(st, func(t *testing.T) {
			t.Logf("Creating session with type: %s", st)
			session := &EnrollmentSession{
				ID:            "sess_" + st,
				SessionType:   st,
				ChallengeHash: "hash_" + st,
				IPAddress:     "127.0.0.1",
				CreatedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(5 * time.Minute),
			}
			err := store.CreateEnrollmentSession(session)
			require.NoError(t, err)

			t.Log("Retrieving and verifying session type")
			retrieved, err := store.GetEnrollmentSession("sess_" + st)
			require.NoError(t, err)
			require.NotNil(t, retrieved)
			assert.Equal(t, st, retrieved.SessionType)
		})
	}
}

// TestEnrollmentSession_DuplicateID tests that duplicate session IDs are rejected.
func TestEnrollmentSession_DuplicateID(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Creating first session")
	session1 := &EnrollmentSession{
		ID:            "duplicate_id",
		SessionType:   "bootstrap",
		ChallengeHash: "hash1",
		IPAddress:     "127.0.0.1",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := store.CreateEnrollmentSession(session1)
	require.NoError(t, err)

	t.Log("Attempting to create second session with same ID (should fail)")
	session2 := &EnrollmentSession{
		ID:            "duplicate_id",
		SessionType:   "admin_invite",
		ChallengeHash: "hash2",
		IPAddress:     "10.0.0.1",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err = store.CreateEnrollmentSession(session2)

	t.Log("Verifying error for duplicate ID")
	assert.Error(t, err, "should reject duplicate session ID")
}
