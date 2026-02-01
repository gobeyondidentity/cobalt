package store

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/enrollment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInviteCodeCreation verifies invite code creation stores hash, not plaintext.
func TestInviteCodeCreation(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant (required for invite codes)
	t.Log("Creating tenant for invite code")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err, "failed to create tenant")

	// Create invite service
	t.Log("Creating invite service")
	svc := NewInviteService(store)

	// Create invite code
	t.Log("Creating invite code via service")
	req := CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	}
	result, err := svc.CreateInviteCode(req)
	require.NoError(t, err, "CreateInviteCode should succeed")

	// Verify result has ID and plaintext
	t.Log("Verifying result has ID and plaintext code")
	assert.NotEmpty(t, result.ID, "result should have ID")
	assert.NotEmpty(t, result.Plaintext, "result should have plaintext code")
	assert.False(t, result.ExpiresAt.IsZero(), "result should have expiration time")

	// Verify hash was stored, not plaintext
	t.Log("Verifying stored hash differs from plaintext")
	storedCode, err := store.GetInviteCodeByHash(enrollment.HashCode(result.Plaintext))
	require.NoError(t, err, "should find code by hash")
	assert.Equal(t, result.ID, storedCode.ID, "IDs should match")
	assert.NotEqual(t, result.Plaintext, storedCode.CodeHash, "stored hash should differ from plaintext")
	assert.Equal(t, enrollment.HashCode(result.Plaintext), storedCode.CodeHash, "stored hash should match computed hash")
}

// TestValidateInviteCodeSuccess verifies successful validation of a valid code.
func TestValidateInviteCodeSuccess(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite service and code
	t.Log("Creating invite code")
	svc := NewInviteService(store)
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	require.NoError(t, err)

	// Validate the code
	t.Log("Validating invite code")
	invite, err := svc.ValidateInviteCode(result.Plaintext)
	require.NoError(t, err, "ValidateInviteCode should succeed for valid code")

	// Verify returned metadata
	t.Log("Verifying returned metadata")
	assert.Equal(t, result.ID, invite.ID)
	assert.Equal(t, "test@example.com", invite.OperatorEmail)
	assert.Equal(t, "tenant1", invite.TenantID)
	assert.Equal(t, "operator", invite.Role)
	assert.Equal(t, "pending", invite.Status)
}

// TestValidateExpiredCode verifies expired codes are rejected.
func TestValidateExpiredCode(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite service with very short TTL
	t.Log("Creating invite code with 1ms TTL")
	svc := NewInviteService(store)
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Millisecond,
	})
	require.NoError(t, err)

	// Wait for expiration
	t.Log("Waiting for code to expire")
	time.Sleep(10 * time.Millisecond)

	// Attempt to validate
	t.Log("Attempting to validate expired code")
	_, err = svc.ValidateInviteCode(result.Plaintext)
	assert.Error(t, err, "should reject expired code")
	assert.Equal(t, enrollment.ErrCodeExpiredCode, enrollment.ErrorCode(err), "error should be expired code error")
}

// TestValidateConsumedCode verifies consumed codes are rejected.
func TestValidateConsumedCode(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite code
	t.Log("Creating invite code")
	svc := NewInviteService(store)
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	require.NoError(t, err)

	// Consume the code
	t.Log("Consuming the invite code")
	_, err = svc.ConsumeInviteCode(result.Plaintext, "km_test123")
	require.NoError(t, err)

	// Attempt to validate consumed code
	t.Log("Attempting to validate consumed code")
	_, err = svc.ValidateInviteCode(result.Plaintext)
	assert.Error(t, err, "should reject consumed code")
	assert.Equal(t, enrollment.ErrCodeCodeConsumed, enrollment.ErrorCode(err), "error should be code consumed error")
}

// TestValidateInvalidCode verifies non-existent codes are rejected.
func TestValidateInvalidCode(t *testing.T) {
	t.Log("Setting up test store")
	SetInsecureMode(true)
	store := setupTestStore(t)

	svc := NewInviteService(store)

	// Attempt to validate non-existent code
	t.Log("Attempting to validate non-existent code")
	_, err := svc.ValidateInviteCode("invalid-code-that-does-not-exist")
	assert.Error(t, err, "should reject invalid code")
	assert.Equal(t, enrollment.ErrCodeInvalidCode, enrollment.ErrorCode(err), "error should be invalid code error")
}

// TestConsumeInviteCode verifies basic consumption works.
func TestConsumeInviteCode(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite code
	t.Log("Creating invite code")
	svc := NewInviteService(store)
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	require.NoError(t, err)

	// Consume the code
	t.Log("Consuming the invite code")
	invite, err := svc.ConsumeInviteCode(result.Plaintext, "km_test123")
	require.NoError(t, err, "ConsumeInviteCode should succeed")

	// Verify returned metadata
	t.Log("Verifying returned metadata")
	assert.Equal(t, result.ID, invite.ID)
	assert.Equal(t, "test@example.com", invite.OperatorEmail)

	// Verify status in store
	t.Log("Verifying status is 'used' in store")
	storedCode, err := store.GetInviteCodeByHash(enrollment.HashCode(result.Plaintext))
	require.NoError(t, err)
	assert.Equal(t, "used", storedCode.Status)
	assert.NotNil(t, storedCode.UsedByKeyMaker)
	assert.Equal(t, "km_test123", *storedCode.UsedByKeyMaker)
}

// TestConsumeInviteCodeConcurrent verifies exactly one goroutine succeeds in a race.
func TestConsumeInviteCodeConcurrent(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite code
	t.Log("Creating invite code")
	svc := NewInviteService(store)
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	require.NoError(t, err)

	// Launch 100 goroutines trying to consume simultaneously
	t.Log("Launching 100 goroutines to consume the same code")
	const numGoroutines = 100
	var successCount int32
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			keymakerID := "km_test" + string(rune('0'+idx%10))
			_, err := svc.ConsumeInviteCode(result.Plaintext, keymakerID)
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}(i)
	}

	wg.Wait()

	// Exactly one should succeed
	t.Log("Verifying exactly 1 goroutine succeeded")
	assert.Equal(t, int32(1), successCount, "exactly 1 goroutine should succeed in consuming the code")
}

// TestConsumeInviteCodeTwice verifies second consumption attempt fails.
func TestConsumeInviteCodeTwice(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite code
	t.Log("Creating invite code")
	svc := NewInviteService(store)
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	require.NoError(t, err)

	// First consumption
	t.Log("First consumption attempt")
	_, err = svc.ConsumeInviteCode(result.Plaintext, "km_first")
	require.NoError(t, err, "first consumption should succeed")

	// Second consumption attempt
	t.Log("Second consumption attempt (should fail)")
	_, err = svc.ConsumeInviteCode(result.Plaintext, "km_second")
	assert.Error(t, err, "second consumption should fail")
	assert.Equal(t, enrollment.ErrCodeCodeConsumed, enrollment.ErrorCode(err), "error should be code consumed error")
}

// TestCreateInviteCodeAudit verifies audit log entry on creation.
func TestCreateInviteCodeAudit(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite code
	t.Log("Creating invite code")
	svc := NewInviteService(store)
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin_user",
		TTL:           1 * time.Hour,
	})
	require.NoError(t, err)

	// Query audit log
	t.Log("Querying audit log for invite_code.created action")
	entries, err := store.QueryAuditEntries(AuditFilter{
		Action: "invite_code.created",
		Target: result.ID,
		Limit:  1,
	})
	require.NoError(t, err, "QueryAuditEntries should succeed")
	require.Len(t, entries, 1, "should have 1 audit entry")

	// Verify audit entry details
	t.Log("Verifying audit entry details")
	entry := entries[0]
	assert.Equal(t, "invite_code.created", entry.Action)
	assert.Equal(t, result.ID, entry.Target)
	assert.Equal(t, "admin_user", entry.Details["creator"])
	assert.Equal(t, "test@example.com", entry.Details["target_email"])
	assert.NotEmpty(t, entry.Details["expires_at"])
}

// TestConsumeInviteCodeAudit verifies audit log entry on consumption.
func TestConsumeInviteCodeAudit(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite code
	t.Log("Creating invite code")
	svc := NewInviteService(store)
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin_user",
		TTL:           1 * time.Hour,
	})
	require.NoError(t, err)

	// Consume the code
	t.Log("Consuming the invite code")
	_, err = svc.ConsumeInviteCode(result.Plaintext, "km_consumer")
	require.NoError(t, err)

	// Query audit log for consumption
	t.Log("Querying audit log for invite_code.consumed action")
	entries, err := store.QueryAuditEntries(AuditFilter{
		Action: "invite_code.consumed",
		Target: result.ID,
		Limit:  1,
	})
	require.NoError(t, err, "QueryAuditEntries should succeed")
	require.Len(t, entries, 1, "should have 1 audit entry")

	// Verify audit entry details
	t.Log("Verifying audit entry details")
	entry := entries[0]
	assert.Equal(t, "invite_code.consumed", entry.Action)
	assert.Equal(t, result.ID, entry.Target)
	assert.Equal(t, "km_consumer", entry.Details["consumer_keymaker"])
	assert.Equal(t, "admin_user", entry.Details["original_creator"])
}

// TestInviteCodeDefaultTTL verifies default 1 hour TTL when not specified.
func TestInviteCodeDefaultTTL(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite code without TTL (zero value)
	t.Log("Creating invite code without specifying TTL")
	svc := NewInviteService(store)
	before := time.Now()
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		// TTL not specified (zero)
	})
	require.NoError(t, err)
	after := time.Now()

	// Verify expiration is approximately 1 hour from now
	t.Log("Verifying default TTL is approximately 1 hour")
	expectedMin := before.Add(1 * time.Hour)
	expectedMax := after.Add(1 * time.Hour)
	assert.True(t, result.ExpiresAt.After(expectedMin) || result.ExpiresAt.Equal(expectedMin),
		"expiration should be at least 1 hour from start")
	assert.True(t, result.ExpiresAt.Before(expectedMax) || result.ExpiresAt.Equal(expectedMax),
		"expiration should be at most 1 hour from end")
}

// TestConsumeInviteCodeAtomicity verifies the atomic UPDATE WHERE pattern.
func TestConsumeInviteCodeAtomicity(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	SetInsecureMode(true)
	store := setupTestStore(t)

	// Create tenant
	t.Log("Creating tenant")
	err := store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	require.NoError(t, err)

	// Create invite code
	t.Log("Creating invite code")
	svc := NewInviteService(store)
	result, err := svc.CreateInviteCode(CreateInviteCodeRequest{
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	require.NoError(t, err)

	// Get the invite to verify initial state
	t.Log("Verifying initial state is 'pending'")
	invite, err := store.GetInviteCodeByHash(enrollment.HashCode(result.Plaintext))
	require.NoError(t, err)
	assert.Equal(t, "pending", invite.Status)

	// Directly call atomic consume
	t.Log("Calling atomic ConsumeInviteCode")
	err = store.ConsumeInviteCode(invite.ID, "km_test")
	require.NoError(t, err, "ConsumeInviteCode should succeed")

	// Verify state changed
	t.Log("Verifying state changed to 'used'")
	invite, err = store.GetInviteCodeByHash(enrollment.HashCode(result.Plaintext))
	require.NoError(t, err)
	assert.Equal(t, "used", invite.Status)
	assert.NotNil(t, invite.UsedByKeyMaker)
	assert.Equal(t, "km_test", *invite.UsedByKeyMaker)

	// Second attempt should fail
	t.Log("Verifying second atomic consume fails")
	err = store.ConsumeInviteCode(invite.ID, "km_other")
	assert.Error(t, err, "second ConsumeInviteCode should fail")
}
