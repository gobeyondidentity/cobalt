package store

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateInviteCode(t *testing.T) {
	tests := []struct {
		name           string
		prefix         string
		wantSingleDash bool // first separator should be single dash, not double
	}{
		{
			name:           "clean prefix without dash",
			prefix:         "GPU",
			wantSingleDash: true,
		},
		{
			name:           "prefix with trailing dash",
			prefix:         "GPU-",
			wantSingleDash: true,
		},
		{
			name:           "four char prefix without dash",
			prefix:         "ACME",
			wantSingleDash: true,
		},
		{
			name:           "prefix with multiple trailing dashes",
			prefix:         "AB--",
			wantSingleDash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := GenerateInviteCode(tt.prefix)

			// Should have format PREFIX-XXXX-XXXX
			parts := strings.Split(code, "-")
			assert.Len(t, parts, 3, "invite code should have 3 parts separated by dashes")

			// First part should be prefix without trailing dashes
			expectedPrefix := strings.TrimRight(strings.ToUpper(tt.prefix), "-")
			assert.Equal(t, expectedPrefix, parts[0], "prefix should not have trailing dashes")

			// Second and third parts should be 4 chars each
			assert.Len(t, parts[1], 4, "second part should be 4 characters")
			assert.Len(t, parts[2], 4, "third part should be 4 characters")

			// Should not contain double dashes
			assert.NotContains(t, code, "--", "invite code should not contain double dashes")
		})
	}
}

func TestGenerateInviteCodeFormat(t *testing.T) {
	// Generate multiple codes to verify randomness and format
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code := GenerateInviteCode("TEST")
		codes[code] = true

		// Verify format
		assert.True(t, strings.HasPrefix(code, "TEST-"), "code should start with TEST-")
		assert.Len(t, code, 14, "code should be 14 chars: TEST-XXXX-XXXX")
	}

	// Should generate unique codes (collision extremely unlikely)
	assert.Greater(t, len(codes), 90, "should generate mostly unique codes")
}

func TestHashInviteCode(t *testing.T) {
	code := "TEST-ABCD-1234"
	hash := HashInviteCode(code)

	// SHA-256 produces 64 hex characters
	assert.Len(t, hash, 64)

	// Same input produces same hash
	assert.Equal(t, hash, HashInviteCode(code))

	// Different input produces different hash
	assert.NotEqual(t, hash, HashInviteCode("TEST-ABCD-5678"))
}

// TestCrossConnectionInviteCodeVisibility tests that invite codes created
// by one database connection are immediately visible to another connection.
// This simulates the scenario where the CLI creates an invite code and
// the Nexus server needs to validate it without a restart.
func TestCrossConnectionInviteCodeVisibility(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Open first connection (simulates Nexus server)
	SetInsecureMode(true)
	serverConn, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open server connection: %v", err)
	}
	defer serverConn.Close()

	// Create a tenant via server connection
	err = serverConn.AddTenant("tenant1", "Test Tenant", "desc", "contact", []string{})
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator via server connection
	err = serverConn.CreateOperator("op1", "test@example.com", "Test")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Open second connection (simulates CLI)
	cliConn, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open CLI connection: %v", err)
	}
	defer cliConn.Close()

	// Create invite code via CLI connection
	inviteCode := GenerateInviteCode("TEST")
	codeHash := HashInviteCode(inviteCode)
	invite := &InviteCode{
		ID:            "inv1",
		CodeHash:      codeHash,
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "cli",
		ExpiresAt:     DefaultExpirationTime(),
		Status:        "pending",
	}
	err = cliConn.CreateInviteCode(invite)
	if err != nil {
		t.Fatalf("failed to create invite code via CLI: %v", err)
	}

	// CRITICAL: Without WAL mode, this lookup would fail because the server
	// connection wouldn't see the invite code created by the CLI connection.
	// With WAL mode enabled, the server connection should immediately see the new invite.
	foundInvite, err := serverConn.GetInviteCodeByHash(codeHash)
	if err != nil {
		t.Fatalf("server connection failed to find invite code created by CLI: %v", err)
	}

	assert.Equal(t, "inv1", foundInvite.ID)
	assert.Equal(t, "test@example.com", foundInvite.OperatorEmail)
	assert.Equal(t, "pending", foundInvite.Status)
}

// DefaultExpirationTime returns a time 24 hours from now for testing.
func DefaultExpirationTime() time.Time {
	return time.Now().Add(24 * time.Hour)
}

// TestDeleteOperator_Success tests successful operator deletion.
func TestDeleteOperator_Success(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	store := setupTestStore(t)

	// Create a tenant and operator
	t.Log("Creating tenant and operator")
	if err := store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	if err := store.CreateOperator("op1", "test@example.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Add operator to tenant
	t.Log("Adding operator to tenant")
	if err := store.AddOperatorToTenant("op1", "tenant1", "operator"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}

	// Verify operator exists
	t.Log("Verifying operator exists before deletion")
	op, err := store.GetOperator("op1")
	if err != nil {
		t.Fatalf("operator should exist before deletion: %v", err)
	}
	assert.Equal(t, "op1", op.ID)

	// Delete the operator
	t.Log("Deleting operator")
	err = store.DeleteOperator("op1")
	if err != nil {
		t.Fatalf("DeleteOperator failed: %v", err)
	}

	// Verify operator is gone
	t.Log("Verifying operator no longer exists")
	_, err = store.GetOperator("op1")
	assert.Error(t, err, "operator should not exist after deletion")

	// Verify tenant membership is also removed
	t.Log("Verifying tenant membership is removed")
	memberships, err := store.GetOperatorTenants("op1")
	assert.NoError(t, err)
	assert.Len(t, memberships, 0, "operator should have no tenant memberships after deletion")
}

// TestDeleteOperator_HasKeymakers tests that operator deletion fails when keymakers exist.
func TestDeleteOperator_HasKeymakers(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	store := setupTestStore(t)

	// Create operator
	t.Log("Creating operator")
	if err := store.CreateOperator("op1", "test@example.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create a keymaker for this operator
	t.Log("Creating keymaker for operator")
	km := &KeyMaker{
		ID:                "km1",
		OperatorID:        "op1",
		Name:              "Test KeyMaker",
		Platform:          "darwin",
		SecureElement:     "TPM",
		DeviceFingerprint: "fingerprint123",
		PublicKey:         "pubkey123",
		Status:            "active",
	}
	if err := store.CreateKeyMaker(km); err != nil {
		t.Fatalf("failed to create keymaker: %v", err)
	}

	// Attempt to delete operator should fail
	t.Log("Attempting to delete operator with keymakers (should fail)")
	err := store.DeleteOperator("op1")
	assert.Error(t, err, "deleting operator with keymakers should fail")
	assert.Contains(t, err.Error(), "keymaker", "error should mention keymakers")

	// Verify operator still exists
	t.Log("Verifying operator still exists after failed deletion")
	op, err := store.GetOperator("op1")
	assert.NoError(t, err)
	assert.Equal(t, "op1", op.ID)
}

// TestDeleteOperator_HasAuthorizations tests that operator deletion fails when authorizations exist.
func TestDeleteOperator_HasAuthorizations(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	store := setupTestStore(t)

	// Create tenant and operator
	t.Log("Creating tenant and operator")
	if err := store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	if err := store.CreateOperator("op1", "test@example.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create an authorization for this operator
	t.Log("Creating authorization for operator")
	if err := store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"device1"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Attempt to delete operator should fail
	t.Log("Attempting to delete operator with authorizations (should fail)")
	err := store.DeleteOperator("op1")
	assert.Error(t, err, "deleting operator with authorizations should fail")
	assert.Contains(t, err.Error(), "authorization", "error should mention authorizations")

	// Verify operator still exists
	t.Log("Verifying operator still exists after failed deletion")
	op, err := store.GetOperator("op1")
	assert.NoError(t, err)
	assert.Equal(t, "op1", op.ID)
}

// TestDeleteOperator_NotFound tests deletion of non-existent operator.
func TestDeleteOperator_NotFound(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Attempting to delete non-existent operator")
	err := store.DeleteOperator("nonexistent")
	assert.Error(t, err, "deleting non-existent operator should fail")
	assert.Contains(t, err.Error(), "not found", "error should indicate operator not found")
}

// TestDeleteInviteCode_Success tests successful invite code deletion.
func TestDeleteInviteCode_Success(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	store := setupTestStore(t)

	// Create a tenant
	t.Log("Creating tenant")
	if err := store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an invite code
	t.Log("Creating invite code")
	code := GenerateInviteCode("TEST")
	codeHash := HashInviteCode(code)
	invite := &InviteCode{
		ID:            "inv1",
		CodeHash:      codeHash,
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		ExpiresAt:     DefaultExpirationTime(),
		Status:        "pending",
	}
	if err := store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Verify invite exists
	t.Log("Verifying invite code exists before deletion")
	found, err := store.GetInviteCodeByHash(codeHash)
	if err != nil {
		t.Fatalf("invite code should exist before deletion: %v", err)
	}
	assert.Equal(t, "inv1", found.ID)

	// Delete the invite code
	t.Log("Deleting invite code")
	err = store.DeleteInviteCode("inv1")
	if err != nil {
		t.Fatalf("DeleteInviteCode failed: %v", err)
	}

	// Verify invite is gone
	t.Log("Verifying invite code no longer exists")
	_, err = store.GetInviteCodeByHash(codeHash)
	assert.Error(t, err, "invite code should not exist after deletion")
}

// TestDeleteInviteCode_NotFound tests deletion of non-existent invite code.
func TestDeleteInviteCode_NotFound(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Attempting to delete non-existent invite code")
	err := store.DeleteInviteCode("nonexistent")
	assert.Error(t, err, "deleting non-existent invite code should fail")
	assert.Contains(t, err.Error(), "not found", "error should indicate invite code not found")
}

// TestListAllKeyMakers_Empty tests listing keymakers when none exist.
func TestListAllKeyMakers_Empty(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	t.Log("Listing all keymakers from empty database")
	keymakers, err := store.ListAllKeyMakers()
	assert.NoError(t, err, "listing empty keymakers should not error")
	assert.Len(t, keymakers, 0, "should return empty slice when no keymakers exist")
}

// TestListAllKeyMakers_ReturnsAll tests that ListAllKeyMakers returns all keymakers regardless of status.
func TestListAllKeyMakers_ReturnsAll(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	store := setupTestStore(t)

	// Create two operators
	t.Log("Creating operators")
	if err := store.CreateOperator("op1", "op1@example.com", "Operator 1"); err != nil {
		t.Fatalf("failed to create operator 1: %v", err)
	}
	if err := store.CreateOperator("op2", "op2@example.com", "Operator 2"); err != nil {
		t.Fatalf("failed to create operator 2: %v", err)
	}

	// Create keymakers with different statuses and operators
	t.Log("Creating keymakers with different statuses")
	keymakers := []*KeyMaker{
		{
			ID:                "km1",
			OperatorID:        "op1",
			Name:              "Active KM 1",
			Platform:          "darwin",
			SecureElement:     "TPM",
			DeviceFingerprint: "fp1",
			PublicKey:         "pk1",
			Status:            "active",
		},
		{
			ID:                "km2",
			OperatorID:        "op1",
			Name:              "Revoked KM",
			Platform:          "linux",
			SecureElement:     "TPM",
			DeviceFingerprint: "fp2",
			PublicKey:         "pk2",
			Status:            "revoked",
		},
		{
			ID:                "km3",
			OperatorID:        "op2",
			Name:              "Active KM 2",
			Platform:          "windows",
			SecureElement:     "TPM",
			DeviceFingerprint: "fp3",
			PublicKey:         "pk3",
			Status:            "active",
		},
	}

	for _, km := range keymakers {
		if err := store.CreateKeyMaker(km); err != nil {
			t.Fatalf("failed to create keymaker %s: %v", km.ID, err)
		}
	}

	t.Log("Listing all keymakers")
	result, err := store.ListAllKeyMakers()
	assert.NoError(t, err, "listing all keymakers should not error")
	assert.Len(t, result, 3, "should return all 3 keymakers")

	// Verify all keymakers are present
	t.Log("Verifying all keymakers are returned")
	ids := make(map[string]bool)
	for _, km := range result {
		ids[km.ID] = true
	}
	assert.True(t, ids["km1"], "should include km1")
	assert.True(t, ids["km2"], "should include km2 (revoked)")
	assert.True(t, ids["km3"], "should include km3")
}

// TestListAllKeyMakers_OrderedByBoundAtDesc tests that keymakers are ordered by bound_at DESC.
func TestListAllKeyMakers_OrderedByBoundAtDesc(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	store := setupTestStore(t)

	// Create an operator
	t.Log("Creating operator")
	if err := store.CreateOperator("op1", "op1@example.com", "Operator 1"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create keymakers with delays to ensure different timestamps
	// SQLite timestamps are in seconds, so we need 1+ second delay
	t.Log("Creating keymakers in sequence with 1 second delays")
	for i := 1; i <= 3; i++ {
		km := &KeyMaker{
			ID:                string(rune('a'+i-1)) + "km",
			OperatorID:        "op1",
			Name:              "KeyMaker",
			Platform:          "darwin",
			SecureElement:     "TPM",
			DeviceFingerprint: "fp",
			PublicKey:         "pk" + string(rune('0'+i)),
			Status:            "active",
		}
		if err := store.CreateKeyMaker(km); err != nil {
			t.Fatalf("failed to create keymaker %d: %v", i, err)
		}
		// 1 second delay to ensure different timestamps (SQLite uses seconds)
		if i < 3 {
			time.Sleep(1 * time.Second)
		}
	}

	t.Log("Listing all keymakers and verifying order")
	result, err := store.ListAllKeyMakers()
	assert.NoError(t, err, "listing all keymakers should not error")
	assert.Len(t, result, 3, "should return all 3 keymakers")

	// Most recent (last created) should be first due to DESC ordering
	t.Log("Verifying keymakers are ordered by bound_at DESC")
	assert.Equal(t, "ckm", result[0].ID, "most recently bound should be first")
	assert.Equal(t, "bkm", result[1].ID, "second most recent should be second")
	assert.Equal(t, "akm", result[2].ID, "oldest should be last")

	// Also verify bound_at values are actually in descending order
	t.Log("Verifying bound_at timestamps are in descending order")
	for i := 0; i < len(result)-1; i++ {
		assert.True(t, result[i].BoundAt.After(result[i+1].BoundAt) || result[i].BoundAt.Equal(result[i+1].BoundAt),
			"bound_at should be in descending order")
	}
}
