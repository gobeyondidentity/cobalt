package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			Kid:               "km1",
			KeyFingerprint:    "list-all-km1-fp",
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
			Kid:               "km2",
			KeyFingerprint:    "list-all-km2-fp",
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
			Kid:               "km3",
			KeyFingerprint:    "list-all-km3-fp",
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

	// Create keymakers
	t.Log("Creating keymakers")
	keymakerIDs := []string{"akm", "bkm", "ckm"}
	for i, kmID := range keymakerIDs {
		km := &KeyMaker{
			ID:                kmID,
			OperatorID:        "op1",
			Name:              "KeyMaker",
			Platform:          "darwin",
			SecureElement:     "TPM",
			DeviceFingerprint: "fp",
			PublicKey:         "pk" + string(rune('0'+i)),
			Status:            "active",
			Kid:               kmID,
			KeyFingerprint:    "ordered-" + kmID + "-fp",
		}
		if err := store.CreateKeyMaker(km); err != nil {
			t.Fatalf("failed to create keymaker %s: %v", kmID, err)
		}
	}

	// Set explicit bound_at timestamps via SQL to ensure deterministic ordering
	// akm: oldest (1000), bkm: middle (2000), ckm: newest (3000)
	t.Log("Setting explicit bound_at timestamps")
	timestamps := map[string]int64{"akm": 1000, "bkm": 2000, "ckm": 3000}
	for id, ts := range timestamps {
		_, err := store.DB().Exec("UPDATE keymakers SET bound_at = ? WHERE id = ?", ts, id)
		if err != nil {
			t.Fatalf("failed to update bound_at for %s: %v", id, err)
		}
	}

	t.Log("Listing all keymakers and verifying order")
	result, err := store.ListAllKeyMakers()
	assert.NoError(t, err, "listing all keymakers should not error")
	assert.Len(t, result, 3, "should return all 3 keymakers")

	// Most recent (highest timestamp) should be first due to DESC ordering
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

// ============== DPoP Key Lookup Tests ==============

// TestKeyFingerprint verifies SHA256 hex output for DPoP key fingerprints.
func TestKeyFingerprint(t *testing.T) {
	t.Log("Testing KeyFingerprint function produces correct SHA256 hex output")

	// Test with known input
	publicKey := []byte("test-public-key-data")
	expectedHash := sha256.Sum256(publicKey)
	expectedHex := hex.EncodeToString(expectedHash[:])

	t.Log("Computing fingerprint for known public key")
	result := KeyFingerprint(publicKey)

	t.Log("Verifying fingerprint is 64 character hex string (SHA256)")
	assert.Len(t, result, 64, "SHA256 hex fingerprint should be 64 characters")

	t.Log("Verifying fingerprint matches expected SHA256 hash")
	assert.Equal(t, expectedHex, result, "fingerprint should match expected SHA256 hex")

	t.Log("Verifying same input produces same fingerprint")
	result2 := KeyFingerprint(publicKey)
	assert.Equal(t, result, result2, "same input should produce same fingerprint")

	t.Log("Verifying different input produces different fingerprint")
	differentKey := []byte("different-public-key-data")
	differentResult := KeyFingerprint(differentKey)
	assert.NotEqual(t, result, differentResult, "different input should produce different fingerprint")
}

// TestAdminKey_CRUD tests create, get, get by kid, list, revoke operations for admin keys.
func TestAdminKey_CRUD(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	store := setupTestStore(t)

	// Create an operator first (admin keys require operator reference)
	t.Log("Creating operator for admin key ownership")
	err := store.CreateOperator("op1", "admin@example.com", "Admin User")
	require.NoError(t, err, "failed to create operator")

	// Test CreateAdminKey
	t.Log("Creating admin key with DPoP binding")
	publicKey := []byte("admin-public-key-data")
	fingerprint := KeyFingerprint(publicKey)
	ak := &AdminKey{
		ID:             "ak1",
		OperatorID:     "op1",
		Name:           "Admin Laptop",
		PublicKey:      publicKey,
		Kid:            "kid-123",
		KeyFingerprint: fingerprint,
		Status:         "active",
	}
	err = store.CreateAdminKey(ak)
	require.NoError(t, err, "CreateAdminKey should succeed")

	// Test GetAdminKey
	t.Log("Retrieving admin key by ID")
	retrieved, err := store.GetAdminKey("ak1")
	require.NoError(t, err, "GetAdminKey should succeed")
	assert.Equal(t, "ak1", retrieved.ID)
	assert.Equal(t, "op1", retrieved.OperatorID)
	assert.Equal(t, "Admin Laptop", retrieved.Name)
	assert.Equal(t, publicKey, retrieved.PublicKey)
	assert.Equal(t, "kid-123", retrieved.Kid)
	assert.Equal(t, fingerprint, retrieved.KeyFingerprint)
	assert.Equal(t, "active", retrieved.Status)
	assert.False(t, retrieved.BoundAt.IsZero(), "BoundAt should be set")

	// Test GetAdminKeyByKid
	t.Log("Retrieving admin key by kid for DPoP verification")
	byKid, err := store.GetAdminKeyByKid("kid-123")
	require.NoError(t, err, "GetAdminKeyByKid should succeed")
	assert.Equal(t, "ak1", byKid.ID)
	assert.Equal(t, "kid-123", byKid.Kid)

	// Test GetAdminKeyByKid with non-existent kid
	t.Log("Verifying GetAdminKeyByKid returns error for non-existent kid")
	_, err = store.GetAdminKeyByKid("nonexistent-kid")
	assert.Error(t, err, "should error for non-existent kid")

	// Test ListAdminKeysByOperator
	t.Log("Listing admin keys by operator")

	// Create a second admin key for the same operator
	ak2 := &AdminKey{
		ID:             "ak2",
		OperatorID:     "op1",
		Name:           "Admin Phone",
		PublicKey:      []byte("phone-public-key"),
		Kid:            "kid-456",
		KeyFingerprint: KeyFingerprint([]byte("phone-public-key")),
		Status:         "active",
	}
	err = store.CreateAdminKey(ak2)
	require.NoError(t, err, "CreateAdminKey for second key should succeed")

	keys, err := store.ListAdminKeysByOperator("op1")
	require.NoError(t, err, "ListAdminKeysByOperator should succeed")
	assert.Len(t, keys, 2, "should return 2 admin keys")

	// Test UpdateAdminKeyLastSeen
	t.Log("Updating last seen timestamp for admin key")
	err = store.UpdateAdminKeyLastSeen("ak1")
	require.NoError(t, err, "UpdateAdminKeyLastSeen should succeed")

	updated, _ := store.GetAdminKey("ak1")
	assert.NotNil(t, updated.LastSeen, "LastSeen should be set after update")

	// Test RevokeAdminKey
	t.Log("Revoking admin key")
	err = store.RevokeAdminKey("ak1")
	require.NoError(t, err, "RevokeAdminKey should succeed")

	revoked, _ := store.GetAdminKey("ak1")
	assert.Equal(t, "revoked", revoked.Status, "status should be revoked")

	// Verify revoked key is still returned by kid lookup (for rejection)
	t.Log("Verifying revoked key is still retrievable by kid for rejection logic")
	byKidRevoked, err := store.GetAdminKeyByKid("kid-123")
	require.NoError(t, err, "should still find revoked key by kid")
	assert.Equal(t, "revoked", byKidRevoked.Status)
}

// TestAdminKey_DuplicateKeyFingerprint verifies unique constraint rejects duplicate fingerprints.
func TestAdminKey_DuplicateKeyFingerprint(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	store := setupTestStore(t)

	// Create operator
	t.Log("Creating operator")
	err := store.CreateOperator("op1", "admin@example.com", "Admin User")
	require.NoError(t, err)

	// Create first admin key
	t.Log("Creating first admin key with unique fingerprint")
	publicKey := []byte("shared-public-key-data")
	fingerprint := KeyFingerprint(publicKey)
	ak1 := &AdminKey{
		ID:             "ak1",
		OperatorID:     "op1",
		Name:           "First Key",
		PublicKey:      publicKey,
		Kid:            "kid-1",
		KeyFingerprint: fingerprint,
		Status:         "active",
	}
	err = store.CreateAdminKey(ak1)
	require.NoError(t, err, "first admin key should be created")

	// Attempt to create second key with same fingerprint
	t.Log("Attempting to create second admin key with duplicate fingerprint (should fail)")
	ak2 := &AdminKey{
		ID:             "ak2",
		OperatorID:     "op1",
		Name:           "Second Key",
		PublicKey:      publicKey, // Same public key
		Kid:            "kid-2",   // Different kid
		KeyFingerprint: fingerprint,
		Status:         "active",
	}
	err = store.CreateAdminKey(ak2)
	assert.Error(t, err, "should reject duplicate key fingerprint")
	assert.Contains(t, err.Error(), "UNIQUE constraint failed", "error should indicate unique constraint violation")
}

// TestGetKeyMakerByKid verifies kid-based lookup for keymakers.
func TestGetKeyMakerByKid(t *testing.T) {
	t.Log("Setting up test store and prerequisite data")
	store := setupTestStore(t)

	// Create operator
	t.Log("Creating operator")
	err := store.CreateOperator("op1", "operator@example.com", "Test Operator")
	require.NoError(t, err)

	// Create keymaker without kid (legacy)
	t.Log("Creating keymaker without kid (legacy device)")
	km1 := &KeyMaker{
		ID:                "km1",
		OperatorID:        "op1",
		Name:              "Legacy Device",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "fp1",
		PublicKey:         "pubkey1",
		Status:            "active",
		Kid:               "km1-legacy",
		KeyFingerprint:    "getkmbykid-km1-fp",
	}
	err = store.CreateKeyMaker(km1)
	require.NoError(t, err)

	// Create keymaker with kid
	t.Log("Creating keymaker with kid for DPoP binding")
	km2 := &KeyMaker{
		ID:                "km2",
		OperatorID:        "op1",
		Name:              "DPoP Device",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "fp2",
		PublicKey:         "pubkey2",
		Status:            "active",
		Kid:               "km-kid-123",
		KeyFingerprint:    KeyFingerprint([]byte("pubkey2")),
	}
	err = store.CreateKeyMaker(km2)
	require.NoError(t, err)

	// Test GetKeyMakerByKid
	t.Log("Looking up keymaker by kid")
	found, err := store.GetKeyMakerByKid("km-kid-123")
	require.NoError(t, err, "GetKeyMakerByKid should succeed")
	assert.Equal(t, "km2", found.ID)
	assert.Equal(t, "DPoP Device", found.Name)

	// Test with non-existent kid
	t.Log("Verifying GetKeyMakerByKid returns error for non-existent kid")
	_, err = store.GetKeyMakerByKid("nonexistent")
	assert.Error(t, err, "should error for non-existent kid")
}

// TestGetDPUByKid verifies kid-based lookup for DPUs.
func TestGetDPUByKid(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	// Create DPU without kid (legacy)
	t.Log("Creating DPU without kid (legacy)")
	err := store.Add("dpu1", "bf3-legacy", "192.168.1.100", 50051)
	require.NoError(t, err)

	// Create DPU with kid
	t.Log("Creating DPU for DPoP binding")
	err = store.Add("dpu2", "bf3-dpop", "192.168.1.101", 50051)
	require.NoError(t, err)

	// Set kid and public_key on dpu2
	t.Log("Setting kid and public_key on DPU via direct update")
	publicKey := []byte("dpu-public-key-data")
	_, err = store.db.Exec(`UPDATE dpus SET public_key = ?, kid = ?, key_fingerprint = ? WHERE id = ?`,
		publicKey, "dpu-kid-456", KeyFingerprint(publicKey), "dpu2")
	require.NoError(t, err)

	// Test GetDPUByKid
	t.Log("Looking up DPU by kid")
	found, err := store.GetDPUByKid("dpu-kid-456")
	require.NoError(t, err, "GetDPUByKid should succeed")
	assert.Equal(t, "dpu2", found.ID)
	assert.Equal(t, "bf3-dpop", found.Name)
	assert.Equal(t, publicKey, found.PublicKey)

	// Test with non-existent kid
	t.Log("Verifying GetDPUByKid returns error for non-existent kid")
	_, err = store.GetDPUByKid("nonexistent")
	assert.Error(t, err, "should error for non-existent kid")
}

// BenchmarkKeyMakerLookupByKid benchmarks kid-based keymaker lookup.
// Target: <1ms for 10,000 lookups (100ns per lookup average).
func BenchmarkKeyMakerLookupByKid(b *testing.B) {
	// Setup: create store with many keymakers
	tmpDir := b.TempDir()
	dbPath := tmpDir + "/bench.db"
	store, err := Open(dbPath)
	if err != nil {
		b.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Create operator
	err = store.CreateOperator("op1", "operator@example.com", "Test")
	if err != nil {
		b.Fatalf("failed to create operator: %v", err)
	}

	// Create 1000 keymakers with kids using fmt.Sprintf for unique IDs
	var targetKid string
	for i := 0; i < 1000; i++ {
		id := "km" + strings.Repeat("0", 4-len(string(rune('0'+i%10000/1000)))) + string(rune('0'+i%10000/1000)) + string(rune('0'+i%1000/100)) + string(rune('0'+i%100/10)) + string(rune('0'+i%10))
		// Simplified: just use a format string
		id = "km" + string([]byte{'0' + byte(i/1000%10), '0' + byte(i/100%10), '0' + byte(i/10%10), '0' + byte(i%10)})
		km := &KeyMaker{
			ID:                id,
			OperatorID:        "op1",
			Name:              "Device",
			Platform:          "darwin",
			SecureElement:     "secure_enclave",
			DeviceFingerprint: "fp" + id,
			PublicKey:         "pk" + id,
			Status:            "active",
		}
		err = store.CreateKeyMaker(km)
		if err != nil {
			b.Fatalf("failed to create keymaker %s: %v", id, err)
		}
		kid := "kid-" + id
		_, err = store.db.Exec(`UPDATE keymakers SET kid = ? WHERE id = ?`, kid, id)
		if err != nil {
			b.Fatalf("failed to set kid: %v", err)
		}
		// Target kid in the middle (around index 500)
		if i == 500 {
			targetKid = kid
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.GetKeyMakerByKid(targetKid)
		if err != nil {
			b.Fatalf("lookup failed: %v", err)
		}
	}
}

// TestAdminKey_ListEmpty verifies empty list behavior.
func TestAdminKey_ListEmpty(t *testing.T) {
	t.Log("Setting up test store")
	store := setupTestStore(t)

	// Create operator with no admin keys
	t.Log("Creating operator without admin keys")
	err := store.CreateOperator("op1", "admin@example.com", "Admin")
	require.NoError(t, err)

	t.Log("Listing admin keys for operator with none")
	keys, err := store.ListAdminKeysByOperator("op1")
	assert.NoError(t, err, "listing empty should not error")
	assert.Len(t, keys, 0, "should return empty slice")
}
