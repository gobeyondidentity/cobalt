package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// setupAdminKeyTest creates a test store with a tenant, operator, and admin key.
func setupAdminKeyTest(t *testing.T) (*store.Store, *Server, func()) {
	t.Helper()

	// Create temp database
	tmpFile, err := os.CreateTemp("", "adminkey_test_*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()

	s, err := store.Open(dbPath)
	if err != nil {
		os.Remove(dbPath)
		t.Fatalf("failed to open store: %v", err)
	}

	srv := NewServer(s)

	cleanup := func() {
		s.Close()
		os.Remove(dbPath)
	}

	return s, srv, cleanup
}

// createTestAdminKey creates a test admin key in the store.
func createTestAdminKey(t *testing.T, s *store.Store, id, operatorID, status string) *store.AdminKey {
	t.Helper()

	ak := &store.AdminKey{
		ID:             id,
		OperatorID:     operatorID,
		Name:           "test-key",
		PublicKey:      make([]byte, 32), // dummy key
		Kid:            id,
		KeyFingerprint: "fp_" + id,
		Status:         status,
	}
	if err := s.CreateAdminKey(ak); err != nil {
		t.Fatalf("failed to create admin key: %v", err)
	}
	return ak
}

// createTestOperator creates a test operator in the store.
func createTestOperator(t *testing.T, s *store.Store, id, email string) {
	t.Helper()

	if err := s.CreateOperator(id, email, "Test User"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := s.UpdateOperatorStatus(id, "active"); err != nil {
		t.Fatalf("failed to update operator status: %v", err)
	}
}

// createTestTenant creates a test tenant in the store.
func createTestTenant(t *testing.T, s *store.Store, id, name string) {
	t.Helper()

	if err := s.AddTenant(id, name, "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
}

// addOperatorToTenant adds an operator to a tenant with the given role.
func addOperatorToTenant(t *testing.T, s *store.Store, operatorID, tenantID, role string) {
	t.Helper()

	if err := s.AddOperatorToTenant(operatorID, tenantID, role); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}
}

// requestWithIdentity creates an HTTP request with a DPoP identity in context.
func requestWithIdentity(method, url string, body []byte, identity *dpop.Identity) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, url, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	req.Header.Set("Content-Type", "application/json")

	if identity != nil {
		ctx := dpop.ContextWithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)
	}
	return req
}

func TestRevokeAdminKey_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing successful admin key revocation by super:admin")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	// Setup: create tenant, operator with super:admin role, and admin key
	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")

	// Create an admin key for caller (so we don't hit last super:admin check)
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")
	// Create target admin key to revoke
	createTestAdminKey(t, s, "adm_target", "op_target", "active")

	// Make revocation request
	reqBody := RevokeAdminKeyRequest{Reason: "Compromised device"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_target", body, identity)
	req.SetPathValue("id", "adm_target")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify the key is revoked
	ak, err := s.GetAdminKey("adm_target")
	if err != nil {
		t.Fatalf("failed to get admin key: %v", err)
	}
	if ak.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %s", ak.Status)
	}
	if ak.RevokedBy == nil || *ak.RevokedBy != "adm_caller" {
		t.Errorf("expected revoked_by 'adm_caller', got %v", ak.RevokedBy)
	}
	if ak.RevokedReason == nil || *ak.RevokedReason != "Compromised device" {
		t.Errorf("expected revoked_reason 'Compromised device', got %v", ak.RevokedReason)
	}

	t.Log("Admin key successfully revoked with audit tracking")
}

func TestRevokeAdminKey_EmptyReason(t *testing.T) {
	t.Parallel()
	t.Log("Testing that empty reason is rejected with 400")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")
	createTestAdminKey(t, s, "adm_target", "op_caller", "active")

	reqBody := RevokeAdminKeyRequest{Reason: ""}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_target", body, identity)
	req.SetPathValue("id", "adm_target")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] == "" || resp["error"] != "reason is required and cannot be empty" {
		t.Errorf("expected 'reason is required' error, got %s", resp["error"])
	}

	t.Log("Empty reason correctly rejected with 400")
}

func TestRevokeAdminKey_TenantAdminForbidden(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin receives 403 when attempting to revoke")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")
	createTestAdminKey(t, s, "adm_target", "op_tenantadmin", "active")

	reqBody := RevokeAdminKeyRequest{Reason: "Test reason"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_target", body, identity)
	req.SetPathValue("id", "adm_target")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "only super:admin can revoke admin keys" {
		t.Errorf("expected 'only super:admin' error, got %s", resp["error"])
	}

	t.Log("tenant:admin correctly receives 403")
}

func TestRevokeAdminKey_NotFound(t *testing.T) {
	t.Parallel()
	t.Log("Testing that non-existent admin key returns 404")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")

	reqBody := RevokeAdminKeyRequest{Reason: "Test reason"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_nonexistent", body, identity)
	req.SetPathValue("id", "adm_nonexistent")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Non-existent admin key correctly returns 404")
}

func TestRevokeAdminKey_AlreadyRevoked(t *testing.T) {
	t.Parallel()
	t.Log("Testing that already-revoked admin key returns 409")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")
	createTestAdminKey(t, s, "adm_revoked", "op_caller", "revoked")

	reqBody := RevokeAdminKeyRequest{Reason: "Test reason"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_revoked", body, identity)
	req.SetPathValue("id", "adm_revoked")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "admin key is already revoked" {
		t.Errorf("expected 'already revoked' error, got %s", resp["error"])
	}

	t.Log("Already revoked key correctly returns 409 (LC-1: revocation is permanent)")
}

func TestRevokeAdminKey_LastSuperAdminProtection(t *testing.T) {
	t.Parallel()
	t.Log("Testing that cannot revoke last active super:admin key")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")

	// Only one super:admin key exists
	createTestAdminKey(t, s, "adm_only", "op_superadmin", "active")

	reqBody := RevokeAdminKeyRequest{Reason: "Test reason"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_only",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_only", body, identity)
	req.SetPathValue("id", "adm_only")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "cannot revoke the last active super:admin key (would cause system lockout)" {
		t.Errorf("expected 'last active super:admin' error, got %s", resp["error"])
	}

	// Verify key is still active
	ak, _ := s.GetAdminKey("adm_only")
	if ak.Status != "active" {
		t.Errorf("expected status 'active', got %s", ak.Status)
	}

	t.Log("Last super:admin key protection working correctly")
}

func TestRevokeAdminKey_SelfRevocationAllowed(t *testing.T) {
	t.Parallel()
	t.Log("Testing that self-revocation is allowed but logged with warning")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_other", "other@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_other", "tenant1", "super:admin")

	// Create keys for both super:admins so self-revocation doesn't hit "last admin" protection
	createTestAdminKey(t, s, "adm_self", "op_superadmin", "active")
	createTestAdminKey(t, s, "adm_other", "op_other", "active")

	reqBody := RevokeAdminKeyRequest{Reason: "Retiring this device"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_self",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_self", body, identity)
	req.SetPathValue("id", "adm_self")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify the key is revoked
	ak, err := s.GetAdminKey("adm_self")
	if err != nil {
		t.Fatalf("failed to get admin key: %v", err)
	}
	if ak.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %s", ak.Status)
	}

	// Verify audit log has self_revocation flag
	entries, err := s.QueryAuditEntries(store.AuditFilter{Action: "admin_key.self_revoke", Limit: 1})
	if err != nil {
		t.Fatalf("failed to query audit entries: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 self_revoke audit entry, got %d", len(entries))
	} else {
		if entries[0].Details["self_revocation"] != "true" {
			t.Errorf("expected self_revocation=true in audit, got %s", entries[0].Details["self_revocation"])
		}
	}

	t.Log("Self-revocation allowed and logged with warning")
}

func TestRevokeAdminKey_Unauthenticated(t *testing.T) {
	t.Parallel()
	t.Log("Testing that unauthenticated request returns 401")

	_, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	reqBody := RevokeAdminKeyRequest{Reason: "Test reason"}
	body, _ := json.Marshal(reqBody)

	// No identity in context
	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_target", body, nil)
	req.SetPathValue("id", "adm_target")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Unauthenticated request correctly rejected with 401")
}

func TestRevokeAdminKey_InvalidJSON(t *testing.T) {
	t.Parallel()
	t.Log("Testing that invalid JSON returns 400")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_target", []byte("invalid json"), identity)
	req.SetPathValue("id", "adm_target")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Invalid JSON correctly rejected with 400")
}

func TestRevokeAdminKey_WhitespaceReason(t *testing.T) {
	t.Parallel()
	t.Log("Testing that whitespace-only reason is rejected")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")
	createTestAdminKey(t, s, "adm_target", "op_caller", "active")

	reqBody := RevokeAdminKeyRequest{Reason: "   \t\n  "}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("DELETE", "/api/v1/admin-keys/adm_target", body, identity)
	req.SetPathValue("id", "adm_target")

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Whitespace-only reason correctly rejected")
}

func TestCountActiveSuperAdminKeys(t *testing.T) {
	t.Parallel()
	t.Log("Testing CountActiveSuperAdminKeys store method")

	s, _, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	// Initially no super:admin keys
	count, err := s.CountActiveSuperAdminKeys()
	if err != nil {
		t.Fatalf("CountActiveSuperAdminKeys failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 super admin keys, got %d", count)
	}
	t.Log("Initial count: 0 super:admin keys")

	// Add tenant and operator with super:admin role
	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")

	// Still 0 because no admin key yet
	count, _ = s.CountActiveSuperAdminKeys()
	if count != 0 {
		t.Errorf("expected 0 super admin keys (no admin key yet), got %d", count)
	}

	// Create active admin key for super:admin
	createTestAdminKey(t, s, "adm_super1", "op_superadmin", "active")

	count, _ = s.CountActiveSuperAdminKeys()
	if count != 1 {
		t.Errorf("expected 1 super admin key, got %d", count)
	}
	t.Log("After adding super:admin with key: 1 super:admin key")

	// Add another super:admin with key
	createTestOperator(t, s, "op_superadmin2", "superadmin2@test.com")
	addOperatorToTenant(t, s, "op_superadmin2", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_super2", "op_superadmin2", "active")

	count, _ = s.CountActiveSuperAdminKeys()
	if count != 2 {
		t.Errorf("expected 2 super admin keys, got %d", count)
	}
	t.Log("After adding second super:admin: 2 super:admin keys")

	// Add a regular operator with admin key (should not count)
	createTestOperator(t, s, "op_regular", "regular@test.com")
	addOperatorToTenant(t, s, "op_regular", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_regular", "op_regular", "active")

	count, _ = s.CountActiveSuperAdminKeys()
	if count != 2 {
		t.Errorf("expected still 2 super admin keys (regular operator doesn't count), got %d", count)
	}
	t.Log("Regular operator key doesn't count as super:admin")

	// Revoke one super:admin key
	s.RevokeAdminKeyWithReason("adm_super1", "test", "test")

	count, _ = s.CountActiveSuperAdminKeys()
	if count != 1 {
		t.Errorf("expected 1 super admin key after revocation, got %d", count)
	}
	t.Log("After revoking one: 1 super:admin key")
}

func TestIsAdminKeyLastActiveSuperAdmin(t *testing.T) {
	t.Parallel()
	t.Log("Testing IsAdminKeyLastActiveSuperAdmin store method")

	s, _, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")

	// Create super:admin with one key
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_only_super", "op_superadmin", "active")

	// This is the only super:admin key
	isLast, err := s.IsAdminKeyLastActiveSuperAdmin("adm_only_super")
	if err != nil {
		t.Fatalf("IsAdminKeyLastActiveSuperAdmin failed: %v", err)
	}
	if !isLast {
		t.Error("expected isLast=true for only super:admin key")
	}
	t.Log("Single super:admin key correctly identified as last")

	// Add another super:admin key
	createTestOperator(t, s, "op_superadmin2", "superadmin2@test.com")
	addOperatorToTenant(t, s, "op_superadmin2", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_super2", "op_superadmin2", "active")

	// Now neither is "last"
	isLast, _ = s.IsAdminKeyLastActiveSuperAdmin("adm_only_super")
	if isLast {
		t.Error("expected isLast=false when there are 2 super:admin keys")
	}
	t.Log("With 2 super:admin keys, neither is last")

	// Test with non-super:admin key
	createTestOperator(t, s, "op_regular", "regular@test.com")
	addOperatorToTenant(t, s, "op_regular", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_regular", "op_regular", "active")

	isLast, _ = s.IsAdminKeyLastActiveSuperAdmin("adm_regular")
	if isLast {
		t.Error("expected isLast=false for non-super:admin key")
	}
	t.Log("Non-super:admin key correctly identified as not-last")
}

// Import context for dpop.ContextWithIdentity
var _ = context.Background

// ----- List AdminKey Tests -----

func TestListAdminKeys_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing successful admin key listing by super:admin")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	// Setup: create tenant, operators, and admin keys
	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	createTestOperator(t, s, "op_other", "other@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_other", "tenant1", "operator")

	// Create admin keys
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")
	createTestAdminKey(t, s, "adm_other", "op_other", "active")

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("GET", "/api/v1/admin-keys", nil, identity)
	rec := httptest.NewRecorder()
	srv.handleListAdminKeys(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var keys []AdminKeyResponse
	if err := json.NewDecoder(rec.Body).Decode(&keys); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("expected 2 admin keys, got %d", len(keys))
	}
	t.Log("Admin keys listed successfully")
}

func TestListAdminKeys_WithStatusFilter(t *testing.T) {
	t.Parallel()
	t.Log("Testing admin key listing with status filter")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	createTestOperator(t, s, "op_other", "other@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_other", "tenant1", "operator")

	createTestAdminKey(t, s, "adm_active", "op_caller", "active")
	createTestAdminKey(t, s, "adm_revoked", "op_other", "revoked")

	identity := &dpop.Identity{
		KID:        "adm_active",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	// Test filter by revoked
	req := requestWithIdentity("GET", "/api/v1/admin-keys?status=revoked", nil, identity)
	rec := httptest.NewRecorder()
	srv.handleListAdminKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var keys []AdminKeyResponse
	if err := json.NewDecoder(rec.Body).Decode(&keys); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("expected 1 revoked admin key, got %d", len(keys))
	}
	if len(keys) > 0 && keys[0].Status != "revoked" {
		t.Errorf("expected status 'revoked', got %s", keys[0].Status)
	}
	t.Log("Status filter works correctly")
}

func TestListAdminKeys_TenantAdminForbidden(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin receives 403 for listing admin keys")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_tenant_admin", "tadmin@test.com")
	addOperatorToTenant(t, s, "op_tenant_admin", "tenant1", "tenant:admin")
	createTestAdminKey(t, s, "adm_tadmin", "op_tenant_admin", "active")

	identity := &dpop.Identity{
		KID:        "adm_tadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenant_admin",
	}

	req := requestWithIdentity("GET", "/api/v1/admin-keys", nil, identity)
	rec := httptest.NewRecorder()
	srv.handleListAdminKeys(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", rec.Code, rec.Body.String())
	}
	t.Log("tenant:admin correctly receives 403")
}

func TestListAdminKeys_InvalidStatus(t *testing.T) {
	t.Parallel()
	t.Log("Testing that invalid status filter returns 400")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("GET", "/api/v1/admin-keys?status=invalid", nil, identity)
	rec := httptest.NewRecorder()
	srv.handleListAdminKeys(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
	}
	t.Log("Invalid status filter correctly rejected")
}

// ----- Get AdminKey Tests -----

func TestGetAdminKey_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing successful admin key retrieval by super:admin")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("GET", "/api/v1/admin-keys/adm_caller", nil, identity)
	req.SetPathValue("id", "adm_caller")
	rec := httptest.NewRecorder()
	srv.handleGetAdminKey(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var key AdminKeyResponse
	if err := json.NewDecoder(rec.Body).Decode(&key); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if key.ID != "adm_caller" {
		t.Errorf("expected ID 'adm_caller', got %s", key.ID)
	}
	if key.Status != "active" {
		t.Errorf("expected status 'active', got %s", key.Status)
	}
	t.Log("Admin key retrieved successfully")
}

func TestGetAdminKey_NotFound(t *testing.T) {
	t.Parallel()
	t.Log("Testing 404 for non-existent admin key")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_caller", "op_caller", "active")

	identity := &dpop.Identity{
		KID:        "adm_caller",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("GET", "/api/v1/admin-keys/adm_nonexistent", nil, identity)
	req.SetPathValue("id", "adm_nonexistent")
	rec := httptest.NewRecorder()
	srv.handleGetAdminKey(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", rec.Code, rec.Body.String())
	}
	t.Log("Non-existent admin key correctly returns 404")
}

func TestGetAdminKey_TenantAdminForbidden(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin receives 403 for getting admin key details")

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_tenant_admin", "tadmin@test.com")
	addOperatorToTenant(t, s, "op_tenant_admin", "tenant1", "tenant:admin")
	createTestAdminKey(t, s, "adm_tadmin", "op_tenant_admin", "active")

	identity := &dpop.Identity{
		KID:        "adm_tadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenant_admin",
	}

	req := requestWithIdentity("GET", "/api/v1/admin-keys/adm_tadmin", nil, identity)
	req.SetPathValue("id", "adm_tadmin")
	rec := httptest.NewRecorder()
	srv.handleGetAdminKey(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", rec.Code, rec.Body.String())
	}
	t.Log("tenant:admin correctly receives 403")
}

func TestRevokeAdminKey_ConcurrentRaceCondition(t *testing.T) {
	t.Log("Testing TOCTOU race condition: concurrent revocations cannot leave zero super:admins")

	// Note: t.Parallel() deliberately omitted to control test timing

	s, srv, cleanup := setupAdminKeyTest(t)
	defer cleanup()

	// Setup: create tenant with exactly 2 super:admin keys
	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_super1", "super1@test.com")
	createTestOperator(t, s, "op_super2", "super2@test.com")
	addOperatorToTenant(t, s, "op_super1", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_super2", "tenant1", "super:admin")

	createTestAdminKey(t, s, "adm_super1", "op_super1", "active")
	createTestAdminKey(t, s, "adm_super2", "op_super2", "active")

	// Verify initial state: 2 active super:admin keys
	count, _ := s.CountActiveSuperAdminKeys()
	t.Logf("Initial super:admin key count: %d", count)
	if count != 2 {
		t.Fatalf("expected 2 super:admin keys, got %d", count)
	}

	// Prepare concurrent revocation requests
	// super1 tries to revoke super2's key, and super2 tries to revoke super1's key
	results := make(chan int, 2) // Collect HTTP status codes

	revoke := func(callerID, targetID string) {
		reqBody := RevokeAdminKeyRequest{Reason: "Concurrent test"}
		body, _ := json.Marshal(reqBody)

		identity := &dpop.Identity{
			KID:        callerID,
			CallerType: dpop.CallerTypeAdmin,
			Status:     dpop.IdentityStatusActive,
			OperatorID: "op_" + callerID[4:], // adm_super1 -> op_super1
		}

		req := requestWithIdentity("DELETE", "/api/v1/admin-keys/"+targetID, body, identity)
		req.SetPathValue("id", targetID)

		rec := httptest.NewRecorder()
		srv.handleRevokeAdminKey(rec, req)
		results <- rec.Code
	}

	// Launch concurrent revocations
	t.Log("Launching concurrent revocation requests...")
	go revoke("adm_super1", "adm_super2")
	go revoke("adm_super2", "adm_super1")

	// Collect results
	code1 := <-results
	code2 := <-results
	t.Logf("Response codes: %d, %d", code1, code2)

	// Exactly one should succeed (204), one should fail with conflict (409)
	successCount := 0
	conflictCount := 0
	for _, code := range []int{code1, code2} {
		switch code {
		case http.StatusNoContent:
			successCount++
		case http.StatusConflict:
			conflictCount++
		default:
			t.Errorf("unexpected status code: %d", code)
		}
	}

	if successCount != 1 || conflictCount != 1 {
		t.Errorf("expected exactly 1 success and 1 conflict, got %d successes and %d conflicts",
			successCount, conflictCount)
	}

	// Verify final state: exactly 1 active super:admin key remains
	finalCount, _ := s.CountActiveSuperAdminKeys()
	t.Logf("Final super:admin key count: %d", finalCount)
	if finalCount != 1 {
		t.Errorf("RACE CONDITION BUG: expected 1 super:admin key, got %d (lockout would occur if 0)", finalCount)
	}

	t.Log("TOCTOU race condition prevented: exactly 1 super:admin key remains")
}
