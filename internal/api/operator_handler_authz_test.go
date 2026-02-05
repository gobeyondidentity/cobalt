package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// setupOperatorAuthzTest creates a test store with tenants and operators for authorization tests.
func setupOperatorAuthzTest(t *testing.T) (*store.Store, *Server, func()) {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "operator_authz_test_*.db")
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

// ----- handleGetOperator Authorization Tests -----

func TestGetOperator_SuperAdmin_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing that super:admin can view any operator")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Tenant One")
	createTestTenant(t, s, "tenant2", "Tenant Two")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant2", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("GET", "/api/v1/operators/target@test.com", nil, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleGetOperator(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("super:admin successfully viewed operator in different tenant")
}

func TestGetOperator_TenantAdmin_SameTenant_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin can view operator in same tenant")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("GET", "/api/v1/operators/target@test.com", nil, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleGetOperator(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("tenant:admin successfully viewed operator in same tenant")
}

func TestGetOperator_TenantAdmin_CrossTenant_Forbidden(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin cannot view operator in different tenant")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Tenant One")
	createTestTenant(t, s, "tenant2", "Tenant Two")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	addOperatorToTenant(t, s, "op_target", "tenant2", "operator") // Different tenant!
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("GET", "/api/v1/operators/target@test.com", nil, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleGetOperator(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Cross-tenant operator view correctly forbidden")
}

func TestGetOperator_Unauthenticated(t *testing.T) {
	t.Parallel()
	t.Log("Testing that unauthenticated request returns 401")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")

	// No identity
	req := requestWithIdentity("GET", "/api/v1/operators/target@test.com", nil, nil)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleGetOperator(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Unauthenticated request correctly rejected with 401")
}

// ----- handleUpdateOperatorStatus Authorization Tests -----

func TestUpdateOperatorStatus_SuperAdmin_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing that super:admin can update operator status in any tenant")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Tenant One")
	createTestTenant(t, s, "tenant2", "Tenant Two")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant2", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	body, _ := json.Marshal(updateOperatorStatusRequest{Status: "suspended"})

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("PATCH", "/api/v1/operators/target@test.com/status", body, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleUpdateOperatorStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify status changed
	op, _ := s.GetOperator("op_target")
	if op.Status != "suspended" {
		t.Errorf("expected status 'suspended', got %s", op.Status)
	}

	t.Log("super:admin successfully updated operator status in different tenant")
}

func TestUpdateOperatorStatus_TenantAdmin_SameTenant_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin can update operator status in same tenant")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")

	body, _ := json.Marshal(updateOperatorStatusRequest{Status: "suspended"})

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("PATCH", "/api/v1/operators/target@test.com/status", body, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleUpdateOperatorStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify status changed
	op, _ := s.GetOperator("op_target")
	if op.Status != "suspended" {
		t.Errorf("expected status 'suspended', got %s", op.Status)
	}

	t.Log("tenant:admin successfully updated operator status in same tenant")
}

func TestUpdateOperatorStatus_TenantAdmin_CrossTenant_Forbidden(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin cannot update operator status in different tenant")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Tenant One")
	createTestTenant(t, s, "tenant2", "Tenant Two")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	addOperatorToTenant(t, s, "op_target", "tenant2", "operator") // Different tenant!
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")

	body, _ := json.Marshal(updateOperatorStatusRequest{Status: "suspended"})

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("PATCH", "/api/v1/operators/target@test.com/status", body, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleUpdateOperatorStatus(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify status NOT changed
	op, _ := s.GetOperator("op_target")
	if op.Status == "suspended" {
		t.Error("operator status should NOT have been changed")
	}

	t.Log("Cross-tenant status update correctly forbidden")
}

func TestUpdateOperatorStatus_Unauthenticated(t *testing.T) {
	t.Parallel()
	t.Log("Testing that unauthenticated request returns 401")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")

	body, _ := json.Marshal(updateOperatorStatusRequest{Status: "suspended"})

	// No identity
	req := requestWithIdentity("PATCH", "/api/v1/operators/target@test.com/status", body, nil)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleUpdateOperatorStatus(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Unauthenticated request correctly rejected with 401")
}

// ----- handleDeleteOperator Authorization Tests -----

func TestDeleteOperator_SuperAdmin_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing that super:admin can delete operator in any tenant")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Tenant One")
	createTestTenant(t, s, "tenant2", "Tenant Two")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant2", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("DELETE", "/api/v1/operators/target@test.com", nil, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleDeleteOperator(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify operator deleted
	_, err := s.GetOperator("op_target")
	if err == nil {
		t.Error("expected operator to be deleted")
	}

	t.Log("super:admin successfully deleted operator in different tenant")
}

func TestDeleteOperator_TenantAdmin_SameTenant_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin can delete operator in same tenant")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("DELETE", "/api/v1/operators/target@test.com", nil, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleDeleteOperator(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify operator deleted
	_, err := s.GetOperator("op_target")
	if err == nil {
		t.Error("expected operator to be deleted")
	}

	t.Log("tenant:admin successfully deleted operator in same tenant")
}

func TestDeleteOperator_TenantAdmin_CrossTenant_Forbidden(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin cannot delete operator in different tenant")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Tenant One")
	createTestTenant(t, s, "tenant2", "Tenant Two")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	addOperatorToTenant(t, s, "op_target", "tenant2", "operator") // Different tenant!
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("DELETE", "/api/v1/operators/target@test.com", nil, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleDeleteOperator(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify operator NOT deleted
	_, err := s.GetOperator("op_target")
	if err != nil {
		t.Error("operator should NOT have been deleted")
	}

	t.Log("Cross-tenant operator deletion correctly forbidden")
}

func TestDeleteOperator_Unauthenticated(t *testing.T) {
	t.Parallel()
	t.Log("Testing that unauthenticated request returns 401")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")

	// No identity
	req := requestWithIdentity("DELETE", "/api/v1/operators/target@test.com", nil, nil)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleDeleteOperator(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Unauthenticated request correctly rejected with 401")
}

// ----- Regular Operator Cannot Access -----

func TestGetOperator_RegularOperator_Forbidden(t *testing.T) {
	t.Parallel()
	t.Log("Testing that regular operator cannot view other operators")

	s, srv, cleanup := setupOperatorAuthzTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "operator") // Just operator, not admin
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")

	km := &store.KeyMaker{
		ID:         "km_caller",
		OperatorID: "op_caller",
		Name:       "test-keymaker",
		PublicKey:  "test-pubkey",
		Status:     "active",
		Kid:        "km_caller",
	}
	s.CreateKeyMaker(km)

	identity := &dpop.Identity{
		KID:        "km_caller",
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("GET", "/api/v1/operators/target@test.com", nil, identity)
	req.SetPathValue("email", "target@test.com")

	rec := httptest.NewRecorder()
	srv.handleGetOperator(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Regular operator correctly forbidden from viewing other operators")
}
