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

// setupSuspensionTest creates a test store with tenants and operators.
func setupSuspensionTest(t *testing.T) (*store.Store, *Server, func()) {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "suspension_test_*.db")
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

func TestSuspendOperator_SuperAdmin_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing successful operator suspension by super:admin")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	// Setup: create tenant, caller (super:admin), and target operator
	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	// Make suspension request
	reqBody := SuspendOperatorRequest{Reason: "Security investigation"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify operator is suspended
	op, err := s.GetOperator("op_target")
	if err != nil {
		t.Fatalf("failed to get operator: %v", err)
	}
	if op.Status != "suspended" {
		t.Errorf("expected status 'suspended', got %s", op.Status)
	}
	if op.SuspendedBy == nil || *op.SuspendedBy != "adm_superadmin" {
		t.Errorf("expected suspended_by 'adm_superadmin', got %v", op.SuspendedBy)
	}
	if op.SuspendedReason == nil || *op.SuspendedReason != "Security investigation" {
		t.Errorf("expected suspended_reason 'Security investigation', got %v", op.SuspendedReason)
	}
	if op.SuspendedAt == nil {
		t.Error("expected suspended_at to be set")
	}

	// Verify response includes suspension details
	var resp operatorResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Status != "suspended" {
		t.Errorf("response status should be 'suspended', got %s", resp.Status)
	}

	t.Log("Operator successfully suspended with audit tracking")
}

func TestSuspendOperator_TenantAdmin_SameTenant_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing successful operator suspension by tenant:admin in same tenant")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")

	reqBody := SuspendOperatorRequest{Reason: "Leave of absence"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	op, _ := s.GetOperator("op_target")
	if op.Status != "suspended" {
		t.Errorf("expected status 'suspended', got %s", op.Status)
	}

	t.Log("tenant:admin successfully suspended operator in same tenant")
}

func TestSuspendOperator_TenantAdmin_CrossTenant_Forbidden(t *testing.T) {
	t.Parallel()
	t.Log("Testing that tenant:admin cannot suspend operator in different tenant")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Tenant One")
	createTestTenant(t, s, "tenant2", "Tenant Two")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	addOperatorToTenant(t, s, "op_target", "tenant2", "operator") // Different tenant!
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")

	reqBody := SuspendOperatorRequest{Reason: "Attempted cross-tenant suspension"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify operator was NOT suspended
	op, _ := s.GetOperator("op_target")
	if op.Status == "suspended" {
		t.Error("operator should NOT have been suspended")
	}

	t.Log("Cross-tenant suspension correctly forbidden")
}

func TestSuspendOperator_RegularOperator_Forbidden(t *testing.T) {
	t.Parallel()
	t.Log("Testing that regular operator cannot suspend anyone")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_caller", "caller@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_caller", "tenant1", "operator") // Just operator, not admin
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")

	// Create a keymaker for the regular operator (not admin key)
	km := &store.KeyMaker{
		ID:         "km_caller",
		OperatorID: "op_caller",
		Name:       "test-keymaker",
		PublicKey:  "test-pubkey",
		Status:     "active",
		Kid:        "km_caller",
	}
	s.CreateKeyMaker(km)

	reqBody := SuspendOperatorRequest{Reason: "Unauthorized attempt"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "km_caller",
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_caller",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Regular operator correctly forbidden from suspending")
}

func TestSuspendOperator_EmptyReason(t *testing.T) {
	t.Parallel()
	t.Log("Testing that empty reason is rejected with 400")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	reqBody := SuspendOperatorRequest{Reason: ""}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "reason is required and cannot be empty" {
		t.Errorf("expected 'reason is required' error, got %s", resp["error"])
	}

	t.Log("Empty reason correctly rejected with 400")
}

func TestSuspendOperator_NotFound(t *testing.T) {
	t.Parallel()
	t.Log("Testing that non-existent operator returns 404")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	reqBody := SuspendOperatorRequest{Reason: "Test reason"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_nonexistent/suspend", body, identity)
	req.SetPathValue("id", "op_nonexistent")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Non-existent operator correctly returns 404")
}

func TestSuspendOperator_AlreadySuspended(t *testing.T) {
	t.Parallel()
	t.Log("Testing that already-suspended operator returns 409")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	// Pre-suspend the operator
	s.SuspendOperator("op_target", "adm_superadmin", "Already suspended")

	reqBody := SuspendOperatorRequest{Reason: "Double suspension attempt"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "operator is already suspended" {
		t.Errorf("expected 'already suspended' error, got %s", resp["error"])
	}

	t.Log("Already suspended operator correctly returns 409")
}

func TestUnsuspendOperator_SuperAdmin_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing successful operator unsuspension by super:admin")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	// Pre-suspend the operator
	s.SuspendOperator("op_target", "adm_superadmin", "Investigation")

	reqBody := UnsuspendOperatorRequest{Reason: "Investigation complete, cleared"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/unsuspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleUnsuspendOperator(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify operator is active
	op, err := s.GetOperator("op_target")
	if err != nil {
		t.Fatalf("failed to get operator: %v", err)
	}
	if op.Status != "active" {
		t.Errorf("expected status 'active', got %s", op.Status)
	}
	if op.SuspendedAt != nil {
		t.Error("expected suspended_at to be cleared")
	}
	if op.SuspendedBy != nil {
		t.Error("expected suspended_by to be cleared")
	}
	if op.SuspendedReason != nil {
		t.Error("expected suspended_reason to be cleared")
	}

	t.Log("Operator successfully unsuspended")
}

func TestUnsuspendOperator_TenantAdmin_SameTenant_Success(t *testing.T) {
	t.Parallel()
	t.Log("Testing successful operator unsuspension by tenant:admin in same tenant")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_tenantadmin", "tenantadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_tenantadmin", "tenant1", "tenant:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_tenantadmin", "op_tenantadmin", "active")

	// Pre-suspend the operator
	s.SuspendOperator("op_target", "adm_tenantadmin", "Investigation")

	reqBody := UnsuspendOperatorRequest{Reason: "False alarm"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_tenantadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tenantadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/unsuspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleUnsuspendOperator(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	op, _ := s.GetOperator("op_target")
	if op.Status != "active" {
		t.Errorf("expected status 'active', got %s", op.Status)
	}

	t.Log("tenant:admin successfully unsuspended operator in same tenant")
}

func TestUnsuspendOperator_NotSuspended(t *testing.T) {
	t.Parallel()
	t.Log("Testing that unsuspending non-suspended operator returns 409")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	// Operator is NOT suspended

	reqBody := UnsuspendOperatorRequest{Reason: "Unnecessary unsuspension"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/unsuspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleUnsuspendOperator(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "operator is not currently suspended" {
		t.Errorf("expected 'not currently suspended' error, got %s", resp["error"])
	}

	t.Log("Non-suspended operator correctly returns 409 for unsuspend")
}

func TestUnsuspendOperator_EmptyReason(t *testing.T) {
	t.Parallel()
	t.Log("Testing that empty reason for unsuspend is rejected with 400")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	// Suspend the operator
	s.SuspendOperator("op_target", "adm_superadmin", "Investigation")

	reqBody := UnsuspendOperatorRequest{Reason: ""}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/unsuspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleUnsuspendOperator(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Empty reason for unsuspend correctly rejected with 400")
}

func TestSuspendOperator_AuditLog(t *testing.T) {
	t.Parallel()
	t.Log("Testing that suspension creates audit log entry")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	reqBody := SuspendOperatorRequest{Reason: "Audit test reason"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify audit log entry
	entries, err := s.QueryAuditEntries(store.AuditFilter{Action: "operator.suspend", Limit: 1})
	if err != nil {
		t.Fatalf("failed to query audit entries: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 audit entry, got %d", len(entries))
	} else {
		entry := entries[0]
		if entry.Action != "operator.suspend" {
			t.Errorf("expected action 'operator.suspend', got %s", entry.Action)
		}
		if entry.Target != "op_target" {
			t.Errorf("expected target 'op_target', got %s", entry.Target)
		}
		if entry.Details["reason"] != "Audit test reason" {
			t.Errorf("expected reason in details, got %v", entry.Details)
		}
		if entry.Details["admin_id"] != "adm_superadmin" {
			t.Errorf("expected admin_id 'adm_superadmin', got %s", entry.Details["admin_id"])
		}
	}

	t.Log("Audit log entry correctly created for suspension")
}

func TestUnsuspendOperator_AuditLog(t *testing.T) {
	t.Parallel()
	t.Log("Testing that unsuspension creates audit log entry")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	// Suspend first
	s.SuspendOperator("op_target", "adm_superadmin", "Investigation")

	reqBody := UnsuspendOperatorRequest{Reason: "Cleared of suspicion"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/unsuspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleUnsuspendOperator(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify audit log entry
	entries, err := s.QueryAuditEntries(store.AuditFilter{Action: "operator.unsuspend", Limit: 1})
	if err != nil {
		t.Fatalf("failed to query audit entries: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 unsuspend audit entry, got %d", len(entries))
	} else {
		entry := entries[0]
		if entry.Action != "operator.unsuspend" {
			t.Errorf("expected action 'operator.unsuspend', got %s", entry.Action)
		}
		if entry.Details["reason"] != "Cleared of suspicion" {
			t.Errorf("expected reason 'Cleared of suspicion', got %s", entry.Details["reason"])
		}
	}

	t.Log("Audit log entry correctly created for unsuspension")
}

func TestSuspendOperator_Unauthenticated(t *testing.T) {
	t.Parallel()
	t.Log("Testing that unauthenticated request returns 401")

	_, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	reqBody := SuspendOperatorRequest{Reason: "Test reason"}
	body, _ := json.Marshal(reqBody)

	// No identity in context
	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, nil)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Unauthenticated request correctly rejected with 401")
}

func TestSuspendOperator_WhitespaceReason(t *testing.T) {
	t.Parallel()
	t.Log("Testing that whitespace-only reason is rejected")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Test Tenant")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin")
	addOperatorToTenant(t, s, "op_target", "tenant1", "operator")
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	reqBody := SuspendOperatorRequest{Reason: "   \t\n  "}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("Whitespace-only reason correctly rejected")
}

func TestSuspendOperator_SuperAdminCanSuspendAnyTenant(t *testing.T) {
	t.Parallel()
	t.Log("Testing that super:admin can suspend operator in any tenant")

	s, srv, cleanup := setupSuspensionTest(t)
	defer cleanup()

	createTestTenant(t, s, "tenant1", "Tenant One")
	createTestTenant(t, s, "tenant2", "Tenant Two")
	createTestOperator(t, s, "op_superadmin", "superadmin@test.com")
	createTestOperator(t, s, "op_target", "target@test.com")
	addOperatorToTenant(t, s, "op_superadmin", "tenant1", "super:admin") // Super admin in tenant1
	addOperatorToTenant(t, s, "op_target", "tenant2", "operator")       // Target in tenant2
	createTestAdminKey(t, s, "adm_superadmin", "op_superadmin", "active")

	reqBody := SuspendOperatorRequest{Reason: "Cross-tenant suspension by super:admin"}
	body, _ := json.Marshal(reqBody)

	identity := &dpop.Identity{
		KID:        "adm_superadmin",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_superadmin",
	}

	req := requestWithIdentity("POST", "/api/v1/operators/op_target/suspend", body, identity)
	req.SetPathValue("id", "op_target")

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	op, _ := s.GetOperator("op_target")
	if op.Status != "suspended" {
		t.Errorf("expected status 'suspended', got %s", op.Status)
	}

	t.Log("super:admin successfully suspended operator in different tenant")
}
