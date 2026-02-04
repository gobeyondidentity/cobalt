package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// TestRevokeKeyMaker_RequiresReason tests that a reason is required for revocation.
func TestRevokeKeyMaker_RequiresReason(t *testing.T) {
	t.Log("Testing that KeyMaker revocation requires a reason")

	server, mux := setupTestServer(t)

	t.Log("Creating operator and KeyMaker")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	keymakerID := "km_" + uuid.New().String()[:8]
	km := &store.KeyMaker{
		ID:                keymakerID,
		OperatorID:        operatorID,
		Name:              "test-keymaker",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp123",
		PublicKey:         "ssh-ed25519 AAAA...",
		Status:            "active",
		Kid:               keymakerID,
		KeyFingerprint:    "fingerprint-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(km); err != nil {
		t.Fatalf("failed to create keymaker: %v", err)
	}

	t.Log("Testing missing reason field returns 400")
	body := `{}`
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	// Inject identity for the operator who owns this KeyMaker
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        keymakerID,
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for missing reason, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Testing empty reason field returns 400")
	body = `{"reason": ""}`
	req = httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for empty reason, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Testing whitespace-only reason returns 400")
	body = `{"reason": "   "}`
	req = httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for whitespace reason, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("Reason validation tests passed")
}

// TestRevokeKeyMaker_OperatorCanRevokeSelf tests that an operator can revoke their own KeyMaker.
func TestRevokeKeyMaker_OperatorCanRevokeSelf(t *testing.T) {
	t.Log("Testing that an operator can revoke their own KeyMaker")

	server, mux := setupTestServer(t)

	t.Log("Creating operator and KeyMaker")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	keymakerID := "km_" + uuid.New().String()[:8]
	km := &store.KeyMaker{
		ID:                keymakerID,
		OperatorID:        operatorID,
		Name:              "test-keymaker",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp123",
		PublicKey:         "ssh-ed25519 AAAA...",
		Status:            "active",
		Kid:               keymakerID,
		KeyFingerprint:    "fingerprint-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(km); err != nil {
		t.Fatalf("failed to create keymaker: %v", err)
	}

	t.Log("Revoking own KeyMaker with valid reason")
	body := `{"reason": "Device lost"}`
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	// Inject identity for the operator who owns this KeyMaker
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        keymakerID,
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for self-revocation, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying response contains revocation details")
	var resp RevokeKeyMakerResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ID != keymakerID {
		t.Errorf("expected id %s, got %s", keymakerID, resp.ID)
	}
	if resp.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %s", resp.Status)
	}
	if resp.RevokedReason != "Device lost" {
		t.Errorf("expected reason 'Device lost', got %s", resp.RevokedReason)
	}
	if resp.RevokedBy != keymakerID {
		t.Errorf("expected revoked_by to be actor, got %s", resp.RevokedBy)
	}
	if resp.RevokedAt == "" {
		t.Error("expected revoked_at to be set")
	}
	t.Log("Self-revocation successful with correct response")

	t.Log("Verifying KeyMaker status persisted in store")
	updatedKM, err := server.store.GetKeyMaker(keymakerID)
	if err != nil {
		t.Fatalf("failed to get keymaker: %v", err)
	}
	if updatedKM.Status != "revoked" {
		t.Errorf("expected status 'revoked' in store, got %s", updatedKM.Status)
	}
	if updatedKM.RevokedReason == nil || *updatedKM.RevokedReason != "Device lost" {
		t.Errorf("expected reason 'Device lost' in store")
	}
}

// TestRevokeKeyMaker_OperatorCannotRevokeOthers tests that an operator cannot revoke others' KeyMakers.
func TestRevokeKeyMaker_OperatorCannotRevokeOthers(t *testing.T) {
	t.Log("Testing that an operator cannot revoke another operator's KeyMaker")

	server, mux := setupTestServer(t)

	t.Log("Creating two operators")
	operatorAID := "op_a_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorAID, "operatorA@acme.com", "Operator A"); err != nil {
		t.Fatalf("failed to create operator A: %v", err)
	}

	operatorBID := "op_b_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorBID, "operatorB@acme.com", "Operator B"); err != nil {
		t.Fatalf("failed to create operator B: %v", err)
	}

	t.Log("Creating KeyMaker for operator B")
	keymakerBID := "km_b_" + uuid.New().String()[:8]
	kmB := &store.KeyMaker{
		ID:                keymakerBID,
		OperatorID:        operatorBID,
		Name:              "operator-b-keymaker",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp123",
		PublicKey:         "ssh-ed25519 AAAA...",
		Status:            "active",
		Kid:               keymakerBID,
		KeyFingerprint:    "fingerprint-b-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(kmB); err != nil {
		t.Fatalf("failed to create keymaker B: %v", err)
	}

	t.Log("Operator A attempting to revoke operator B's KeyMaker")
	keymakerAID := "km_a_" + uuid.New().String()[:8]
	body := `{"reason": "Trying to revoke someone else's device"}`
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerBID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	// Inject identity for operator A
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        keymakerAID,
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorAID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for unauthorized revocation, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying KeyMaker is still active")
	km, err := server.store.GetKeyMaker(keymakerBID)
	if err != nil {
		t.Fatalf("failed to get keymaker: %v", err)
	}
	if km.Status != "active" {
		t.Errorf("expected status 'active', got %s", km.Status)
	}
	t.Log("Operator correctly denied from revoking others' KeyMakers")
}

// TestRevokeKeyMaker_TenantAdminCanRevokeInTenant tests that a tenant admin can revoke KeyMakers in their tenant.
func TestRevokeKeyMaker_TenantAdminCanRevokeInTenant(t *testing.T) {
	t.Log("Testing that a tenant:admin can revoke KeyMakers in their tenant")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant")
	tenantID := "tnt_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	t.Log("Creating tenant admin operator")
	adminID := "op_admin_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(adminID, "admin@acme.com", "Tenant Admin"); err != nil {
		t.Fatalf("failed to create admin operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(adminID, tenantID, "tenant:admin"); err != nil {
		t.Fatalf("failed to add admin to tenant: %v", err)
	}

	t.Log("Creating regular operator in same tenant")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "user@acme.com", "Regular Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "operator"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}

	t.Log("Creating KeyMaker for regular operator")
	keymakerID := "km_" + uuid.New().String()[:8]
	km := &store.KeyMaker{
		ID:                keymakerID,
		OperatorID:        operatorID,
		Name:              "user-keymaker",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp123",
		PublicKey:         "ssh-ed25519 AAAA...",
		Status:            "active",
		Kid:               keymakerID,
		KeyFingerprint:    "fingerprint-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(km); err != nil {
		t.Fatalf("failed to create keymaker: %v", err)
	}

	t.Log("Tenant admin revoking operator's KeyMaker")
	adminKID := "adm_" + uuid.New().String()[:8]
	body := `{"reason": "Operator terminated"}`
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	// Inject identity for admin
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: adminID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for tenant admin revocation, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying KeyMaker is revoked")
	revokedKM, err := server.store.GetKeyMaker(keymakerID)
	if err != nil {
		t.Fatalf("failed to get keymaker: %v", err)
	}
	if revokedKM.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %s", revokedKM.Status)
	}
	t.Log("Tenant admin successfully revoked operator's KeyMaker")
}

// TestRevokeKeyMaker_TenantAdminCannotRevokeOtherTenant tests that a tenant admin cannot revoke KeyMakers in other tenants.
func TestRevokeKeyMaker_TenantAdminCannotRevokeOtherTenant(t *testing.T) {
	t.Log("Testing that a tenant:admin cannot revoke KeyMakers in another tenant")

	server, mux := setupTestServer(t)

	t.Log("Creating two tenants")
	tenantAID := "tnt_a_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantAID, "Acme Corp", "Tenant A", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant A: %v", err)
	}

	tenantBID := "tnt_b_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantBID, "Beta Inc", "Tenant B", "admin@beta.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant B: %v", err)
	}

	t.Log("Creating tenant admin for tenant A")
	adminAID := "op_admin_a_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(adminAID, "admin@acme.com", "Acme Admin"); err != nil {
		t.Fatalf("failed to create admin A: %v", err)
	}
	if err := server.store.AddOperatorToTenant(adminAID, tenantAID, "tenant:admin"); err != nil {
		t.Fatalf("failed to add admin A to tenant: %v", err)
	}

	t.Log("Creating operator in tenant B")
	operatorBID := "op_b_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorBID, "user@beta.com", "Beta User"); err != nil {
		t.Fatalf("failed to create operator B: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorBID, tenantBID, "operator"); err != nil {
		t.Fatalf("failed to add operator B to tenant: %v", err)
	}

	t.Log("Creating KeyMaker for operator in tenant B")
	keymakerBID := "km_b_" + uuid.New().String()[:8]
	kmB := &store.KeyMaker{
		ID:                keymakerBID,
		OperatorID:        operatorBID,
		Name:              "beta-user-keymaker",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp123",
		PublicKey:         "ssh-ed25519 AAAA...",
		Status:            "active",
		Kid:               keymakerBID,
		KeyFingerprint:    "fingerprint-b-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(kmB); err != nil {
		t.Fatalf("failed to create keymaker B: %v", err)
	}

	t.Log("Tenant A admin attempting to revoke tenant B's KeyMaker")
	adminKID := "adm_a_" + uuid.New().String()[:8]
	body := `{"reason": "Cross-tenant attack attempt"}`
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerBID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	// Inject identity for admin A
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: adminAID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for cross-tenant revocation, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying KeyMaker is still active")
	km, err := server.store.GetKeyMaker(keymakerBID)
	if err != nil {
		t.Fatalf("failed to get keymaker: %v", err)
	}
	if km.Status != "active" {
		t.Errorf("expected status 'active', got %s", km.Status)
	}
	t.Log("Tenant admin correctly denied from revoking other tenant's KeyMakers")
}

// TestRevokeKeyMaker_SuperAdminCanRevokeAny tests that a super admin can revoke any KeyMaker.
func TestRevokeKeyMaker_SuperAdminCanRevokeAny(t *testing.T) {
	t.Log("Testing that a super:admin can revoke any KeyMaker")

	server, mux := setupTestServer(t)

	t.Log("Creating tenants")
	tenantAID := "tnt_a_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantAID, "Acme Corp", "Tenant A", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant A: %v", err)
	}

	tenantBID := "tnt_b_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantBID, "Beta Inc", "Tenant B", "admin@beta.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant B: %v", err)
	}

	t.Log("Creating super admin in tenant A")
	superAdminID := "op_super_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@global.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenantAID, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant: %v", err)
	}

	t.Log("Creating operator in tenant B")
	operatorBID := "op_b_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorBID, "user@beta.com", "Beta User"); err != nil {
		t.Fatalf("failed to create operator B: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorBID, tenantBID, "operator"); err != nil {
		t.Fatalf("failed to add operator B to tenant: %v", err)
	}

	t.Log("Creating KeyMaker for operator in tenant B")
	keymakerBID := "km_b_" + uuid.New().String()[:8]
	kmB := &store.KeyMaker{
		ID:                keymakerBID,
		OperatorID:        operatorBID,
		Name:              "beta-user-keymaker",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp123",
		PublicKey:         "ssh-ed25519 AAAA...",
		Status:            "active",
		Kid:               keymakerBID,
		KeyFingerprint:    "fingerprint-b-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(kmB); err != nil {
		t.Fatalf("failed to create keymaker B: %v", err)
	}

	t.Log("Super admin revoking KeyMaker in different tenant")
	superKID := "adm_super_" + uuid.New().String()[:8]
	body := `{"reason": "Security investigation"}`
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerBID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	// Inject identity for super admin
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        superKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: superAdminID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for super admin revocation, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying KeyMaker is revoked")
	revokedKM, err := server.store.GetKeyMaker(keymakerBID)
	if err != nil {
		t.Fatalf("failed to get keymaker: %v", err)
	}
	if revokedKM.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %s", revokedKM.Status)
	}
	t.Log("Super admin successfully revoked KeyMaker across tenants")
}

// TestRevokeKeyMaker_AlreadyRevokedReturns409 tests that revoking an already-revoked KeyMaker returns 409.
func TestRevokeKeyMaker_AlreadyRevokedReturns409(t *testing.T) {
	t.Log("Testing that revoking an already-revoked KeyMaker returns 409")

	server, mux := setupTestServer(t)

	t.Log("Creating operator and KeyMaker")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	keymakerID := "km_" + uuid.New().String()[:8]
	km := &store.KeyMaker{
		ID:                keymakerID,
		OperatorID:        operatorID,
		Name:              "test-keymaker",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp123",
		PublicKey:         "ssh-ed25519 AAAA...",
		Status:            "active",
		Kid:               keymakerID,
		KeyFingerprint:    "fingerprint-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(km); err != nil {
		t.Fatalf("failed to create keymaker: %v", err)
	}

	t.Log("First revocation should succeed")
	body := `{"reason": "Device lost"}`
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        keymakerID,
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for first revocation, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("First revocation succeeded")

	t.Log("Second revocation should return 409")
	body = `{"reason": "Trying again"}`
	req = httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409 for already revoked, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("Already revoked correctly returns 409")
}

// TestRevokeKeyMaker_NotFoundReturns404 tests that revoking a non-existent KeyMaker returns 404.
func TestRevokeKeyMaker_NotFoundReturns404(t *testing.T) {
	t.Log("Testing that revoking a non-existent KeyMaker returns 404")

	server, mux := setupTestServer(t)

	t.Log("Creating operator")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	t.Log("Attempting to revoke non-existent KeyMaker")
	body := `{"reason": "Should not work"}`
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/km_nonexistent", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_test",
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404 for non-existent KeyMaker, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("Non-existent KeyMaker correctly returns 404")
}

// TestRevokeKeyMaker_AuditEntry tests that revocation creates an audit log entry.
func TestRevokeKeyMaker_AuditEntry(t *testing.T) {
	t.Log("Testing that KeyMaker revocation creates an audit log entry")

	server, mux := setupTestServer(t)

	t.Log("Creating operator and KeyMaker")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	keymakerID := "km_" + uuid.New().String()[:8]
	km := &store.KeyMaker{
		ID:                keymakerID,
		OperatorID:        operatorID,
		Name:              "test-keymaker",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp123",
		PublicKey:         "ssh-ed25519 AAAA...",
		Status:            "active",
		Kid:               keymakerID,
		KeyFingerprint:    "fingerprint-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(km); err != nil {
		t.Fatalf("failed to create keymaker: %v", err)
	}

	t.Log("Revoking KeyMaker")
	body := `{"reason": "Audit test reason"}`
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        keymakerID,
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying audit log entry was created")
	entries, err := server.store.QueryAuditEntries(store.AuditFilter{
		Action: "keymaker.revoke",
		Target: keymakerID,
	})
	if err != nil {
		t.Fatalf("failed to query audit entries: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("keymaker.revoke audit entry not found")
	}

	entry := entries[0]
	if entry.Decision != "allowed" {
		t.Errorf("expected decision 'allowed', got %s", entry.Decision)
	}
	if entry.Details["actor"] != keymakerID {
		t.Errorf("expected actor %s, got %s", keymakerID, entry.Details["actor"])
	}
	if entry.Details["reason"] != "Audit test reason" {
		t.Errorf("expected reason 'Audit test reason', got %s", entry.Details["reason"])
	}
	t.Log("Audit log entry verified")
}
