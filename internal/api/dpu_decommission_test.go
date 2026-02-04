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

// TestDecommissionDPU_RequiresReason tests that DPU decommissioning requires a reason.
func TestDecommissionDPU_RequiresReason(t *testing.T) {
	t.Log("Testing that DPU decommissioning requires a reason")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant and DPU")
	tenantID := "tenant_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	dpuID := "dpu_" + uuid.New().String()[:8]
	if err := server.store.Add(dpuID, "test-dpu", "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuID, tenantID); err != nil {
		t.Fatalf("failed to assign DPU to tenant: %v", err)
	}

	// Create an admin identity for auth
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "admin@acme.com", "Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "tenant:admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}
	adminKID := "adm_" + uuid.New().String()[:8]

	t.Log("Testing missing reason field returns 400")
	body := `{}`
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
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
	req = httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for empty reason, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Testing whitespace-only reason returns 400")
	body = `{"reason": "   "}`
	req = httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for whitespace-only reason, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Reason validation tests passed")
}

// TestDecommissionDPU_TenantAdminCanDecommissionOwnTenant tests that tenant:admin can decommission DPUs in own tenant.
func TestDecommissionDPU_TenantAdminCanDecommissionOwnTenant(t *testing.T) {
	t.Log("Testing that tenant:admin can decommission DPUs in own tenant")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant and DPU")
	tenantID := "tenant_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	dpuID := "dpu_" + uuid.New().String()[:8]
	if err := server.store.Add(dpuID, "test-dpu", "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuID, tenantID); err != nil {
		t.Fatalf("failed to assign DPU to tenant: %v", err)
	}

	t.Log("Creating tenant admin")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "admin@acme.com", "Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "tenant:admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}
	adminKID := "adm_" + uuid.New().String()[:8]

	t.Log("Decommissioning DPU as tenant admin")
	body := `{"reason": "Hardware removal"}`
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying response")
	var resp DecommissionDPUResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ID != dpuID {
		t.Errorf("expected ID %s, got %s", dpuID, resp.ID)
	}
	if resp.Status != "decommissioned" {
		t.Errorf("expected status 'decommissioned', got %s", resp.Status)
	}
	if resp.DecommissionedAt == "" {
		t.Error("expected decommissioned_at to be set")
	}

	t.Log("Verifying DPU status in store")
	dpu, err := server.store.Get(dpuID)
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.Status != "decommissioned" {
		t.Errorf("expected status 'decommissioned', got %s", dpu.Status)
	}

	t.Log("Tenant admin successfully decommissioned DPU")
}

// TestDecommissionDPU_TenantAdminCannotDecommissionOtherTenant tests that tenant:admin cannot decommission DPUs in other tenants.
func TestDecommissionDPU_TenantAdminCannotDecommissionOtherTenant(t *testing.T) {
	t.Log("Testing that tenant:admin cannot decommission DPUs in other tenants")

	server, mux := setupTestServer(t)

	t.Log("Creating two tenants")
	tenantA := "tenant_a_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantA, "Acme Corp", "Tenant A", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant A: %v", err)
	}

	tenantB := "tenant_b_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantB, "Beta Corp", "Tenant B", "admin@beta.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant B: %v", err)
	}

	t.Log("Creating DPU in tenant B")
	dpuID := "dpu_b_" + uuid.New().String()[:8]
	if err := server.store.Add(dpuID, "beta-dpu", "192.168.1.101", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuID, tenantB); err != nil {
		t.Fatalf("failed to assign DPU to tenant B: %v", err)
	}

	t.Log("Creating tenant admin for tenant A")
	operatorID := "op_a_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "admin@acme.com", "Admin A"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorID, tenantA, "tenant:admin"); err != nil {
		t.Fatalf("failed to add operator to tenant A: %v", err)
	}
	adminKID := "adm_a_" + uuid.New().String()[:8]

	t.Log("Tenant A admin attempting to decommission tenant B's DPU")
	body := `{"reason": "Trying to decommission"}`
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying DPU is still active")
	dpu, err := server.store.Get(dpuID)
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.Status == "decommissioned" {
		t.Error("DPU should not be decommissioned")
	}

	t.Log("Cross-tenant decommission correctly blocked")
}

// TestDecommissionDPU_SuperAdminCanDecommissionAny tests that super:admin can decommission any DPU.
func TestDecommissionDPU_SuperAdminCanDecommissionAny(t *testing.T) {
	t.Log("Testing that super:admin can decommission any DPU")

	server, mux := setupTestServer(t)

	t.Log("Creating two tenants")
	tenantA := "tenant_a_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantA, "Acme Corp", "Tenant A", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant A: %v", err)
	}

	tenantB := "tenant_b_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantB, "Beta Corp", "Tenant B", "admin@beta.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant B: %v", err)
	}

	t.Log("Creating super admin in tenant A")
	superAdminID := "op_super_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@acme.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenantA, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant: %v", err)
	}
	superKID := "adm_super_" + uuid.New().String()[:8]

	t.Log("Creating DPU in tenant B")
	dpuID := "dpu_b_" + uuid.New().String()[:8]
	if err := server.store.Add(dpuID, "beta-dpu", "192.168.1.101", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuID, tenantB); err != nil {
		t.Fatalf("failed to assign DPU to tenant B: %v", err)
	}

	t.Log("Super admin decommissioning DPU in different tenant")
	body := `{"reason": "Security incident response"}`
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
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
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying DPU is decommissioned")
	dpu, err := server.store.Get(dpuID)
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.Status != "decommissioned" {
		t.Errorf("expected status 'decommissioned', got %s", dpu.Status)
	}

	t.Log("Super admin successfully decommissioned DPU across tenants")
}

// TestDecommissionDPU_AlreadyDecommissionedReturns409 tests that decommissioning an already-decommissioned DPU returns 409.
func TestDecommissionDPU_AlreadyDecommissionedReturns409(t *testing.T) {
	t.Log("Testing that decommissioning an already-decommissioned DPU returns 409")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant and DPU")
	tenantID := "tenant_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	dpuID := "dpu_" + uuid.New().String()[:8]
	if err := server.store.Add(dpuID, "test-dpu", "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuID, tenantID); err != nil {
		t.Fatalf("failed to assign DPU to tenant: %v", err)
	}

	t.Log("Creating tenant admin")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "admin@acme.com", "Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "tenant:admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}
	adminKID := "adm_" + uuid.New().String()[:8]

	t.Log("First decommissioning should succeed")
	body := `{"reason": "First decommission"}`
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for first decommission, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("First decommissioning succeeded")

	t.Log("Second decommissioning should return 409")
	body = `{"reason": "Second attempt"}`
	req = httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx = dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409 for already decommissioned, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("Already decommissioned correctly returns 409")
}

// TestDecommissionDPU_NotFoundReturns404 tests that decommissioning a non-existent DPU returns 404.
func TestDecommissionDPU_NotFoundReturns404(t *testing.T) {
	t.Log("Testing that decommissioning a non-existent DPU returns 404")

	server, mux := setupTestServer(t)

	t.Log("Creating operator")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "admin@acme.com", "Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	// Make super admin so auth doesn't fail
	tenantID := "tenant_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme", "Test", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "super:admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}

	t.Log("Attempting to decommission non-existent DPU")
	body := `{"reason": "Should not work"}`
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/dpu_nonexistent", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "adm_test",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("Non-existent DPU correctly returns 404")
}

// TestDecommissionDPU_CredentialScrubbing tests that credential scrubbing works atomically.
func TestDecommissionDPU_CredentialScrubbing(t *testing.T) {
	t.Log("Testing that credential scrubbing works")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant and DPU")
	tenantID := "tenant_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	dpuName := "test-dpu-" + uuid.New().String()[:8]
	dpuID := "dpu_" + uuid.New().String()[:8]
	if err := server.store.Add(dpuID, dpuName, "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuID, tenantID); err != nil {
		t.Fatalf("failed to assign DPU to tenant: %v", err)
	}

	t.Log("Queuing credentials for the DPU")
	// Queue some credentials
	if err := server.store.QueueCredential(dpuName, "ssh-ca", "prod-ca", []byte("pubkey1")); err != nil {
		t.Fatalf("failed to queue credential 1: %v", err)
	}
	if err := server.store.QueueCredential(dpuName, "ssh-ca", "stage-ca", []byte("pubkey2")); err != nil {
		t.Fatalf("failed to queue credential 2: %v", err)
	}
	if err := server.store.QueueCredential(dpuName, "tls-cert", "api-cert", []byte("cert-data")); err != nil {
		t.Fatalf("failed to queue credential 3: %v", err)
	}

	// Verify credentials exist
	count, err := server.store.CountQueuedCredentials(dpuName)
	if err != nil {
		t.Fatalf("failed to count credentials: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 queued credentials, got %d", count)
	}
	t.Logf("Queued %d credentials for DPU", count)

	t.Log("Creating tenant admin")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "admin@acme.com", "Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "tenant:admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}
	adminKID := "adm_" + uuid.New().String()[:8]

	t.Log("Decommissioning DPU with scrub_credentials=true")
	body := `{"reason": "Hardware removal", "scrub_credentials": true}`
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying response includes credentials_scrubbed count")
	var resp DecommissionDPUResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.CredentialsScrubbed != 3 {
		t.Errorf("expected credentials_scrubbed=3, got %d", resp.CredentialsScrubbed)
	}

	t.Log("Verifying credentials are actually scrubbed")
	count, err = server.store.CountQueuedCredentials(dpuName)
	if err != nil {
		t.Fatalf("failed to count credentials: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 credentials after scrub, got %d", count)
	}

	t.Log("Credential scrubbing works correctly")
}

// TestDecommissionDPU_NoScrubByDefault tests that credentials are NOT scrubbed by default.
func TestDecommissionDPU_NoScrubByDefault(t *testing.T) {
	t.Log("Testing that credentials are NOT scrubbed by default")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant and DPU")
	tenantID := "tenant_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	dpuName := "test-dpu-" + uuid.New().String()[:8]
	dpuID := "dpu_" + uuid.New().String()[:8]
	if err := server.store.Add(dpuID, dpuName, "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuID, tenantID); err != nil {
		t.Fatalf("failed to assign DPU to tenant: %v", err)
	}

	t.Log("Queuing credentials for the DPU")
	if err := server.store.QueueCredential(dpuName, "ssh-ca", "prod-ca", []byte("pubkey1")); err != nil {
		t.Fatalf("failed to queue credential: %v", err)
	}
	if err := server.store.QueueCredential(dpuName, "ssh-ca", "stage-ca", []byte("pubkey2")); err != nil {
		t.Fatalf("failed to queue credential: %v", err)
	}

	t.Log("Creating tenant admin")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "admin@acme.com", "Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "tenant:admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}
	adminKID := "adm_" + uuid.New().String()[:8]

	t.Log("Decommissioning DPU WITHOUT scrub_credentials flag")
	body := `{"reason": "Hardware removal"}`
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying response has credentials_scrubbed=0")
	var resp DecommissionDPUResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.CredentialsScrubbed != 0 {
		t.Errorf("expected credentials_scrubbed=0, got %d", resp.CredentialsScrubbed)
	}

	t.Log("Verifying credentials are still present")
	count, err := server.store.CountQueuedCredentials(dpuName)
	if err != nil {
		t.Fatalf("failed to count credentials: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 credentials still present, got %d", count)
	}

	t.Log("Default behavior (no scrub) works correctly")
}

// TestDecommissionDPU_AuditEntry tests that decommissioning creates an audit log entry.
func TestDecommissionDPU_AuditEntry(t *testing.T) {
	t.Log("Testing that DPU decommissioning creates an audit log entry")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant and DPU")
	tenantID := "tenant_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	dpuID := "dpu_" + uuid.New().String()[:8]
	if err := server.store.Add(dpuID, "test-dpu", "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuID, tenantID); err != nil {
		t.Fatalf("failed to assign DPU to tenant: %v", err)
	}

	t.Log("Creating tenant admin")
	operatorID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "admin@acme.com", "Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "tenant:admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}
	adminKID := "adm_" + uuid.New().String()[:8]

	t.Log("Decommissioning DPU")
	body := `{"reason": "Audit test reason"}`
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        adminKID,
		CallerType: dpop.CallerTypeAdmin,
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
		Action: "dpu.decommission",
		Target: dpuID,
	})
	if err != nil {
		t.Fatalf("failed to query audit entries: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("dpu.decommission audit entry not found")
	}

	entry := entries[0]
	if entry.Decision != "allowed" {
		t.Errorf("expected decision 'allowed', got %s", entry.Decision)
	}
	if entry.Details["actor"] != adminKID {
		t.Errorf("expected actor %s, got %s", adminKID, entry.Details["actor"])
	}
	if entry.Details["reason"] != "Audit test reason" {
		t.Errorf("expected reason 'Audit test reason', got %s", entry.Details["reason"])
	}

	t.Log("Audit log entry verified")
}
