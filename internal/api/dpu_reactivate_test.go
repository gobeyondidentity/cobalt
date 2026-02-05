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

// TestReactivateDPU_SuperAdminCanReactivate tests that super:admin can reactivate a decommissioned DPU.
func TestReactivateDPU_SuperAdminCanReactivate(t *testing.T) {
	t.Log("Testing that super:admin can reactivate a decommissioned DPU")

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

	t.Log("Creating super admin")
	superAdminID := "op_super_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@acme.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenantID, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant: %v", err)
	}
	superKID := "adm_super_" + uuid.New().String()[:8]

	t.Log("Decommissioning the DPU first")
	_, err := server.store.DecommissionDPUAtomic(dpuID, superKID, "Test decommission")
	if err != nil {
		t.Fatalf("failed to decommission DPU: %v", err)
	}

	t.Log("Verifying DPU is decommissioned")
	dpu, err := server.store.Get(dpuID)
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.Status != "decommissioned" {
		t.Fatalf("expected status 'decommissioned', got %s", dpu.Status)
	}

	t.Log("Reactivating DPU as super admin")
	body := `{"reason": "Hardware returned from RMA repair"}`
	req := httptest.NewRequest("POST", "/api/v1/dpus/"+dpuID+"/reactivate", bytes.NewReader([]byte(body)))
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

	t.Log("Verifying response")
	var resp ReactivateDPUResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ID != dpuID {
		t.Errorf("expected ID %s, got %s", dpuID, resp.ID)
	}
	if resp.Status != "pending" {
		t.Errorf("expected status 'pending', got %s", resp.Status)
	}
	if resp.ReactivatedAt == "" {
		t.Error("expected reactivated_at to be set")
	}
	if resp.ReactivatedBy != superKID {
		t.Errorf("expected reactivated_by %s, got %s", superKID, resp.ReactivatedBy)
	}
	if resp.EnrollmentExpiresAt == "" {
		t.Error("expected enrollment_expires_at to be set")
	}

	t.Log("Verifying DPU status in store")
	dpu, err = server.store.Get(dpuID)
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.Status != "pending" {
		t.Errorf("expected status 'pending', got %s", dpu.Status)
	}
	if dpu.EnrollmentExpiresAt == nil {
		t.Error("expected enrollment_expires_at to be set")
	}
	if dpu.DecommissionedAt != nil {
		t.Error("expected decommissioned_at to be cleared")
	}
	if dpu.DecommissionedBy != nil {
		t.Error("expected decommissioned_by to be cleared")
	}
	if dpu.DecommissionedReason != nil {
		t.Error("expected decommissioned_reason to be cleared")
	}
	if dpu.PublicKey != nil {
		t.Error("expected public_key to be cleared")
	}
	if dpu.Kid != nil {
		t.Error("expected kid to be cleared")
	}
	if dpu.KeyFingerprint != nil {
		t.Error("expected key_fingerprint to be cleared")
	}

	t.Log("Super admin successfully reactivated DPU")
}

// TestReactivateDPU_TenantAdminForbidden tests that tenant:admin cannot reactivate DPUs (LC-5).
func TestReactivateDPU_TenantAdminForbidden(t *testing.T) {
	t.Log("Testing that tenant:admin cannot reactivate DPUs (LC-5)")

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

	t.Log("Creating super admin to decommission, then tenant admin to attempt reactivation")
	// Need super admin to decommission
	superAdminID := "op_super_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@acme.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenantID, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant: %v", err)
	}

	// Decommission the DPU
	_, err := server.store.DecommissionDPUAtomic(dpuID, "adm_super", "Test decommission")
	if err != nil {
		t.Fatalf("failed to decommission DPU: %v", err)
	}

	t.Log("Creating tenant admin")
	tenantAdminID := "op_tenant_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(tenantAdminID, "admin@acme.com", "Tenant Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(tenantAdminID, tenantID, "tenant:admin"); err != nil {
		t.Fatalf("failed to add tenant admin to tenant: %v", err)
	}
	tenantKID := "adm_tenant_" + uuid.New().String()[:8]

	t.Log("Tenant admin attempting to reactivate DPU")
	body := `{"reason": "Hardware returned from RMA repair"}`
	req := httptest.NewRequest("POST", "/api/v1/dpus/"+dpuID+"/reactivate", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        tenantKID,
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: tenantAdminID,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying DPU remains decommissioned")
	dpu, err := server.store.Get(dpuID)
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.Status != "decommissioned" {
		t.Errorf("expected status 'decommissioned', got %s", dpu.Status)
	}

	t.Log("Tenant admin correctly blocked from reactivating DPU (LC-5)")
}

// TestReactivateDPU_ReasonMinLength tests that reason must be at least 20 characters.
func TestReactivateDPU_ReasonMinLength(t *testing.T) {
	t.Log("Testing that reactivation reason must be at least 20 characters")

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

	t.Log("Creating super admin")
	superAdminID := "op_super_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@acme.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenantID, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant: %v", err)
	}
	superKID := "adm_super_" + uuid.New().String()[:8]

	// Decommission the DPU
	_, err := server.store.DecommissionDPUAtomic(dpuID, superKID, "Test decommission")
	if err != nil {
		t.Fatalf("failed to decommission DPU: %v", err)
	}

	testCases := []struct {
		name   string
		reason string
	}{
		{"empty reason", ""},
		{"too short (5 chars)", "short"},
		{"too short (19 chars)", "nineteen char rson"},
		{"whitespace only", "                   "},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing reason: %q", tc.reason)
			body, _ := json.Marshal(ReactivateDPURequest{Reason: tc.reason})
			req := httptest.NewRequest("POST", "/api/v1/dpus/"+dpuID+"/reactivate", bytes.NewReader(body))
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

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected status 400 for %s, got %d: %s", tc.name, w.Code, w.Body.String())
			}
		})
	}

	t.Log("Testing exactly 20 chars should succeed")
	body := `{"reason": "exactly twenty chars!"}`
	req := httptest.NewRequest("POST", "/api/v1/dpus/"+dpuID+"/reactivate", bytes.NewReader([]byte(body)))
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
		t.Errorf("expected status 200 for 20-char reason, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Reason minimum length validation passed")
}

// TestReactivateDPU_NotDecommissionedReturns409 tests that reactivating an active DPU returns 409.
func TestReactivateDPU_NotDecommissionedReturns409(t *testing.T) {
	t.Log("Testing that reactivating an active DPU returns 409")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant and DPU (not decommissioned)")
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

	t.Log("Creating super admin")
	superAdminID := "op_super_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@acme.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenantID, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant: %v", err)
	}
	superKID := "adm_super_" + uuid.New().String()[:8]

	t.Log("Attempting to reactivate active DPU")
	body := `{"reason": "Hardware returned from RMA repair"}`
	req := httptest.NewRequest("POST", "/api/v1/dpus/"+dpuID+"/reactivate", bytes.NewReader([]byte(body)))
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

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409 for active DPU, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Active DPU correctly returns 409")
}

// TestReactivateDPU_NotFoundReturns404 tests that reactivating a non-existent DPU returns 404.
func TestReactivateDPU_NotFoundReturns404(t *testing.T) {
	t.Log("Testing that reactivating a non-existent DPU returns 404")

	server, mux := setupTestServer(t)

	t.Log("Creating super admin")
	tenantID := "tenant_" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	superAdminID := "op_super_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@acme.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenantID, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant: %v", err)
	}
	superKID := "adm_super_" + uuid.New().String()[:8]

	t.Log("Attempting to reactivate non-existent DPU")
	body := `{"reason": "Hardware returned from RMA repair"}`
	req := httptest.NewRequest("POST", "/api/v1/dpus/dpu_nonexistent/reactivate", bytes.NewReader([]byte(body)))
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

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Non-existent DPU correctly returns 404")
}

// TestReactivateDPU_AuditEntry tests that reactivation creates an audit log entry.
func TestReactivateDPU_AuditEntry(t *testing.T) {
	t.Log("Testing that DPU reactivation creates an audit log entry")

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

	t.Log("Creating super admin")
	superAdminID := "op_super_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@acme.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenantID, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant: %v", err)
	}
	superKID := "adm_super_" + uuid.New().String()[:8]

	// Decommission the DPU first
	_, err := server.store.DecommissionDPUAtomic(dpuID, superKID, "Test decommission")
	if err != nil {
		t.Fatalf("failed to decommission DPU: %v", err)
	}

	t.Log("Reactivating DPU")
	reason := "Hardware returned from RMA repair facility"
	body, _ := json.Marshal(ReactivateDPURequest{Reason: reason})
	req := httptest.NewRequest("POST", "/api/v1/dpus/"+dpuID+"/reactivate", bytes.NewReader(body))
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

	t.Log("Verifying audit log entry was created")
	entries, err := server.store.QueryAuditEntries(store.AuditFilter{
		Action: "dpu.reactivate",
		Target: dpuID,
	})
	if err != nil {
		t.Fatalf("failed to query audit entries: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("dpu.reactivate audit entry not found")
	}

	entry := entries[0]
	if entry.Decision != "allowed" {
		t.Errorf("expected decision 'allowed', got %s", entry.Decision)
	}
	if entry.Details["actor"] != superKID {
		t.Errorf("expected actor %s, got %s", superKID, entry.Details["actor"])
	}
	if entry.Details["reason"] != reason {
		t.Errorf("expected reason %q, got %s", reason, entry.Details["reason"])
	}
	if entry.Details["severity"] != "high" {
		t.Errorf("expected severity 'high', got %s", entry.Details["severity"])
	}

	t.Log("Audit log entry verified with high severity")
}

// TestReactivateDPU_ClearsCredentials tests that reactivation clears old public key and key fingerprint.
func TestReactivateDPU_ClearsCredentials(t *testing.T) {
	t.Log("Testing that reactivation clears old public key and key fingerprint")

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

	t.Log("Simulating DPU enrollment by setting public key")
	// Update DPU with public key as if enrolled
	err := server.store.UpdateDPUEnrollment(dpuID, []byte("fake-public-key"), "abc123fingerprint", "dpu_kid_123")
	if err != nil {
		t.Fatalf("failed to update DPU enrollment: %v", err)
	}

	// Verify key is set
	dpu, err := server.store.Get(dpuID)
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.PublicKey == nil {
		t.Fatal("expected public_key to be set after enrollment")
	}
	if dpu.KeyFingerprint == nil {
		t.Fatal("expected key_fingerprint to be set after enrollment")
	}
	t.Logf("DPU has public key: %v, fingerprint: %v", dpu.PublicKey != nil, dpu.KeyFingerprint)

	t.Log("Creating super admin")
	superAdminID := "op_super_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@acme.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenantID, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant: %v", err)
	}
	superKID := "adm_super_" + uuid.New().String()[:8]

	// Decommission the DPU
	_, err = server.store.DecommissionDPUAtomic(dpuID, superKID, "Test decommission")
	if err != nil {
		t.Fatalf("failed to decommission DPU: %v", err)
	}

	t.Log("Reactivating DPU")
	body := `{"reason": "Hardware returned from RMA repair"}`
	req := httptest.NewRequest("POST", "/api/v1/dpus/"+dpuID+"/reactivate", bytes.NewReader([]byte(body)))
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

	t.Log("Verifying old credentials are cleared")
	dpu, err = server.store.Get(dpuID)
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.PublicKey != nil {
		t.Error("expected public_key to be cleared after reactivation")
	}
	if dpu.KeyFingerprint != nil {
		t.Error("expected key_fingerprint to be cleared after reactivation")
	}
	if dpu.Kid != nil {
		t.Error("expected kid to be cleared after reactivation")
	}

	t.Log("Old credentials correctly cleared after reactivation")
}
