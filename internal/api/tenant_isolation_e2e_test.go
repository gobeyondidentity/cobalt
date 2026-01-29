package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// TestMultiTenantIsolation_CrossTenantAuthorizationFails verifies that an operator
// with access to a CA in Tenant-A cannot use that CA to authorize access to a DPU
// in Tenant-B.
func TestMultiTenantIsolation_CrossTenantAuthorizationFails(t *testing.T) {
	t.Log("Testing cross-tenant authorization fails")
	server, mux := setupTestServer(t)

	// Create Tenant-A and Tenant-B
	t.Log("Creating Tenant-A with Operator-A, DPU-A, CA-A")
	tenantAID := "tenant-a-" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantAID, "Tenant A", "Test tenant A", "admin-a@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant A: %v", err)
	}

	t.Log("Creating Tenant-B with DPU-B")
	tenantBID := "tenant-b-" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantBID, "Tenant B", "Test tenant B", "admin-b@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant B: %v", err)
	}

	// Create Operator-A and add to Tenant-A
	operatorAID := "op-a-" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorAID, "operator-a@test.com", "Operator A"); err != nil {
		t.Fatalf("failed to create operator A: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorAID, tenantAID, "admin"); err != nil {
		t.Fatalf("failed to add operator A to tenant A: %v", err)
	}

	// Create DPU-A (assigned to Tenant-A) and DPU-B (assigned to Tenant-B)
	dpuAID := "dpu-a-" + uuid.New().String()[:8]
	if err := server.store.Add(dpuAID, "bf3-tenant-a", "192.168.1.10", 50051); err != nil {
		t.Fatalf("failed to create DPU A: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuAID, tenantAID); err != nil {
		t.Fatalf("failed to assign DPU A to tenant A: %v", err)
	}

	dpuBID := "dpu-b-" + uuid.New().String()[:8]
	if err := server.store.Add(dpuBID, "bf3-tenant-b", "192.168.1.20", 50051); err != nil {
		t.Fatalf("failed to create DPU B: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuBID, tenantBID); err != nil {
		t.Fatalf("failed to assign DPU B to tenant B: %v", err)
	}

	// Create CA-A (assigned to Tenant-A)
	caAID := "ca-a-" + uuid.New().String()[:8]
	if err := server.store.CreateSSHCA(caAID, "ssh-ca-tenant-a", []byte("pubkey-a"), []byte("privkey-a"), "ed25519", &tenantAID); err != nil {
		t.Fatalf("failed to create CA A: %v", err)
	}

	// Grant Operator-A access to CA-A and DPU-A (within Tenant-A)
	t.Log("Granting Operator-A access to CA-A and DPU-A in Tenant-A")
	authID := "auth-" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorAID, tenantAID, []string{caAID}, []string{dpuAID}, "system", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Test: Operator-A attempts to access DPU-B (in Tenant-B) using CA-A
	t.Log("Attempting authorization check for Operator-A targeting DPU-B (wrong tenant)")
	body := CheckAuthorizationRequest{
		OperatorID: operatorAID,
		CAID:       caAID,
		DeviceID:   dpuBID, // DPU-B is in Tenant-B, not authorized
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Log("Verifying authorization denied for cross-tenant access")
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result CheckAuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Authorized {
		t.Error("expected authorized=false for cross-tenant DPU access, but got true")
	}
	if result.Reason == "" {
		t.Error("expected a reason when not authorized")
	}
}

// TestMultiTenantIsolation_CrossTenantCAAccessFails verifies that an operator
// cannot access a CA that belongs to a different tenant.
func TestMultiTenantIsolation_CrossTenantCAAccessFails(t *testing.T) {
	t.Log("Testing cross-tenant CA access fails")
	server, mux := setupTestServer(t)

	// Create Tenant-A and Tenant-B
	tenantAID := "tenant-a-" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantAID, "Tenant A", "Test tenant A", "admin-a@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant A: %v", err)
	}

	tenantBID := "tenant-b-" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantBID, "Tenant B", "Test tenant B", "admin-b@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant B: %v", err)
	}

	// Create Operator-A in Tenant-A
	operatorAID := "op-a-" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorAID, "operator-a@test.com", "Operator A"); err != nil {
		t.Fatalf("failed to create operator A: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorAID, tenantAID, "admin"); err != nil {
		t.Fatalf("failed to add operator A to tenant A: %v", err)
	}

	// Create CA-A (Tenant-A) and CA-B (Tenant-B)
	caAID := "ca-a-" + uuid.New().String()[:8]
	if err := server.store.CreateSSHCA(caAID, "ssh-ca-tenant-a", []byte("pubkey-a"), []byte("privkey-a"), "ed25519", &tenantAID); err != nil {
		t.Fatalf("failed to create CA A: %v", err)
	}

	caBID := "ca-b-" + uuid.New().String()[:8]
	if err := server.store.CreateSSHCA(caBID, "ssh-ca-tenant-b", []byte("pubkey-b"), []byte("privkey-b"), "ed25519", &tenantBID); err != nil {
		t.Fatalf("failed to create CA B: %v", err)
	}

	// Grant Operator-A access to CA-A only
	authID := "auth-" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorAID, tenantAID, []string{caAID}, []string{"all"}, "system", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Test: Operator-A attempts to access CA-B (in Tenant-B)
	t.Log("Operator-A granted to CA-A (Tenant-A), attempting access to CA-B (Tenant-B)")
	body := CheckAuthorizationRequest{
		OperatorID: operatorAID,
		CAID:       caBID, // CA-B belongs to Tenant-B
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Log("Verifying authorization denied for cross-tenant CA")
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result CheckAuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Authorized {
		t.Error("expected authorized=false for cross-tenant CA access, but got true")
	}
}

// TestMultiTenantIsolation_ResourceListingIsolation verifies that listing resources
// for one tenant does not include resources from another tenant.
func TestMultiTenantIsolation_ResourceListingIsolation(t *testing.T) {
	t.Log("Testing resource listing isolation")
	server, mux := setupTestServer(t)

	// Create Tenant-A and Tenant-B
	tenantAID := "tenant-a-" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantAID, "Tenant A", "Test tenant A", "admin-a@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant A: %v", err)
	}

	tenantBID := "tenant-b-" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantBID, "Tenant B", "Test tenant B", "admin-b@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant B: %v", err)
	}

	// Create DPUs for Tenant-A
	t.Log("Creating DPUs in Tenant-A and Tenant-B")
	dpuA1ID := "dpu-a1-" + uuid.New().String()[:8]
	if err := server.store.Add(dpuA1ID, "bf3-tenant-a-1", "192.168.1.10", 50051); err != nil {
		t.Fatalf("failed to create DPU A1: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuA1ID, tenantAID); err != nil {
		t.Fatalf("failed to assign DPU A1 to tenant A: %v", err)
	}

	dpuA2ID := "dpu-a2-" + uuid.New().String()[:8]
	if err := server.store.Add(dpuA2ID, "bf3-tenant-a-2", "192.168.1.11", 50051); err != nil {
		t.Fatalf("failed to create DPU A2: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuA2ID, tenantAID); err != nil {
		t.Fatalf("failed to assign DPU A2 to tenant A: %v", err)
	}

	// Create DPUs for Tenant-B
	dpuB1ID := "dpu-b1-" + uuid.New().String()[:8]
	if err := server.store.Add(dpuB1ID, "bf3-tenant-b-1", "192.168.1.20", 50051); err != nil {
		t.Fatalf("failed to create DPU B1: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuB1ID, tenantBID); err != nil {
		t.Fatalf("failed to assign DPU B1 to tenant B: %v", err)
	}

	dpuB2ID := "dpu-b2-" + uuid.New().String()[:8]
	if err := server.store.Add(dpuB2ID, "bf3-tenant-b-2", "192.168.1.21", 50051); err != nil {
		t.Fatalf("failed to create DPU B2: %v", err)
	}
	if err := server.store.AssignDPUToTenant(dpuB2ID, tenantBID); err != nil {
		t.Fatalf("failed to assign DPU B2 to tenant B: %v", err)
	}

	// Test: List DPUs for Tenant-A only
	t.Log("Listing DPUs for Tenant-A only")
	req := httptest.NewRequest("GET", "/api/tenants/"+tenantAID+"/dpus", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []dpuResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Log("Verifying only Tenant-A DPUs returned, no cross-tenant leakage")
	if len(result) != 2 {
		t.Errorf("expected 2 DPUs for Tenant-A, got %d", len(result))
	}

	// Verify that only Tenant-A DPUs are in the result
	dpuAIDs := map[string]bool{dpuA1ID: false, dpuA2ID: false}
	dpuBIDs := map[string]bool{dpuB1ID: true, dpuB2ID: true}

	for _, dpu := range result {
		if _, ok := dpuAIDs[dpu.ID]; ok {
			dpuAIDs[dpu.ID] = true
		}
		if _, ok := dpuBIDs[dpu.ID]; ok {
			t.Errorf("Tenant-B DPU %s leaked into Tenant-A query", dpu.ID)
		}
	}

	// Verify all Tenant-A DPUs were found
	for id, found := range dpuAIDs {
		if !found {
			t.Errorf("Tenant-A DPU %s was not returned in query", id)
		}
	}
}

// TestMultiTenantIsolation_OperatorCannotSeeOtherTenantAuthorizations verifies that
// listing authorizations for one tenant does not include authorizations from another tenant.
func TestMultiTenantIsolation_OperatorCannotSeeOtherTenantAuthorizations(t *testing.T) {
	t.Log("Testing authorization listing isolation")
	server, mux := setupTestServer(t)

	// Create Tenant-A and Tenant-B
	tenantAID := "tenant-a-" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantAID, "Tenant A", "Test tenant A", "admin-a@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant A: %v", err)
	}

	tenantBID := "tenant-b-" + uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantBID, "Tenant B", "Test tenant B", "admin-b@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant B: %v", err)
	}

	// Create Operator-A in Tenant-A
	operatorAID := "op-a-" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorAID, "operator-a@test.com", "Operator A"); err != nil {
		t.Fatalf("failed to create operator A: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorAID, tenantAID, "admin"); err != nil {
		t.Fatalf("failed to add operator A to tenant A: %v", err)
	}

	// Create Operator-B in Tenant-B
	operatorBID := "op-b-" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorBID, "operator-b@test.com", "Operator B"); err != nil {
		t.Fatalf("failed to create operator B: %v", err)
	}
	if err := server.store.AddOperatorToTenant(operatorBID, tenantBID, "admin"); err != nil {
		t.Fatalf("failed to add operator B to tenant B: %v", err)
	}

	// Create CAs for each tenant
	caAID := "ca-a-" + uuid.New().String()[:8]
	if err := server.store.CreateSSHCA(caAID, "ssh-ca-tenant-a", []byte("pubkey-a"), []byte("privkey-a"), "ed25519", &tenantAID); err != nil {
		t.Fatalf("failed to create CA A: %v", err)
	}

	caBID := "ca-b-" + uuid.New().String()[:8]
	if err := server.store.CreateSSHCA(caBID, "ssh-ca-tenant-b", []byte("pubkey-b"), []byte("privkey-b"), "ed25519", &tenantBID); err != nil {
		t.Fatalf("failed to create CA B: %v", err)
	}

	// Create authorizations for each tenant
	authAID := "auth-a-" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authAID, operatorAID, tenantAID, []string{caAID}, []string{"all"}, "system", nil); err != nil {
		t.Fatalf("failed to create authorization A: %v", err)
	}

	authBID := "auth-b-" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authBID, operatorBID, tenantBID, []string{caBID}, []string{"all"}, "system", nil); err != nil {
		t.Fatalf("failed to create authorization B: %v", err)
	}

	// Test: List authorizations for Tenant-A only
	t.Log("Verifying Tenant-A query only returns Tenant-A authorizations")
	req := httptest.NewRequest("GET", "/api/v1/authorizations?tenant_id="+tenantAID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify only Tenant-A authorization is returned
	if len(result) != 1 {
		t.Errorf("expected 1 authorization for Tenant-A, got %d", len(result))
	}

	for _, auth := range result {
		if auth.TenantID != tenantAID {
			t.Errorf("expected tenant_id %s, got %s", tenantAID, auth.TenantID)
		}
		if auth.ID == authBID {
			t.Error("Tenant-B authorization leaked into Tenant-A query")
		}
	}

	// Verify Tenant-A authorization was returned
	found := false
	for _, auth := range result {
		if auth.ID == authAID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Tenant-A authorization was not returned in query")
	}
}
