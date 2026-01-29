package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// TestAuthorizationEnforcement_PushWithoutGrant tests that authorization check
// returns denied when no grant exists for the operator.
func TestAuthorizationEnforcement_PushWithoutGrant(t *testing.T) {
	t.Log("Testing authorization check WITHOUT grant - should be denied")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant, operator, CA, and DPU")

	// Create a tenant
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create an SSH CA for the tenant
	caID := "ca_" + uuid.New().String()[:8]
	caName := "test-production-ca"
	pubKey := []byte("fake-public-key")
	privKey := []byte("fake-private-key")
	if err := server.store.CreateSSHCA(caID, caName, pubKey, privKey, "ed25519", &tenantID); err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	// Create a DPU and assign to tenant
	dpuID := "dpu_" + uuid.New().String()[:8]
	dpuName := "bf3-test-cluster"
	if err := server.store.Add(dpuID, dpuName, "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}

	// Do NOT create any authorization grant

	t.Log("Calling authorization check endpoint")

	// Call authorization check endpoint
	body := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       caID,
		DeviceID:   dpuID,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result CheckAuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Log("Verifying authorization denied")

	if result.Authorized {
		t.Error("expected authorized=false when no grant exists, got true")
	}
	if result.Reason == "" {
		t.Error("expected reason to be non-empty when not authorized")
	}
	t.Logf("Authorization correctly denied with reason: %s", result.Reason)
}

// TestAuthorizationEnforcement_PushWithGrant tests that authorization check
// returns allowed when a matching grant exists for the operator.
func TestAuthorizationEnforcement_PushWithGrant(t *testing.T) {
	t.Log("Testing authorization check WITH grant - should be allowed")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant, operator, CA, and DPU")

	// Create a tenant
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create an SSH CA for the tenant
	caID := "ca_" + uuid.New().String()[:8]
	caName := "test-production-ca"
	pubKey := []byte("fake-public-key")
	privKey := []byte("fake-private-key")
	if err := server.store.CreateSSHCA(caID, caName, pubKey, privKey, "ed25519", &tenantID); err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	// Create a DPU and assign to tenant
	dpuID := "dpu_" + uuid.New().String()[:8]
	dpuName := "bf3-test-cluster"
	if err := server.store.Add(dpuID, dpuName, "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}

	t.Log("Creating authorization grant for operator")

	// Create authorization grant: operator -> CA -> device
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{caID}, []string{dpuID}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	t.Log("Calling authorization check endpoint")

	// Call authorization check endpoint
	body := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       caID,
		DeviceID:   dpuID,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result CheckAuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Log("Verifying authorization allowed")

	if !result.Authorized {
		t.Errorf("expected authorized=true with matching grant, got false. Reason: %s", result.Reason)
	}
	t.Log("Authorization correctly allowed with matching grant")
}

// TestAuthorizationEnforcement_WrongDPU tests that authorization check
// returns denied when the grant is for a different DPU than requested.
func TestAuthorizationEnforcement_WrongDPU(t *testing.T) {
	t.Log("Testing authorization check for WRONG DPU - should be denied")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant, operator, CA, and two DPUs (A and B)")

	// Create a tenant
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create an SSH CA for the tenant
	caID := "ca_" + uuid.New().String()[:8]
	caName := "test-production-ca"
	pubKey := []byte("fake-public-key")
	privKey := []byte("fake-private-key")
	if err := server.store.CreateSSHCA(caID, caName, pubKey, privKey, "ed25519", &tenantID); err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	// Create DPU-A
	dpuAID := "dpu_" + uuid.New().String()[:8]
	dpuAName := "bf3-cluster-a"
	if err := server.store.Add(dpuAID, dpuAName, "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU-A: %v", err)
	}

	// Create DPU-B
	dpuBID := "dpu_" + uuid.New().String()[:8]
	dpuBName := "bf3-cluster-b"
	if err := server.store.Add(dpuBID, dpuBName, "192.168.1.101", 50051); err != nil {
		t.Fatalf("failed to create DPU-B: %v", err)
	}

	t.Log("Grant is for DPU-A, checking authorization for DPU-B")

	// Create authorization grant for DPU-A only
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{caID}, []string{dpuAID}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Call authorization check endpoint for DPU-B (not in grant)
	body := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       caID,
		DeviceID:   dpuBID, // Request authorization for DPU-B, but grant is for DPU-A
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result CheckAuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Log("Verifying authorization denied for wrong device")

	if result.Authorized {
		t.Error("expected authorized=false for wrong DPU, got true")
	}
	if result.Reason == "" {
		t.Error("expected reason to be non-empty when not authorized")
	}
	t.Logf("Authorization correctly denied for wrong DPU with reason: %s", result.Reason)
}
