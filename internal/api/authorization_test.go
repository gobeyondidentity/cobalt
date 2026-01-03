package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestCreateAuthorization_Success tests successful authorization creation.
func TestCreateAuthorization_Success(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create authorization
	body := CreateAuthorizationRequest{
		OperatorEmail: "operator@acme.com",
		TenantID:      tenantID,
		CAIDs:         []string{"ca-prod-001", "ca-staging-001"},
		DeviceIDs:     []string{"all"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var result AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.ID == "" {
		t.Error("expected non-empty authorization id")
	}
	if result.OperatorID != operatorID {
		t.Errorf("expected operator_id '%s', got '%s'", operatorID, result.OperatorID)
	}
	if result.TenantID != tenantID {
		t.Errorf("expected tenant_id '%s', got '%s'", tenantID, result.TenantID)
	}
	if len(result.CAIDs) != 2 {
		t.Errorf("expected 2 CA IDs, got %d", len(result.CAIDs))
	}
	if len(result.DeviceIDs) != 1 || result.DeviceIDs[0] != "all" {
		t.Errorf("expected device_ids ['all'], got %v", result.DeviceIDs)
	}
	if result.CreatedAt == "" {
		t.Error("expected non-empty created_at")
	}
}

// TestCreateAuthorization_WithExpiry tests authorization creation with expiration.
func TestCreateAuthorization_WithExpiry(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create authorization with expiration
	expiresAt := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	body := CreateAuthorizationRequest{
		OperatorEmail: "operator@acme.com",
		TenantID:      tenantID,
		CAIDs:         []string{"ca-prod-001"},
		DeviceIDs:     []string{"device-001", "device-002"},
		ExpiresAt:     &expiresAt,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var result AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.ExpiresAt == nil {
		t.Error("expected non-nil expires_at")
	}
	if len(result.DeviceIDs) != 2 {
		t.Errorf("expected 2 device IDs, got %d", len(result.DeviceIDs))
	}
}

// TestCreateAuthorization_OperatorNotFound tests authorization creation with non-existent operator.
func TestCreateAuthorization_OperatorNotFound(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Try to create authorization for non-existent operator
	body := CreateAuthorizationRequest{
		OperatorEmail: "nonexistent@acme.com",
		TenantID:      tenantID,
		CAIDs:         []string{"ca-prod-001"},
		DeviceIDs:     []string{"all"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

// TestListAuthorizations_ByOperator tests listing authorizations by operator ID.
func TestListAuthorizations_ByOperator(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create two authorizations via store directly
	auth1ID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(auth1ID, operatorID, tenantID, []string{"ca-1"}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization 1: %v", err)
	}

	auth2ID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(auth2ID, operatorID, tenantID, []string{"ca-2"}, []string{"device-1"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization 2: %v", err)
	}

	// List authorizations by operator
	req := httptest.NewRequest("GET", "/api/v1/authorizations?operator_id="+operatorID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 authorizations, got %d", len(result))
	}
}

// TestListAuthorizations_ByTenant tests listing authorizations by tenant ID.
func TestListAuthorizations_ByTenant(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create two operators with authorizations
	op1ID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(op1ID, "op1@acme.com", "Operator 1"); err != nil {
		t.Fatalf("failed to create operator 1: %v", err)
	}

	op2ID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(op2ID, "op2@acme.com", "Operator 2"); err != nil {
		t.Fatalf("failed to create operator 2: %v", err)
	}

	// Create authorizations for both operators in the same tenant
	auth1ID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(auth1ID, op1ID, tenantID, []string{"ca-1"}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization 1: %v", err)
	}

	auth2ID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(auth2ID, op2ID, tenantID, []string{"ca-2"}, []string{"device-1"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization 2: %v", err)
	}

	// List authorizations by tenant
	req := httptest.NewRequest("GET", "/api/v1/authorizations?tenant_id="+tenantID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 authorizations, got %d", len(result))
	}
}

// TestListAuthorizations_NoFilter tests that listing without filter returns error.
func TestListAuthorizations_NoFilter(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/authorizations", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestGetAuthorization_Success tests getting a single authorization.
func TestGetAuthorization_Success(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create authorization via store
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{"ca-prod"}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Get authorization
	req := httptest.NewRequest("GET", "/api/v1/authorizations/"+authID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.ID != authID {
		t.Errorf("expected id '%s', got '%s'", authID, result.ID)
	}
	if result.OperatorID != operatorID {
		t.Errorf("expected operator_id '%s', got '%s'", operatorID, result.OperatorID)
	}
}

// TestGetAuthorization_NotFound tests getting a non-existent authorization.
func TestGetAuthorization_NotFound(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/authorizations/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

// TestDeleteAuthorization_Success tests successful authorization deletion.
func TestDeleteAuthorization_Success(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create authorization via store
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{"ca-prod"}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Delete authorization
	req := httptest.NewRequest("DELETE", "/api/v1/authorizations/"+authID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify deletion
	_, err := server.store.GetAuthorization(authID)
	if err == nil {
		t.Error("expected authorization to be deleted")
	}
}

// TestDeleteAuthorization_NotFound tests deleting a non-existent authorization.
func TestDeleteAuthorization_NotFound(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("DELETE", "/api/v1/authorizations/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCheckAuthorization_Authorized tests checking authorization when operator is authorized.
func TestCheckAuthorization_Authorized(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create authorization granting access to ca-prod and all devices
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{"ca-prod"}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Check authorization for CA only
	body := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       "ca-prod",
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

	if !result.Authorized {
		t.Errorf("expected authorized=true, got false. Reason: %s", result.Reason)
	}
}

// TestCheckAuthorization_AuthorizedWithDevice tests checking full authorization.
func TestCheckAuthorization_AuthorizedWithDevice(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create authorization granting access to ca-prod and all devices
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{"ca-prod"}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Check full authorization (CA + device)
	body := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       "ca-prod",
		DeviceID:   "device-xyz-123",
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

	if !result.Authorized {
		t.Errorf("expected authorized=true, got false. Reason: %s", result.Reason)
	}
}

// TestCheckAuthorization_NotAuthorized tests checking authorization when operator is not authorized.
func TestCheckAuthorization_NotAuthorized(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create authorization for a different CA
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{"ca-staging"}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Check authorization for ca-prod (not authorized)
	body := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       "ca-prod", // Operator only has access to ca-staging
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

	if result.Authorized {
		t.Error("expected authorized=false, got true")
	}
	if result.Reason == "" {
		t.Error("expected reason to be non-empty when not authorized")
	}
}

// TestCheckAuthorization_NotAuthorizedForDevice tests specific device authorization failure.
func TestCheckAuthorization_NotAuthorizedForDevice(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create authorization for ca-prod but only specific device
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{"ca-prod"}, []string{"device-001"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Check authorization for different device
	body := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       "ca-prod",
		DeviceID:   "device-999", // Not authorized for this device
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

	if result.Authorized {
		t.Error("expected authorized=false for unauthorized device, got true")
	}
}

// TestCheckAuthorization_MissingOperatorID tests check with missing operator_id.
func TestCheckAuthorization_MissingOperatorID(t *testing.T) {
	_, mux := setupTestServer(t)

	body := CheckAuthorizationRequest{
		CAID: "ca-prod",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCheckAuthorization_MissingCAID tests check with missing ca_id.
func TestCheckAuthorization_MissingCAID(t *testing.T) {
	_, mux := setupTestServer(t)

	body := CheckAuthorizationRequest{
		OperatorID: "some-operator-id",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAuthorizationResponse_IncludesNames tests that authorization responses include both IDs and names.
func TestAuthorizationResponse_IncludesNames(t *testing.T) {
	server, mux := setupTestServer(t)

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

	// Create an SSH CA with a known ID and name
	caID := "ca_" + uuid.New().String()[:8]
	caName := "test-production-ca"
	pubKey := []byte("fake-public-key")
	privKey := []byte("fake-private-key")
	if err := server.store.CreateSSHCA(caID, caName, pubKey, privKey, "ed25519", &tenantID); err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	// Create a DPU with a known ID and name
	dpuID := "dpu_" + uuid.New().String()[:8]
	dpuName := "bf3-gpu-cluster-1"
	if err := server.store.Add(dpuID, dpuName, "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}

	// Create authorization using the CA ID and DPU ID
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{caID}, []string{dpuID}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Get authorization via API
	req := httptest.NewRequest("GET", "/api/v1/authorizations/"+authID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify IDs are present
	if len(result.CAIDs) != 1 || result.CAIDs[0] != caID {
		t.Errorf("expected ca_ids [%s], got %v", caID, result.CAIDs)
	}
	if len(result.DeviceIDs) != 1 || result.DeviceIDs[0] != dpuID {
		t.Errorf("expected device_ids [%s], got %v", dpuID, result.DeviceIDs)
	}

	// Verify names are resolved correctly
	if len(result.CANames) != 1 || result.CANames[0] != caName {
		t.Errorf("expected ca_names [%s], got %v", caName, result.CANames)
	}
	if len(result.DeviceNames) != 1 || result.DeviceNames[0] != dpuName {
		t.Errorf("expected device_names [%s], got %v", dpuName, result.DeviceNames)
	}
}

// TestAuthorizationResponse_AllDevicesName tests that "all" device ID returns "all" as name.
func TestAuthorizationResponse_AllDevicesName(t *testing.T) {
	server, mux := setupTestServer(t)

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

	// Create authorization with "all" devices
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{"ca-prod"}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Get authorization via API
	req := httptest.NewRequest("GET", "/api/v1/authorizations/"+authID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify "all" is preserved in both IDs and names
	if len(result.DeviceIDs) != 1 || result.DeviceIDs[0] != "all" {
		t.Errorf("expected device_ids [all], got %v", result.DeviceIDs)
	}
	if len(result.DeviceNames) != 1 || result.DeviceNames[0] != "all" {
		t.Errorf("expected device_names [all], got %v", result.DeviceNames)
	}
}

// TestAuthorizationResponse_GracefulDegradation tests that unknown IDs are returned as-is.
func TestAuthorizationResponse_GracefulDegradation(t *testing.T) {
	server, mux := setupTestServer(t)

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

	// Create authorization with CA and device IDs that don't exist in the store
	unknownCAID := "ca_nonexistent"
	unknownDeviceID := "dpu_nonexistent"
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{unknownCAID}, []string{unknownDeviceID}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// Get authorization via API
	req := httptest.NewRequest("GET", "/api/v1/authorizations/"+authID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify IDs are present
	if len(result.CAIDs) != 1 || result.CAIDs[0] != unknownCAID {
		t.Errorf("expected ca_ids [%s], got %v", unknownCAID, result.CAIDs)
	}
	if len(result.DeviceIDs) != 1 || result.DeviceIDs[0] != unknownDeviceID {
		t.Errorf("expected device_ids [%s], got %v", unknownDeviceID, result.DeviceIDs)
	}

	// When lookup fails, names should fall back to IDs (graceful degradation)
	if len(result.CANames) != 1 || result.CANames[0] != unknownCAID {
		t.Errorf("expected ca_names to fall back to [%s], got %v", unknownCAID, result.CANames)
	}
	if len(result.DeviceNames) != 1 || result.DeviceNames[0] != unknownDeviceID {
		t.Errorf("expected device_names to fall back to [%s], got %v", unknownDeviceID, result.DeviceNames)
	}
}

// TestListAuthorizations_IncludesNames tests that list response includes names.
func TestListAuthorizations_IncludesNames(t *testing.T) {
	server, mux := setupTestServer(t)

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

	// Create an SSH CA
	caID := "ca_" + uuid.New().String()[:8]
	caName := "my-test-ca"
	if err := server.store.CreateSSHCA(caID, caName, []byte("pub"), []byte("priv"), "ed25519", &tenantID); err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	// Create authorization
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{caID}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	// List authorizations by operator
	req := httptest.NewRequest("GET", "/api/v1/authorizations?operator_id="+operatorID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []AuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 authorization, got %d", len(result))
	}

	// Verify names are included in list response
	if len(result[0].CANames) != 1 || result[0].CANames[0] != caName {
		t.Errorf("expected ca_names [%s], got %v", caName, result[0].CANames)
	}
	if len(result[0].DeviceNames) != 1 || result[0].DeviceNames[0] != "all" {
		t.Errorf("expected device_names [all], got %v", result[0].DeviceNames)
	}
}
