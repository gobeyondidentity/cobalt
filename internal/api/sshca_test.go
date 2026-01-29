package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// TestCreateSSHCA_Success tests successful SSH CA creation via API.
func TestCreateSSHCA_Success(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Creating SSH CA via POST /api/v1/ssh-cas")
	body := createSSHCARequest{
		Name:      "test-production-ca",
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDPBzSGdN6RSHNr2x3vy2X4KV9VEjOYwL0Y2qAP/H test@example.com",
		KeyType:   "ed25519",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	// Add auth context (simulates authenticated request)
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 201 Created")
	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Decoding response body")
	var result createSSHCAResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Log("Verifying response fields")
	if result.ID == "" {
		t.Error("expected non-empty CA ID")
	}
	if result.Name != "test-production-ca" {
		t.Errorf("expected name 'test-production-ca', got '%s'", result.Name)
	}
	if result.KeyType != "ed25519" {
		t.Errorf("expected key_type 'ed25519', got '%s'", result.KeyType)
	}
	if result.CreatedAt == "" {
		t.Error("expected non-empty created_at")
	}

	t.Log("Verifying CA was stored in database")
	ca, err := server.store.GetSSHCA("test-production-ca")
	if err != nil {
		t.Fatalf("failed to retrieve CA from store: %v", err)
	}
	if ca.ID != result.ID {
		t.Errorf("stored CA ID '%s' doesn't match response ID '%s'", ca.ID, result.ID)
	}
}

// addSSHCAAuthContext adds authenticated operator context to a request.
func addSSHCAAuthContext(req *http.Request, operatorID, operatorEmail, keyMakerID string) *http.Request {
	ctx := req.Context()
	ctx = context.WithValue(ctx, contextKeyOperatorID, operatorID)
	ctx = context.WithValue(ctx, contextKeyOperatorEmail, operatorEmail)
	ctx = context.WithValue(ctx, contextKeyKeyMakerID, keyMakerID)
	return req.WithContext(ctx)
}

// TestCreateSSHCA_Unauthenticated tests SSH CA creation without authentication returns 401.
func TestCreateSSHCA_Unauthenticated(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating SSH CA without authentication")
	body := createSSHCARequest{
		Name:      "test-ca",
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDPBzSGdN6RSHNr2x3vy2X4KV9VEjOYwL0Y2qAP/H test@example.com",
		KeyType:   "ed25519",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	// No auth context added

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 401 Unauthorized")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateSSHCA_MissingName tests SSH CA creation with missing name returns 400.
func TestCreateSSHCA_MissingName(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Creating SSH CA without name")
	body := createSSHCARequest{
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDPBzSGdN6RSHNr2x3vy2X4KV9VEjOYwL0Y2qAP/H test@example.com",
		KeyType:   "ed25519",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 400 Bad Request")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateSSHCA_MissingPublicKey tests SSH CA creation with missing public_key returns 400.
func TestCreateSSHCA_MissingPublicKey(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Creating SSH CA without public_key")
	body := createSSHCARequest{
		Name:    "test-ca",
		KeyType: "ed25519",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 400 Bad Request")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateSSHCA_MissingKeyType tests SSH CA creation with missing key_type returns 400.
func TestCreateSSHCA_MissingKeyType(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Creating SSH CA without key_type")
	body := createSSHCARequest{
		Name:      "test-ca",
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDPBzSGdN6RSHNr2x3vy2X4KV9VEjOYwL0Y2qAP/H test@example.com",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 400 Bad Request")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateSSHCA_CANameExists tests SSH CA creation when name already exists returns 409.
func TestCreateSSHCA_CANameExists(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Creating first SSH CA directly in store")
	caID := "ca_" + uuid.New().String()[:8]
	err := server.store.CreateSSHCA(caID, "existing-ca", []byte("ssh-ed25519 AAAA pubkey"), []byte("privkey"), "ed25519", nil)
	if err != nil {
		t.Fatalf("failed to create existing CA: %v", err)
	}

	t.Log("Attempting to create SSH CA with same name via API")
	body := createSSHCARequest{
		Name:      "existing-ca",
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDPBzSGdN6RSHNr2x3vy2X4KV9VEjOYwL0Y2qAP/H test@example.com",
		KeyType:   "ed25519",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 409 Conflict")
	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateSSHCA_InvalidPublicKeyFormat tests SSH CA creation with invalid public key format returns 400.
func TestCreateSSHCA_InvalidPublicKeyFormat(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Creating SSH CA with invalid public key format")
	body := createSSHCARequest{
		Name:      "test-ca",
		PublicKey: "invalid-key-format",
		KeyType:   "ed25519",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 400 Bad Request")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateSSHCA_ECDSAPublicKey tests SSH CA creation with ecdsa public key is accepted.
func TestCreateSSHCA_ECDSAPublicKey(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Creating SSH CA with ecdsa public key")
	body := createSSHCARequest{
		Name:      "ecdsa-ca",
		PublicKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFake test@example.com",
		KeyType:   "ecdsa",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 201 Created")
	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateSSHCA_RSAPublicKey tests SSH CA creation with ssh-rsa public key is accepted.
func TestCreateSSHCA_RSAPublicKey(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Creating SSH CA with RSA public key")
	body := createSSHCARequest{
		Name:      "rsa-ca",
		PublicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC test@example.com",
		KeyType:   "rsa",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 201 Created")
	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateSSHCA_IDHasCAPrefix tests that generated CA ID has 'ca_' prefix.
func TestCreateSSHCA_IDHasCAPrefix(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Creating SSH CA")
	body := createSSHCARequest{
		Name:      "prefix-test-ca",
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDPBzSGdN6RSHNr2x3vy2X4KV9VEjOYwL0Y2qAP/H test@example.com",
		KeyType:   "ed25519",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var result createSSHCAResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Logf("Verifying CA ID '%s' has 'ca_' prefix", result.ID)
	if len(result.ID) < 3 || result.ID[:3] != "ca_" {
		t.Errorf("expected CA ID to have 'ca_' prefix, got '%s'", result.ID)
	}
}

// TestCreateSSHCA_InvalidJSON tests SSH CA creation with invalid JSON returns 400.
func TestCreateSSHCA_InvalidJSON(t *testing.T) {
	t.Log("Setting up test server")
	server, _ := setupTestServer(t)

	t.Log("Creating an operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := server.store.UpdateOperatorStatus(operatorID, "active"); err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	t.Log("Sending invalid JSON")
	req := httptest.NewRequest("POST", "/api/v1/ssh-cas", bytes.NewBufferString("{invalid json}"))
	req.Header.Set("Content-Type", "application/json")
	req = addSSHCAAuthContext(req, operatorID, "operator@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handleCreateSSHCA(w, req)

	t.Log("Verifying response status is 400 Bad Request")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}
