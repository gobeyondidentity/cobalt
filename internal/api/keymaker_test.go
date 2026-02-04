package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/store"
	"github.com/google/uuid"
)

// TestBindKeyMaker_Success tests successful binding with a valid invite code.
func TestBindKeyMaker_Success(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "nelson@acme.com", "Nelson"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Add operator to tenant
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}

	// Generate and store invite code
	inviteCode := store.GenerateInviteCode("ACME")
	codeHash := store.HashInviteCode(inviteCode)
	inviteID := uuid.New().String()[:8]
	invite := &store.InviteCode{
		ID:            inviteID,
		CodeHash:      codeHash,
		OperatorEmail: "nelson@acme.com",
		TenantID:      tenantID,
		Role:          "admin",
		CreatedBy:     "system",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Status:        "pending",
	}
	if err := server.store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Bind KeyMaker
	body := BindRequest{
		InviteCode:        inviteCode,
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "abc123def456",
		DeviceName:        "workstation-home",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result BindResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.KeyMakerID == "" {
		t.Error("expected non-empty keymaker_id")
	}
	if result.OperatorID != operatorID {
		t.Errorf("expected operator_id '%s', got '%s'", operatorID, result.OperatorID)
	}
	if result.OperatorEmail != "nelson@acme.com" {
		t.Errorf("expected operator_email 'nelson@acme.com', got '%s'", result.OperatorEmail)
	}
	if len(result.Tenants) != 1 {
		t.Errorf("expected 1 tenant, got %d", len(result.Tenants))
	}
	if len(result.Tenants) > 0 && result.Tenants[0].TenantID != tenantID {
		t.Errorf("expected tenant_id '%s', got '%s'", tenantID, result.Tenants[0].TenantID)
	}
	if len(result.Tenants) > 0 && result.Tenants[0].Role != "admin" {
		t.Errorf("expected role 'admin', got '%s'", result.Tenants[0].Role)
	}

	// Verify operator status is now active
	op, err := server.store.GetOperator(operatorID)
	if err != nil {
		t.Fatalf("failed to get operator: %v", err)
	}
	if op.Status != "active" {
		t.Errorf("expected operator status 'active', got '%s'", op.Status)
	}

	// Verify invite code is now used
	usedInvite, err := server.store.GetInviteCodeByHash(codeHash)
	if err != nil {
		t.Fatalf("failed to get invite code: %v", err)
	}
	if usedInvite.Status != "used" {
		t.Errorf("expected invite status 'used', got '%s'", usedInvite.Status)
	}
}

// TestBindKeyMaker_InvalidCode tests binding with an invalid/unknown invite code.
func TestBindKeyMaker_InvalidCode(t *testing.T) {
	_, mux := setupTestServer(t)

	body := BindRequest{
		InviteCode:        "INVALID-1234-5678",
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "abc123def456",
		DeviceName:        "workstation-home",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] != "invalid invite code" {
		t.Errorf("expected error 'invalid invite code', got '%s'", result["error"])
	}
}

// TestBindKeyMaker_ExpiredCode tests binding with an expired invite code.
func TestBindKeyMaker_ExpiredCode(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "nelson@acme.com", "Nelson"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Generate and store expired invite code
	inviteCode := store.GenerateInviteCode("ACME")
	codeHash := store.HashInviteCode(inviteCode)
	inviteID := uuid.New().String()[:8]
	invite := &store.InviteCode{
		ID:            inviteID,
		CodeHash:      codeHash,
		OperatorEmail: "nelson@acme.com",
		TenantID:      tenantID,
		Role:          "admin",
		CreatedBy:     "system",
		ExpiresAt:     time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		Status:        "pending",
	}
	if err := server.store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Try to bind KeyMaker with expired code
	body := BindRequest{
		InviteCode:        inviteCode,
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "abc123def456",
		DeviceName:        "workstation-home",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] != "invite code has expired" {
		t.Errorf("expected error 'invite code has expired', got '%s'", result["error"])
	}
}

// TestBindKeyMaker_AlreadyUsed tests binding with an already used invite code.
func TestBindKeyMaker_AlreadyUsed(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "nelson@acme.com", "Nelson"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Generate and store already-used invite code
	inviteCode := store.GenerateInviteCode("ACME")
	codeHash := store.HashInviteCode(inviteCode)
	inviteID := uuid.New().String()[:8]
	invite := &store.InviteCode{
		ID:            inviteID,
		CodeHash:      codeHash,
		OperatorEmail: "nelson@acme.com",
		TenantID:      tenantID,
		Role:          "admin",
		CreatedBy:     "system",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Status:        "used", // Already used
	}
	if err := server.store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Try to bind KeyMaker with already-used code
	body := BindRequest{
		InviteCode:        inviteCode,
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "abc123def456",
		DeviceName:        "workstation-home",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] != "invite code has already been used" {
		t.Errorf("expected error 'invite code has already been used', got '%s'", result["error"])
	}
}

// TestBindKeyMaker_RevokedCode tests binding with a revoked invite code.
func TestBindKeyMaker_RevokedCode(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "nelson@acme.com", "Nelson"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Generate and store revoked invite code
	inviteCode := store.GenerateInviteCode("ACME")
	codeHash := store.HashInviteCode(inviteCode)
	inviteID := uuid.New().String()[:8]
	invite := &store.InviteCode{
		ID:            inviteID,
		CodeHash:      codeHash,
		OperatorEmail: "nelson@acme.com",
		TenantID:      tenantID,
		Role:          "admin",
		CreatedBy:     "system",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Status:        "revoked", // Revoked by admin
	}
	if err := server.store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Try to bind KeyMaker with revoked code
	body := BindRequest{
		InviteCode:        inviteCode,
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "abc123def456",
		DeviceName:        "workstation-home",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] != "invite code has been revoked" {
		t.Errorf("expected error 'invite code has been revoked', got '%s'", result["error"])
	}
}

// TestBindKeyMaker_ExpiredStatusCode tests binding with an invite code marked as expired (by cleanup).
func TestBindKeyMaker_ExpiredStatusCode(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "nelson@acme.com", "Nelson"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Generate invite code with status "expired" (set by CleanupExpiredInvites)
	// Note: ExpiresAt is in the future, but status is already "expired"
	inviteCode := store.GenerateInviteCode("ACME")
	codeHash := store.HashInviteCode(inviteCode)
	inviteID := uuid.New().String()[:8]
	invite := &store.InviteCode{
		ID:            inviteID,
		CodeHash:      codeHash,
		OperatorEmail: "nelson@acme.com",
		TenantID:      tenantID,
		Role:          "admin",
		CreatedBy:     "system",
		ExpiresAt:     time.Now().Add(24 * time.Hour), // Future expiry, but status is expired
		Status:        "expired",                      // Marked expired by cleanup job
	}
	if err := server.store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Try to bind KeyMaker with expired status code
	body := BindRequest{
		InviteCode:        inviteCode,
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "abc123def456",
		DeviceName:        "workstation-home",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] != "invite code has expired" {
		t.Errorf("expected error 'invite code has expired', got '%s'", result["error"])
	}
}

// TestBindKeyMaker_CannotReuse tests that an invite code cannot be reused after successful binding.
func TestBindKeyMaker_CannotReuse(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "nelson@acme.com", "Nelson"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Add operator to tenant
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}

	// Generate and store invite code
	inviteCode := store.GenerateInviteCode("ACME")
	codeHash := store.HashInviteCode(inviteCode)
	inviteID := uuid.New().String()[:8]
	invite := &store.InviteCode{
		ID:            inviteID,
		CodeHash:      codeHash,
		OperatorEmail: "nelson@acme.com",
		TenantID:      tenantID,
		Role:          "admin",
		CreatedBy:     "system",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Status:        "pending",
	}
	if err := server.store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// First bind should succeed
	body := BindRequest{
		InviteCode:        inviteCode,
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey1",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "abc123def456",
		DeviceName:        "workstation-1",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first bind should succeed, got %d: %s", w.Code, w.Body.String())
	}

	// Second bind with same code should fail
	body2 := BindRequest{
		InviteCode:        inviteCode,
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey2",
		Platform:          "linux",
		SecureElement:     "tpm",
		DeviceFingerprint: "xyz789",
		DeviceName:        "workstation-2",
	}
	bodyBytes2, _ := json.Marshal(body2)

	req2 := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewReader(bodyBytes2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Errorf("reuse should fail with 400, got %d: %s", w2.Code, w2.Body.String())
	}

	var result map[string]string
	json.NewDecoder(w2.Body).Decode(&result)
	if result["error"] != "invite code has already been used" {
		t.Errorf("expected error 'invite code has already been used', got '%s'", result["error"])
	}
}

// TestBindKeyMaker_AutoGeneratesName tests that device name is auto-generated when not provided.
func TestBindKeyMaker_AutoGeneratesName(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant first
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "nelson@acme.com", "Nelson"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Add operator to tenant
	if err := server.store.AddOperatorToTenant(operatorID, tenantID, "admin"); err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}

	// Generate and store invite code
	inviteCode := store.GenerateInviteCode("ACME")
	codeHash := store.HashInviteCode(inviteCode)
	inviteID := uuid.New().String()[:8]
	invite := &store.InviteCode{
		ID:            inviteID,
		CodeHash:      codeHash,
		OperatorEmail: "nelson@acme.com",
		TenantID:      tenantID,
		Role:          "admin",
		CreatedBy:     "system",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Status:        "pending",
	}
	if err := server.store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Bind KeyMaker without device name
	body := BindRequest{
		InviteCode:        inviteCode,
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "abc123def456",
		DeviceName:        "", // Empty, should be auto-generated
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result BindResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify the KeyMaker was created with an auto-generated name
	km, err := server.store.GetKeyMaker(result.KeyMakerID)
	if err != nil {
		t.Fatalf("failed to get keymaker: %v", err)
	}

	// Name should start with "km-{platform}-"
	if km.Name == "" {
		t.Error("expected auto-generated name, got empty string")
	}
	if len(km.Name) < 10 {
		t.Errorf("expected auto-generated name to be at least 10 chars, got '%s' (%d chars)", km.Name, len(km.Name))
	}
}

// TestBindKeyMaker_InvalidJSON tests binding with invalid JSON body.
func TestBindKeyMaker_InvalidJSON(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("POST", "/api/v1/keymakers/bind", bytes.NewBufferString("not valid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestDeleteInvite_Success tests successful deletion of an invite code.
func TestDeleteInvite_Success(t *testing.T) {
	t.Log("Setting up test server and creating test data")
	server, mux := setupTestServer(t)

	// Create a tenant
	t.Log("Creating test tenant")
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator
	t.Log("Creating test operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "nelson@acme.com", "Nelson"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Generate and store invite code
	t.Log("Creating invite code to be deleted")
	inviteCode := store.GenerateInviteCode("ACME")
	codeHash := store.HashInviteCode(inviteCode)
	inviteID := uuid.New().String()[:8]
	invite := &store.InviteCode{
		ID:            inviteID,
		CodeHash:      codeHash,
		OperatorEmail: "nelson@acme.com",
		TenantID:      tenantID,
		Role:          "admin",
		CreatedBy:     "system",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Status:        "pending",
	}
	if err := server.store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Verify invite exists before deletion
	t.Log("Verifying invite code exists before deletion")
	_, err := server.store.GetInviteCodeByHash(codeHash)
	if err != nil {
		t.Fatalf("invite code should exist before deletion: %v", err)
	}

	// Delete the invite
	t.Log("Sending DELETE request to /api/v1/invites/{code}")
	req := httptest.NewRequest("DELETE", "/api/v1/invites/"+inviteCode, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Log("Verifying response status is 204 No Content")
	if w.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify invite is deleted
	t.Log("Verifying invite code no longer exists in database")
	_, err = server.store.GetInviteCodeByHash(codeHash)
	if err == nil {
		t.Error("expected invite to be deleted, but it still exists")
	}
}

// TestDeleteInvite_NotFound tests deletion of a nonexistent invite code.
func TestDeleteInvite_NotFound(t *testing.T) {
	t.Log("Setting up test server")
	_, mux := setupTestServer(t)

	// Try to delete a nonexistent invite code
	t.Log("Sending DELETE request for nonexistent invite code")
	req := httptest.NewRequest("DELETE", "/api/v1/invites/FAKE-1234-5678", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Log("Verifying response status is 404 Not Found")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error message")
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] != "Invite code not found" {
		t.Errorf("expected error 'Invite code not found', got '%s'", result["error"])
	}
}
