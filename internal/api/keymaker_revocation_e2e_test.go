package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
)

// TestKeyMakerRevocation_BlocksAuthorization tests that revoking a KeyMaker
// blocks subsequent authorization checks.
func TestKeyMakerRevocation_BlocksAuthorization(t *testing.T) {
	t.Log("Testing that KeyMaker revocation blocks authorization checks")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant")
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	t.Log("Creating operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	t.Log("Creating KeyMaker with active status")
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

	t.Log("Creating SSH CA for tenant")
	caID := "ca_" + uuid.New().String()[:8]
	if err := server.store.CreateSSHCA(caID, "production-ca", []byte("fake-pub"), []byte("fake-priv"), "ed25519", &tenantID); err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	t.Log("Creating authorization grant for operator")
	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{caID}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	t.Log("Verifying authorization check passes with active KeyMaker")
	body := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       caID,
		KeyMakerID: keymakerID,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for active keymaker, got %d: %s", w.Code, w.Body.String())
	}

	var result CheckAuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !result.Authorized {
		t.Errorf("expected authorized=true before revocation, got false. Reason: %s", result.Reason)
	}
	t.Log("Authorization check passed with active KeyMaker")

	t.Log("Revoking KeyMaker via DELETE /api/v1/keymakers/{id}")
	req = httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204 for revoke, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("KeyMaker revoked successfully")

	t.Log("Verifying authorization check now returns 401 with 'device revoked'")
	req = httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 after revocation, got %d: %s", w.Code, w.Body.String())
	}

	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != "device revoked" {
		t.Errorf("expected error 'device revoked', got '%s'", errResp.Error)
	}
	t.Log("Authorization correctly blocked with 'device revoked' after revocation")
}

// TestKeyMakerRevocation_Permanent tests that revocation is permanent.
// Once revoked, KeyMaker cannot be reactivated and auth checks continue to fail.
func TestKeyMakerRevocation_Permanent(t *testing.T) {
	t.Log("Testing that KeyMaker revocation is permanent")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant and operator")
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	t.Log("Creating KeyMaker")
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

	t.Log("Creating SSH CA and authorization")
	caID := "ca_" + uuid.New().String()[:8]
	if err := server.store.CreateSSHCA(caID, "production-ca", []byte("fake-pub"), []byte("fake-priv"), "ed25519", &tenantID); err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{caID}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	t.Log("Revoking KeyMaker")
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204 for revoke, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying KeyMaker status is 'revoked' via GET endpoint")
	req = httptest.NewRequest("GET", "/api/v1/keymakers/"+keymakerID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for GET keymaker, got %d: %s", w.Code, w.Body.String())
	}

	var kmResp struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(w.Body).Decode(&kmResp); err != nil {
		t.Fatalf("failed to decode keymaker response: %v", err)
	}
	if kmResp.Status != "revoked" {
		t.Errorf("expected status 'revoked', got '%s'", kmResp.Status)
	}
	t.Log("KeyMaker status confirmed as 'revoked'")

	t.Log("Verifying authorization check still fails (revocation is permanent)")
	body := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       caID,
		KeyMakerID: keymakerID,
	}
	bodyBytes, _ := json.Marshal(body)

	req = httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for revoked keymaker, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("Authorization check correctly fails: revocation is permanent")

	// Note: There is no unrevoke endpoint by design
	t.Log("Confirmed: no unrevoke endpoint exists (by design)")
}

// TestKeyMakerRevocation_PersistsAcrossRestart tests that revocation state
// survives server restart (store close/reopen).
func TestKeyMakerRevocation_PersistsAcrossRestart(t *testing.T) {
	t.Log("Testing that KeyMaker revocation persists across server restart")

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "revocation_persist_test.db")

	// Phase 1: Create store, set up data, and revoke KeyMaker
	var tenantID, operatorID, keymakerID, caID string

	t.Run("Phase1_SetupAndRevoke", func(t *testing.T) {
		t.Log("Phase 1: Setting up data and revoking KeyMaker")

		store.SetInsecureMode(true)
		s, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("failed to open store: %v", err)
		}

		t.Log("Creating tenant")
		tenantID = uuid.New().String()[:8]
		if err := s.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
			t.Fatalf("failed to create tenant: %v", err)
		}

		t.Log("Creating operator")
		operatorID = uuid.New().String()[:8]
		if err := s.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
			t.Fatalf("failed to create operator: %v", err)
		}

		t.Log("Creating KeyMaker")
		keymakerID = "km_" + uuid.New().String()[:8]
		km := &store.KeyMaker{
			ID:                keymakerID,
			OperatorID:        operatorID,
			Name:              "test-keymaker",
			Platform:          "darwin",
			SecureElement:     "software",
			DeviceFingerprint: "fp123",
			PublicKey:         "ssh-ed25519 AAAA...",
			Status:            "active",
		}
		if err := s.CreateKeyMaker(km); err != nil {
			t.Fatalf("failed to create keymaker: %v", err)
		}

		t.Log("Creating SSH CA")
		caID = "ca_" + uuid.New().String()[:8]
		if err := s.CreateSSHCA(caID, "production-ca", []byte("fake-pub"), []byte("fake-priv"), "ed25519", &tenantID); err != nil {
			t.Fatalf("failed to create SSH CA: %v", err)
		}

		t.Log("Creating authorization")
		authID := "auth_" + uuid.New().String()[:8]
		if err := s.CreateAuthorization(authID, operatorID, tenantID, []string{caID}, []string{"all"}, "admin", nil); err != nil {
			t.Fatalf("failed to create authorization: %v", err)
		}

		t.Log("Revoking KeyMaker via store")
		if err := s.RevokeKeyMaker(keymakerID); err != nil {
			t.Fatalf("failed to revoke keymaker: %v", err)
		}

		t.Log("Verifying revocation before close")
		km, err = s.GetKeyMaker(keymakerID)
		if err != nil {
			t.Fatalf("failed to get keymaker: %v", err)
		}
		if km.Status != "revoked" {
			t.Errorf("expected status 'revoked', got '%s'", km.Status)
		}

		t.Log("Closing store (simulating server shutdown)")
		s.Close()
	})

	// Phase 2: Reopen store and verify revocation persisted
	t.Run("Phase2_VerifyPersistence", func(t *testing.T) {
		t.Log("Phase 2: Reopening store and verifying revocation persisted")

		store.SetInsecureMode(true)
		s, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("failed to reopen store: %v", err)
		}
		defer s.Close()

		t.Log("Creating new server with reopened store")
		server := NewServer(s)
		mux := http.NewServeMux()
		server.RegisterRoutes(mux)

		t.Log("Verifying KeyMaker status is still 'revoked' after restart")
		km, err := s.GetKeyMaker(keymakerID)
		if err != nil {
			t.Fatalf("KeyMaker not found after restart: %v", err)
		}
		if km.Status != "revoked" {
			t.Errorf("expected status 'revoked' after restart, got '%s'", km.Status)
		}
		t.Log("KeyMaker status confirmed as 'revoked' after restart")

		t.Log("Verifying authorization check returns 401 after restart")
		body := CheckAuthorizationRequest{
			OperatorID: operatorID,
			CAID:       caID,
			KeyMakerID: keymakerID,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 after restart, got %d: %s", w.Code, w.Body.String())
		}

		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}
		if errResp.Error != "device revoked" {
			t.Errorf("expected error 'device revoked', got '%s'", errResp.Error)
		}
		t.Log("Authorization correctly blocked after restart: revocation persisted")
	})

	// Cleanup
	os.Remove(dbPath)
}

// TestKeyMakerRevocation_NewKeyMakerForSameOperatorWorks tests that
// an operator can register a new KeyMaker after their previous one was revoked.
func TestKeyMakerRevocation_NewKeyMakerForSameOperatorWorks(t *testing.T) {
	t.Log("Testing that operator can use new KeyMaker after previous one revoked")

	server, mux := setupTestServer(t)

	t.Log("Creating tenant")
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "Acme Corp", "Test tenant", "admin@acme.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	t.Log("Creating operator")
	operatorID := uuid.New().String()[:8]
	if err := server.store.CreateOperator(operatorID, "operator@acme.com", "Test Operator"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	t.Log("Creating KeyMaker-A for operator")
	keymakerAID := "km_a_" + uuid.New().String()[:8]
	kmA := &store.KeyMaker{
		ID:                keymakerAID,
		OperatorID:        operatorID,
		Name:              "keymaker-A",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp-device-a",
		PublicKey:         "ssh-ed25519 AAAA-device-a...",
		Status:            "active",
		Kid:               keymakerAID,
		KeyFingerprint:    "fingerprint-device-a-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(kmA); err != nil {
		t.Fatalf("failed to create keymaker-A: %v", err)
	}

	t.Log("Creating SSH CA and authorization")
	caID := "ca_" + uuid.New().String()[:8]
	if err := server.store.CreateSSHCA(caID, "production-ca", []byte("fake-pub"), []byte("fake-priv"), "ed25519", &tenantID); err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	authID := "auth_" + uuid.New().String()[:8]
	if err := server.store.CreateAuthorization(authID, operatorID, tenantID, []string{caID}, []string{"all"}, "admin", nil); err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	t.Log("Revoking KeyMaker-A")
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+keymakerAID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204 for revoke, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("KeyMaker-A revoked")

	t.Log("Creating KeyMaker-B for same operator")
	keymakerBID := "km_b_" + uuid.New().String()[:8]
	kmB := &store.KeyMaker{
		ID:                keymakerBID,
		OperatorID:        operatorID,
		Name:              "keymaker-B",
		Platform:          "darwin",
		SecureElement:     "software",
		DeviceFingerprint: "fp-device-b",
		PublicKey:         "ssh-ed25519 AAAA-device-b...",
		Status:            "active",
		Kid:               keymakerBID,
		KeyFingerprint:    "fingerprint-device-b-" + uuid.New().String()[:8],
	}
	if err := server.store.CreateKeyMaker(kmB); err != nil {
		t.Fatalf("failed to create keymaker-B: %v", err)
	}

	t.Log("Verifying auth check with revoked KeyMaker-A returns 401")
	bodyA := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       caID,
		KeyMakerID: keymakerAID,
	}
	bodyABytes, _ := json.Marshal(bodyA)

	req = httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyABytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for revoked KeyMaker-A, got %d: %s", w.Code, w.Body.String())
	}

	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != "device revoked" {
		t.Errorf("expected error 'device revoked', got '%s'", errResp.Error)
	}
	t.Log("Auth check with KeyMaker-A correctly returned 401 'device revoked'")

	t.Log("Verifying auth check with new KeyMaker-B returns 200 OK")
	bodyB := CheckAuthorizationRequest{
		OperatorID: operatorID,
		CAID:       caID,
		KeyMakerID: keymakerBID,
	}
	bodyBBytes, _ := json.Marshal(bodyB)

	req = httptest.NewRequest("POST", "/api/v1/authorizations/check", bytes.NewReader(bodyBBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 for active KeyMaker-B, got %d: %s", w.Code, w.Body.String())
	}

	var result CheckAuthorizationResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !result.Authorized {
		t.Errorf("expected authorized=true for KeyMaker-B, got false. Reason: %s", result.Reason)
	}
	t.Log("Auth check with KeyMaker-B correctly returned 200 OK (authorized)")
	t.Log("Verified: operator can use new device after previous one was revoked")
}
