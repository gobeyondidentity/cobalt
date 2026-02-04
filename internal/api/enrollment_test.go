package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/enrollment"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// TestEnrollInit_ValidCode tests that a valid invite code returns a challenge.
func TestEnrollInit_ValidCode(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/init with valid invite code returns challenge")

	server, mux := setupTestServer(t)

	// Setup: Create tenant and invite code
	t.Log("Creating tenant for invite code")
	if err := server.store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	t.Log("Creating invite code via InviteService")
	inviteSvc := store.NewInviteService(server.store)
	inviteResult, err := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "operator@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Make enrollment init request
	t.Log("Calling POST /api/v1/enroll/init with invite code")
	body := EnrollInitRequest{Code: inviteResult.Plaintext}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying response contains challenge and enrollment_id")
	var result EnrollInitResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Challenge == "" {
		t.Error("expected non-empty challenge")
	}
	if result.EnrollmentID == "" {
		t.Error("expected non-empty enrollment_id")
	}

	// Verify challenge is valid base64 and 32 bytes when decoded
	t.Log("Verifying challenge is valid 32-byte base64 string")
	challengeBytes, err := base64.StdEncoding.DecodeString(result.Challenge)
	if err != nil {
		t.Fatalf("challenge is not valid base64: %v", err)
	}
	if len(challengeBytes) != enrollment.ChallengeSize {
		t.Errorf("expected challenge to be %d bytes, got %d", enrollment.ChallengeSize, len(challengeBytes))
	}

	// Verify enrollment_id starts with "enroll_"
	t.Log("Verifying enrollment_id has correct prefix")
	if len(result.EnrollmentID) < 8 || result.EnrollmentID[:7] != "enroll_" {
		t.Errorf("expected enrollment_id to start with 'enroll_', got %s", result.EnrollmentID)
	}
}

// TestEnrollInit_InvalidCode tests that an invalid invite code returns 401.
func TestEnrollInit_InvalidCode(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/init with invalid code returns 401")

	_, mux := setupTestServer(t)

	// Make enrollment init request with invalid code
	t.Log("Calling POST /api/v1/enroll/init with invalid code")
	body := EnrollInitRequest{Code: "invalid-code-that-does-not-exist"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains enroll.invalid_code")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeInvalidCode {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeInvalidCode, errResp["error"])
	}
}

// TestEnrollInit_ExpiredCode tests that an expired invite code returns 401.
func TestEnrollInit_ExpiredCode(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/init with expired code returns 401")

	server, mux := setupTestServer(t)

	// Setup: Create tenant and invite code with very short TTL
	t.Log("Creating tenant and invite code with 1ms TTL")
	if err := server.store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	inviteSvc := store.NewInviteService(server.store)
	inviteResult, err := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "operator@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Wait for expiration
	t.Log("Waiting for code to expire")
	time.Sleep(10 * time.Millisecond)

	// Make enrollment init request
	t.Log("Calling POST /api/v1/enroll/init with expired code")
	body := EnrollInitRequest{Code: inviteResult.Plaintext}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains enroll.expired_code")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeExpiredCode {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeExpiredCode, errResp["error"])
	}
}

// TestEnrollInit_ConsumedCode tests that an already consumed invite code returns 401.
func TestEnrollInit_ConsumedCode(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/init with consumed code returns 401")

	server, mux := setupTestServer(t)

	// Setup: Create tenant and invite code
	t.Log("Creating tenant and invite code")
	if err := server.store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	inviteSvc := store.NewInviteService(server.store)
	inviteResult, err := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "operator@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Consume the code
	t.Log("Consuming the invite code")
	_, err = inviteSvc.ConsumeInviteCode(inviteResult.Plaintext, "km_someone")
	if err != nil {
		t.Fatalf("failed to consume invite code: %v", err)
	}

	// Make enrollment init request
	t.Log("Calling POST /api/v1/enroll/init with consumed code")
	body := EnrollInitRequest{Code: inviteResult.Plaintext}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains enroll.code_consumed")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeCodeConsumed {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeCodeConsumed, errResp["error"])
	}
}

// TestEnrollComplete_OperatorSession tests the full operator enrollment flow.
func TestEnrollComplete_OperatorSession(t *testing.T) {
	t.Log("Testing full operator enrollment flow: POST /api/v1/enroll/init -> POST /api/v1/enroll/complete")

	server, mux := setupTestServer(t)

	// Setup: Create tenant and invite code
	t.Log("Creating tenant and invite code")
	if err := server.store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	inviteSvc := store.NewInviteService(server.store)
	inviteResult, err := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "operator@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Generate Ed25519 key pair
	t.Log("Generating Ed25519 key pair")
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Step 1: Enrollment init request
	t.Log("Step 1: Making enrollment init request")
	initBody := EnrollInitRequest{Code: inviteResult.Plaintext}
	initBodyBytes, _ := json.Marshal(initBody)
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(initBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("enrollment init failed: %d: %s", w.Code, w.Body.String())
	}

	var initResp EnrollInitResponse
	json.NewDecoder(w.Body).Decode(&initResp)

	// Step 2: Sign the challenge
	t.Log("Step 2: Signing the challenge with private key")
	challengeBytes, _ := base64.StdEncoding.DecodeString(initResp.Challenge)
	signature := ed25519.Sign(privKey, challengeBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Step 3: Complete enrollment
	t.Log("Step 3: Completing enrollment with signed challenge")
	completeBody := EnrollCompleteRequest{
		EnrollmentID:    initResp.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: signatureB64,
	}
	completeBodyBytes, _ := json.Marshal(completeBody)
	req = httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("enroll complete failed: %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying enrollment complete response")
	var completeResp EnrollCompleteResponse
	if err := json.NewDecoder(w.Body).Decode(&completeResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify keymaker ID format
	t.Log("Verifying keymaker ID starts with 'km_'")
	if len(completeResp.ID) < 3 || completeResp.ID[:3] != "km_" {
		t.Errorf("expected keymaker ID to start with 'km_', got %s", completeResp.ID)
	}

	// Verify fingerprint is SHA256 hex of public key
	t.Log("Verifying fingerprint matches SHA256 of public key")
	expectedHash := sha256.Sum256(pubKey)
	expectedFingerprint := hex.EncodeToString(expectedHash[:])
	if completeResp.Fingerprint != expectedFingerprint {
		t.Errorf("expected fingerprint %s, got %s", expectedFingerprint, completeResp.Fingerprint)
	}

	// Verify operator context is returned in response
	t.Log("Verifying operator context fields in response")
	if completeResp.OperatorEmail != "operator@example.com" {
		t.Errorf("expected operator_email 'operator@example.com', got %q", completeResp.OperatorEmail)
	}
	if completeResp.TenantName != "Test Tenant" {
		t.Errorf("expected tenant_name 'Test Tenant', got %q", completeResp.TenantName)
	}
	if completeResp.TenantRole != "operator" {
		t.Errorf("expected tenant_role 'operator', got %q", completeResp.TenantRole)
	}

	// Verify keymaker was created in database
	t.Log("Verifying keymaker was stored in database")
	km, err := server.store.GetKeyMaker(completeResp.ID)
	if err != nil {
		t.Fatalf("failed to get keymaker: %v", err)
	}
	if km.Status != "active" {
		t.Errorf("expected keymaker status 'active', got '%s'", km.Status)
	}

	// Verify operator was created and activated
	t.Log("Verifying operator was created")
	op, err := server.store.GetOperatorByEmail("operator@example.com")
	if err != nil {
		t.Fatalf("failed to get operator: %v", err)
	}
	if op.Status != "active" {
		t.Errorf("expected operator status 'active', got '%s'", op.Status)
	}

	// Verify enrollment session was deleted
	t.Log("Verifying enrollment session was deleted")
	session, err := server.store.GetEnrollmentSession(initResp.EnrollmentID)
	if err != nil {
		t.Fatalf("unexpected error checking session: %v", err)
	}
	if session != nil {
		t.Error("expected enrollment session to be deleted after completion")
	}
}

// TestEnrollComplete_DuplicateFingerprint tests that duplicate key fingerprints return 409.
func TestEnrollComplete_DuplicateFingerprint(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/complete with duplicate key fingerprint returns 409")

	server, mux := setupTestServer(t)

	// Setup: Create tenant and two invite codes
	t.Log("Creating tenant and two invite codes")
	if err := server.store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	inviteSvc := store.NewInviteService(server.store)

	// First invite code
	inviteResult1, err := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "operator1@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create first invite code: %v", err)
	}

	// Second invite code
	inviteResult2, err := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "operator2@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create second invite code: %v", err)
	}

	// Generate Ed25519 key pair (will use same key for both)
	t.Log("Generating Ed25519 key pair (same key for both enrollments)")
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Complete first enrollment
	t.Log("Completing first enrollment")
	initBody1 := EnrollInitRequest{Code: inviteResult1.Plaintext}
	initBodyBytes1, _ := json.Marshal(initBody1)
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(initBodyBytes1))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first enrollment init failed: %d: %s", w.Code, w.Body.String())
	}

	var initResp1 EnrollInitResponse
	json.NewDecoder(w.Body).Decode(&initResp1)

	challengeBytes1, _ := base64.StdEncoding.DecodeString(initResp1.Challenge)
	signature1 := ed25519.Sign(privKey, challengeBytes1)
	signatureB641 := base64.StdEncoding.EncodeToString(signature1)

	completeBody1 := EnrollCompleteRequest{
		EnrollmentID:    initResp1.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: signatureB641,
	}
	completeBodyBytes1, _ := json.Marshal(completeBody1)
	req = httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBodyBytes1))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first enroll complete failed: %d: %s", w.Code, w.Body.String())
	}

	// Attempt second enrollment with same key
	t.Log("Attempting second enrollment with same key (should fail)")
	initBody2 := EnrollInitRequest{Code: inviteResult2.Plaintext}
	initBodyBytes2, _ := json.Marshal(initBody2)
	req = httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(initBodyBytes2))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("second enrollment init failed: %d: %s", w.Code, w.Body.String())
	}

	var initResp2 EnrollInitResponse
	json.NewDecoder(w.Body).Decode(&initResp2)

	challengeBytes2, _ := base64.StdEncoding.DecodeString(initResp2.Challenge)
	signature2 := ed25519.Sign(privKey, challengeBytes2)
	signatureB642 := base64.StdEncoding.EncodeToString(signature2)

	completeBody2 := EnrollCompleteRequest{
		EnrollmentID:    initResp2.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: signatureB642,
	}
	completeBodyBytes2, _ := json.Marshal(completeBody2)
	req = httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBodyBytes2))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains enroll.key_exists")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeKeyExists {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeKeyExists, errResp["error"])
	}
}

// TestEnrollComplete_OperatorInvalidSignature tests that invalid signature in operator flow returns 401.
func TestEnrollComplete_OperatorInvalidSignature(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/complete (operator) with invalid signature returns 401")

	server, mux := setupTestServer(t)

	// Setup: Create tenant and invite code
	t.Log("Creating tenant and invite code")
	if err := server.store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	inviteSvc := store.NewInviteService(server.store)
	inviteResult, err := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "operator@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create invite code: %v", err)
	}

	// Generate Ed25519 key pairs (one to submit, one to sign with)
	t.Log("Generating two Ed25519 key pairs")
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)
	_, wrongPrivKey, _ := ed25519.GenerateKey(rand.Reader)

	// Enrollment init request
	t.Log("Making enrollment init request")
	initBody := EnrollInitRequest{Code: inviteResult.Plaintext}
	initBodyBytes, _ := json.Marshal(initBody)
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(initBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("enrollment init failed: %d: %s", w.Code, w.Body.String())
	}

	var initResp EnrollInitResponse
	json.NewDecoder(w.Body).Decode(&initResp)

	// Sign with wrong key
	t.Log("Signing challenge with wrong private key")
	challengeBytes, _ := base64.StdEncoding.DecodeString(initResp.Challenge)
	wrongSignature := ed25519.Sign(wrongPrivKey, challengeBytes)
	wrongSignatureB64 := base64.StdEncoding.EncodeToString(wrongSignature)

	// Complete enrollment with wrong signature
	t.Log("Calling POST /api/v1/enroll/complete with wrong signature")
	completeBody := EnrollCompleteRequest{
		EnrollmentID:    initResp.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: wrongSignatureB64,
	}
	completeBodyBytes, _ := json.Marshal(completeBody)
	req = httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains enroll.invalid_signature")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeInvalidSignature {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeInvalidSignature, errResp["error"])
	}
}

// TestEnrollInit_MissingCode tests that missing code field returns 400.
func TestEnrollInit_MissingCode(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/init with missing code returns 400")

	_, mux := setupTestServer(t)

	// Make enrollment init request without code field
	t.Log("Calling POST /api/v1/enroll/init with empty code")
	body := EnrollInitRequest{Code: ""}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestEnrollInit_InvalidJSON tests that invalid JSON returns 400.
func TestEnrollInit_InvalidJSON(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/init with invalid JSON returns 400")

	_, mux := setupTestServer(t)

	// Make enrollment init request with invalid JSON
	t.Log("Calling POST /api/v1/enroll/init with invalid JSON")
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewBufferString("not-valid-json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}
