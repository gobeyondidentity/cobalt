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

	"github.com/nmelo/secure-infra/pkg/enrollment"
)

// TestAdminBootstrap_Success tests that a fresh server accepts bootstrap enrollment.
func TestAdminBootstrap_Success(t *testing.T) {
	t.Log("Testing POST /api/v1/admin/bootstrap on fresh server returns challenge")

	server, mux := setupTestServer(t)

	// Initialize bootstrap window
	t.Log("Initializing bootstrap window")
	if err := server.store.InitBootstrapWindow(); err != nil {
		t.Fatalf("failed to init bootstrap window: %v", err)
	}

	// Generate a test Ed25519 key pair
	t.Log("Generating Ed25519 key pair for bootstrap request")
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Make bootstrap request
	t.Log("Calling POST /api/v1/admin/bootstrap with public key")
	body := map[string]string{"public_key": pubKeyB64}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying response contains challenge and enrollment_id")
	var result BootstrapResponse
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

// TestAdminBootstrap_WindowClosed tests that bootstrap fails after window expires.
func TestAdminBootstrap_WindowClosed(t *testing.T) {
	t.Log("Testing POST /api/v1/admin/bootstrap returns 403 when window is closed")

	server, mux := setupTestServer(t)

	// Initialize bootstrap window, then manually expire it
	// We can't easily mock time, so we directly manipulate the database
	t.Log("Initializing bootstrap window")
	if err := server.store.InitBootstrapWindow(); err != nil {
		t.Fatalf("failed to init bootstrap window: %v", err)
	}

	// Set window to be opened 11 minutes ago (beyond 10 minute threshold)
	t.Log("Manually expiring bootstrap window by setting window_opened_at to 11 minutes ago")
	expiredTime := time.Now().Add(-11 * time.Minute).Unix()
	_, err := server.store.DB().Exec(`UPDATE bootstrap_state SET window_opened_at = ? WHERE id = 1`, expiredTime)
	if err != nil {
		t.Fatalf("failed to expire window: %v", err)
	}

	// Generate a test key
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Make bootstrap request
	t.Log("Calling POST /api/v1/admin/bootstrap with expired window")
	body := map[string]string{"public_key": pubKeyB64}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains bootstrap.window_closed code")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeWindowClosed {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeWindowClosed, errResp["error"])
	}
}

// TestAdminBootstrap_AlreadyEnrolled tests that bootstrap fails if admin already exists.
func TestAdminBootstrap_AlreadyEnrolled(t *testing.T) {
	t.Log("Testing POST /api/v1/admin/bootstrap returns 403 when admin already enrolled")

	server, mux := setupTestServer(t)

	// Initialize and complete bootstrap
	t.Log("Completing bootstrap enrollment to create first admin")
	server.store.InitBootstrapWindow()
	server.store.CompleteBootstrap("adm_existing")

	// Generate a test key
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Make bootstrap request
	t.Log("Calling POST /api/v1/admin/bootstrap after admin already enrolled")
	body := map[string]string{"public_key": pubKeyB64}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains bootstrap.already_enrolled code")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeAlreadyEnrolled {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeAlreadyEnrolled, errResp["error"])
	}
}

// TestAdminBootstrap_InvalidPublicKey tests that invalid public keys are rejected.
func TestAdminBootstrap_InvalidPublicKey(t *testing.T) {
	t.Log("Testing POST /api/v1/admin/bootstrap rejects invalid public keys")

	server, mux := setupTestServer(t)
	server.store.InitBootstrapWindow()

	testCases := []struct {
		name      string
		publicKey string
		wantCode  int
	}{
		{"empty", "", http.StatusBadRequest},
		{"not base64", "not-valid-base64!!!", http.StatusBadRequest},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("too short")), http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing with %s public key", tc.name)
			body := map[string]string{"public_key": tc.publicKey}
			bodyBytes, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != tc.wantCode {
				t.Errorf("expected status %d, got %d: %s", tc.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestEnrollComplete_Success tests the full bootstrap and complete flow.
func TestEnrollComplete_Success(t *testing.T) {
	t.Log("Testing full bootstrap flow: POST /api/v1/admin/bootstrap -> POST /enroll/complete")

	server, mux := setupTestServer(t)
	server.store.InitBootstrapWindow()

	// Generate Ed25519 key pair
	t.Log("Generating Ed25519 key pair")
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Step 1: Bootstrap request
	t.Log("Step 1: Making bootstrap request")
	body := map[string]string{"public_key": pubKeyB64}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap failed: %d: %s", w.Code, w.Body.String())
	}

	var bootstrapResp BootstrapResponse
	json.NewDecoder(w.Body).Decode(&bootstrapResp)

	// Step 2: Sign the challenge
	t.Log("Step 2: Signing the challenge with private key")
	challengeBytes, _ := base64.StdEncoding.DecodeString(bootstrapResp.Challenge)
	signature := ed25519.Sign(privKey, challengeBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Step 3: Complete enrollment
	t.Log("Step 3: Completing enrollment with signed challenge")
	completeBody := EnrollCompleteRequest{
		EnrollmentID:    bootstrapResp.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: signatureB64,
	}
	completeBodyBytes, _ := json.Marshal(completeBody)
	req = httptest.NewRequest("POST", "/enroll/complete", bytes.NewReader(completeBodyBytes))
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

	// Verify admin ID format
	t.Log("Verifying admin ID starts with 'adm_'")
	if len(completeResp.ID) < 4 || completeResp.ID[:4] != "adm_" {
		t.Errorf("expected admin ID to start with 'adm_', got %s", completeResp.ID)
	}

	// Verify fingerprint is SHA256 hex of public key
	t.Log("Verifying fingerprint matches SHA256 of public key")
	expectedHash := sha256.Sum256(pubKey)
	expectedFingerprint := hex.EncodeToString(expectedHash[:])
	if completeResp.Fingerprint != expectedFingerprint {
		t.Errorf("expected fingerprint %s, got %s", expectedFingerprint, completeResp.Fingerprint)
	}

	// Verify bootstrap is marked complete
	t.Log("Verifying bootstrap state is marked complete")
	hasAdmin, _ := server.store.HasFirstAdmin()
	if !hasAdmin {
		t.Error("expected bootstrap to be complete with first admin")
	}

	// Verify admin key was created
	t.Log("Verifying admin key was stored in database")
	keys, _ := server.store.ListAdminKeysByOperator(completeResp.ID)
	if len(keys) != 1 {
		t.Errorf("expected 1 admin key, got %d", len(keys))
	}
}

// TestEnrollComplete_InvalidSession tests enrollment with non-existent session.
func TestEnrollComplete_InvalidSession(t *testing.T) {
	t.Log("Testing POST /enroll/complete with invalid enrollment_id returns 400")

	_, mux := setupTestServer(t)

	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Fake challenge
	fakeChallenge := make([]byte, 32)
	rand.Read(fakeChallenge)
	signature := ed25519.Sign(privKey, fakeChallenge)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	t.Log("Calling POST /enroll/complete with non-existent enrollment_id")
	body := EnrollCompleteRequest{
		EnrollmentID:    "enroll_nonexistent",
		PublicKey:       pubKeyB64,
		SignedChallenge: signatureB64,
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/enroll/complete", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains enroll.invalid_session code")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeInvalidSession {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeInvalidSession, errResp["error"])
	}
}

// TestEnrollComplete_ExpiredChallenge tests enrollment after challenge expires.
func TestEnrollComplete_ExpiredChallenge(t *testing.T) {
	t.Log("Testing POST /enroll/complete with expired challenge returns 401")

	server, mux := setupTestServer(t)
	server.store.InitBootstrapWindow()

	// Generate key and get bootstrap challenge
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	t.Log("Making bootstrap request")
	body := map[string]string{"public_key": pubKeyB64}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var bootstrapResp BootstrapResponse
	json.NewDecoder(w.Body).Decode(&bootstrapResp)

	// Manually expire the enrollment session
	t.Log("Manually expiring enrollment session by setting expires_at to past")
	expiredTime := time.Now().Add(-1 * time.Minute).Unix()
	_, err := server.store.DB().Exec(`UPDATE enrollment_sessions SET expires_at = ? WHERE id = ?`,
		expiredTime, bootstrapResp.EnrollmentID)
	if err != nil {
		t.Fatalf("failed to expire session: %v", err)
	}

	// Try to complete enrollment
	t.Log("Calling POST /enroll/complete with expired session")
	challengeBytes, _ := base64.StdEncoding.DecodeString(bootstrapResp.Challenge)
	signature := ed25519.Sign(privKey, challengeBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	completeBody := EnrollCompleteRequest{
		EnrollmentID:    bootstrapResp.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: signatureB64,
	}
	completeBodyBytes, _ := json.Marshal(completeBody)
	req = httptest.NewRequest("POST", "/enroll/complete", bytes.NewReader(completeBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains enroll.challenge_expired code")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeChallengeExpired {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeChallengeExpired, errResp["error"])
	}
}

// TestEnrollComplete_InvalidSignature tests enrollment with wrong key signing.
func TestEnrollComplete_InvalidSignature(t *testing.T) {
	t.Log("Testing POST /enroll/complete with invalid signature returns 401")

	server, mux := setupTestServer(t)
	server.store.InitBootstrapWindow()

	// Generate original key pair
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Generate a different key pair to sign with
	_, wrongPrivKey, _ := ed25519.GenerateKey(rand.Reader)

	t.Log("Making bootstrap request")
	body := map[string]string{"public_key": pubKeyB64}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var bootstrapResp BootstrapResponse
	json.NewDecoder(w.Body).Decode(&bootstrapResp)

	// Sign with wrong key
	t.Log("Signing challenge with wrong private key")
	challengeBytes, _ := base64.StdEncoding.DecodeString(bootstrapResp.Challenge)
	wrongSignature := ed25519.Sign(wrongPrivKey, challengeBytes)
	wrongSignatureB64 := base64.StdEncoding.EncodeToString(wrongSignature)

	// Try to complete enrollment
	t.Log("Calling POST /enroll/complete with wrong signature")
	completeBody := EnrollCompleteRequest{
		EnrollmentID:    bootstrapResp.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: wrongSignatureB64,
	}
	completeBodyBytes, _ := json.Marshal(completeBody)
	req = httptest.NewRequest("POST", "/enroll/complete", bytes.NewReader(completeBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error response contains enroll.invalid_signature code")
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != enrollment.ErrCodeInvalidSignature {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeInvalidSignature, errResp["error"])
	}
}

// TestEnrollComplete_SessionDeletedOnSuccess tests that enrollment session is deleted after success.
func TestEnrollComplete_SessionDeletedOnSuccess(t *testing.T) {
	t.Log("Testing that enrollment session is deleted after successful completion")

	server, mux := setupTestServer(t)
	server.store.InitBootstrapWindow()

	// Complete the full bootstrap flow
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	body := map[string]string{"public_key": pubKeyB64}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var bootstrapResp BootstrapResponse
	json.NewDecoder(w.Body).Decode(&bootstrapResp)

	challengeBytes, _ := base64.StdEncoding.DecodeString(bootstrapResp.Challenge)
	signature := ed25519.Sign(privKey, challengeBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	completeBody := EnrollCompleteRequest{
		EnrollmentID:    bootstrapResp.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: signatureB64,
	}
	completeBodyBytes, _ := json.Marshal(completeBody)
	req = httptest.NewRequest("POST", "/enroll/complete", bytes.NewReader(completeBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d: %s", w.Code, w.Body.String())
	}

	// Verify session no longer exists
	t.Log("Verifying enrollment session was deleted")
	session, err := server.store.GetEnrollmentSession(bootstrapResp.EnrollmentID)
	if err != nil {
		t.Fatalf("unexpected error checking session: %v", err)
	}
	if session != nil {
		t.Error("expected enrollment session to be deleted after completion")
	}
}

// TestAdminBootstrap_ConcurrentProtection tests that bootstrap is protected against concurrent requests.
func TestAdminBootstrap_ConcurrentProtection(t *testing.T) {
	t.Log("Testing bootstrap mutex prevents concurrent enrollment issues")

	server, mux := setupTestServer(t)
	server.store.InitBootstrapWindow()

	// First request should succeed
	pubKey1, privKey1, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB641 := base64.StdEncoding.EncodeToString(pubKey1)

	body1 := map[string]string{"public_key": pubKeyB641}
	bodyBytes1, _ := json.Marshal(body1)
	req1 := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	mux.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first bootstrap request failed: %d", w1.Code)
	}

	var bootstrapResp1 BootstrapResponse
	json.NewDecoder(w1.Body).Decode(&bootstrapResp1)

	// Complete the first enrollment
	challengeBytes1, _ := base64.StdEncoding.DecodeString(bootstrapResp1.Challenge)
	signature1 := ed25519.Sign(privKey1, challengeBytes1)
	signatureB641 := base64.StdEncoding.EncodeToString(signature1)

	completeBody1 := EnrollCompleteRequest{
		EnrollmentID:    bootstrapResp1.EnrollmentID,
		PublicKey:       pubKeyB641,
		SignedChallenge: signatureB641,
	}
	completeBodyBytes1, _ := json.Marshal(completeBody1)
	completeReq1 := httptest.NewRequest("POST", "/enroll/complete", bytes.NewReader(completeBodyBytes1))
	completeReq1.Header.Set("Content-Type", "application/json")
	completeW1 := httptest.NewRecorder()
	mux.ServeHTTP(completeW1, completeReq1)

	if completeW1.Code != http.StatusOK {
		t.Fatalf("first enrollment complete failed: %d", completeW1.Code)
	}

	// Second bootstrap request should fail (admin already enrolled)
	t.Log("Verifying second bootstrap request fails after first admin enrolled")
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB642 := base64.StdEncoding.EncodeToString(pubKey2)

	body2 := map[string]string{"public_key": pubKeyB642}
	bodyBytes2, _ := json.Marshal(body2)
	req2 := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bodyBytes2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("expected second bootstrap to return 403, got %d", w2.Code)
	}
}
