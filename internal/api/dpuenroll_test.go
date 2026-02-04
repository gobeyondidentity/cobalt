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

// TestDPUEnrollInit_Success tests that DPU enrollment init returns a challenge.
func TestDPUEnrollInit_Success(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/dpu/init with registered DPU serial returns challenge")

	server, mux := setupTestServer(t)

	// Setup: Register a DPU with pending status and set its serial number
	t.Log("Registering DPU with serial number and setting enrollment expiration")
	err := server.store.Add("dpu1", "bf3-test", "192.168.1.100", 50051)
	if err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}

	// Set serial number
	err = server.store.SetDPUSerialNumber("dpu1", "MLX-BF3-SN12345")
	if err != nil {
		t.Fatalf("failed to set serial number: %v", err)
	}

	// Set enrollment expiration to future (DPU is in registration window)
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	_, err = server.store.DB().Exec(`UPDATE dpus SET status = 'pending', enrollment_expires_at = ? WHERE id = ?`, expiresAt, "dpu1")
	if err != nil {
		t.Fatalf("failed to set enrollment expiration: %v", err)
	}

	// Make init request with serial number
	t.Log("Calling POST /api/v1/enroll/dpu/init with serial number")
	body := map[string]string{"serial": "MLX-BF3-SN12345"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying response contains challenge and enrollment_id")
	var result DPUEnrollInitResponse
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

	// Verify enrollment session was created with dpu session type
	t.Log("Verifying enrollment session was created with SessionType='dpu'")
	session, err := server.store.GetEnrollmentSession(result.EnrollmentID)
	if err != nil {
		t.Fatalf("failed to get enrollment session: %v", err)
	}
	if session == nil {
		t.Fatal("expected enrollment session to be created")
	}
	if session.SessionType != "dpu" {
		t.Errorf("expected session type 'dpu', got '%s'", session.SessionType)
	}
	if session.DPUID == nil || *session.DPUID != "dpu1" {
		t.Errorf("expected session DPUID 'dpu1', got %v", session.DPUID)
	}
}

// TestDPUEnrollInit_UnknownSerial tests that unknown serial returns 404.
func TestDPUEnrollInit_UnknownSerial(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/dpu/init with unknown serial returns 404")

	_, mux := setupTestServer(t)

	t.Log("Calling POST /api/v1/enroll/dpu/init with non-existent serial")
	body := map[string]string{"serial": "UNKNOWN-SERIAL-123"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error message indicates DPU not registered")
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] == "" {
		t.Error("expected error message in response")
	}
}

// TestDPUEnrollInit_AlreadyEnrolled tests that already-enrolled DPU returns 409.
func TestDPUEnrollInit_AlreadyEnrolled(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/dpu/init with already-enrolled DPU returns 409")

	server, mux := setupTestServer(t)

	// Setup: Register a DPU with 'active' status (already enrolled)
	t.Log("Registering DPU with 'active' status (already enrolled)")
	err := server.store.Add("dpu1", "bf3-enrolled", "192.168.1.100", 50051)
	if err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}
	err = server.store.SetDPUSerialNumber("dpu1", "MLX-BF3-ENROLLED")
	if err != nil {
		t.Fatalf("failed to set serial number: %v", err)
	}
	// Set status to 'active' (enrolled)
	_, err = server.store.DB().Exec(`UPDATE dpus SET status = 'active' WHERE id = ?`, "dpu1")
	if err != nil {
		t.Fatalf("failed to set DPU status: %v", err)
	}

	t.Log("Calling POST /api/v1/enroll/dpu/init with already-enrolled DPU")
	body := map[string]string{"serial": "MLX-BF3-ENROLLED"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error message indicates conflict")
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] == "" {
		t.Error("expected error message in response")
	}
}

// TestDPUEnrollInit_ExpiredRegistration tests that expired registration window returns 401.
func TestDPUEnrollInit_ExpiredRegistration(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/dpu/init with expired registration returns 401 enroll.expired_code")

	server, mux := setupTestServer(t)

	// Setup: Register a DPU with expired enrollment window
	t.Log("Registering DPU with expired enrollment window")
	err := server.store.Add("dpu1", "bf3-expired", "192.168.1.100", 50051)
	if err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}
	err = server.store.SetDPUSerialNumber("dpu1", "MLX-BF3-EXPIRED")
	if err != nil {
		t.Fatalf("failed to set serial number: %v", err)
	}
	// Set enrollment expiration to past (registration window expired)
	expiredTime := time.Now().Add(-1 * time.Hour).Unix()
	_, err = server.store.DB().Exec(`UPDATE dpus SET status = 'pending', enrollment_expires_at = ? WHERE id = ?`, expiredTime, "dpu1")
	if err != nil {
		t.Fatalf("failed to set enrollment expiration: %v", err)
	}

	t.Log("Calling POST /api/v1/enroll/dpu/init with expired registration")
	body := map[string]string{"serial": "MLX-BF3-EXPIRED"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error code is enroll.expired_code")
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] != enrollment.ErrCodeExpiredCode {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeExpiredCode, result["error"])
	}
}

// TestDPUEnrollInit_EmptySerial tests that empty serial returns 400.
func TestDPUEnrollInit_EmptySerial(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/dpu/init with empty serial returns 400")

	_, mux := setupTestServer(t)

	t.Log("Calling POST /api/v1/enroll/dpu/init with empty serial")
	body := map[string]string{"serial": ""}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestDPUEnrollComplete_Success tests the full DPU enrollment flow.
func TestDPUEnrollComplete_Success(t *testing.T) {
	t.Log("Testing full DPU enrollment flow: POST /api/v1/enroll/dpu/init -> POST /api/v1/enroll/complete")

	server, mux := setupTestServer(t)

	// Setup: Register a DPU with pending status
	t.Log("Registering DPU with pending status")
	err := server.store.Add("dpu1", "bf3-enroll-test", "192.168.1.100", 50051)
	if err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}
	err = server.store.SetDPUSerialNumber("dpu1", "MLX-BF3-ENROLL-TEST")
	if err != nil {
		t.Fatalf("failed to set serial number: %v", err)
	}
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	_, err = server.store.DB().Exec(`UPDATE dpus SET status = 'pending', enrollment_expires_at = ? WHERE id = ?`, expiresAt, "dpu1")
	if err != nil {
		t.Fatalf("failed to set enrollment expiration: %v", err)
	}

	// Step 1: Init enrollment
	t.Log("Step 1: Making DPU enrollment init request")
	initBody := map[string]string{"serial": "MLX-BF3-ENROLL-TEST"}
	initBodyBytes, _ := json.Marshal(initBody)
	req := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(initBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("init failed: %d: %s", w.Code, w.Body.String())
	}

	var initResp DPUEnrollInitResponse
	json.NewDecoder(w.Body).Decode(&initResp)

	// Step 2: Generate key pair and sign challenge
	t.Log("Step 2: Generating Ed25519 key pair and signing challenge")
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

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
		t.Fatalf("complete failed: %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying enrollment complete response")
	var completeResp EnrollCompleteResponse
	if err := json.NewDecoder(w.Body).Decode(&completeResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify DPU ID format
	t.Log("Verifying DPU ID starts with 'dpu_'")
	if len(completeResp.ID) < 4 || completeResp.ID[:4] != "dpu_" {
		t.Errorf("expected DPU ID to start with 'dpu_', got %s", completeResp.ID)
	}

	// Verify fingerprint is SHA256 hex of public key
	t.Log("Verifying fingerprint matches SHA256 of public key")
	expectedHash := sha256.Sum256(pubKey)
	expectedFingerprint := hex.EncodeToString(expectedHash[:])
	if completeResp.Fingerprint != expectedFingerprint {
		t.Errorf("expected fingerprint %s, got %s", expectedFingerprint, completeResp.Fingerprint)
	}

	// Verify DPU status is now 'active'
	t.Log("Verifying DPU status is now 'active'")
	dpu, err := server.store.Get("dpu1")
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.Status != "active" {
		t.Errorf("expected DPU status 'active', got '%s'", dpu.Status)
	}

	// Verify DPU has kid and fingerprint set
	t.Log("Verifying DPU has kid and fingerprint set")
	if dpu.Kid == nil || *dpu.Kid != completeResp.ID {
		t.Errorf("expected DPU kid to be '%s', got %v", completeResp.ID, dpu.Kid)
	}
	if dpu.KeyFingerprint == nil || *dpu.KeyFingerprint != completeResp.Fingerprint {
		t.Errorf("expected DPU fingerprint to be '%s', got %v", completeResp.Fingerprint, dpu.KeyFingerprint)
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

// TestDPUEnrollComplete_DuplicateKey tests that duplicate fingerprint returns 409.
func TestDPUEnrollComplete_DuplicateKey(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/complete with duplicate key fingerprint returns 409")

	server, mux := setupTestServer(t)

	// Setup: Create two DPUs
	t.Log("Registering two DPUs")
	for _, dpuID := range []string{"dpu1", "dpu2"} {
		err := server.store.Add(dpuID, "bf3-"+dpuID, "192.168.1.100", 50051)
		if err != nil {
			t.Fatalf("failed to add DPU: %v", err)
		}
		err = server.store.SetDPUSerialNumber(dpuID, "SERIAL-"+dpuID)
		if err != nil {
			t.Fatalf("failed to set serial number: %v", err)
		}
		expiresAt := time.Now().Add(24 * time.Hour).Unix()
		_, err = server.store.DB().Exec(`UPDATE dpus SET status = 'pending', enrollment_expires_at = ? WHERE id = ?`, expiresAt, dpuID)
		if err != nil {
			t.Fatalf("failed to set enrollment expiration: %v", err)
		}
	}

	// Generate a shared key pair (to simulate duplicate)
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Enroll first DPU
	t.Log("Enrolling first DPU")
	initBody := map[string]string{"serial": "SERIAL-dpu1"}
	initBodyBytes, _ := json.Marshal(initBody)
	req := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(initBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var initResp DPUEnrollInitResponse
	json.NewDecoder(w.Body).Decode(&initResp)

	challengeBytes, _ := base64.StdEncoding.DecodeString(initResp.Challenge)
	signature := ed25519.Sign(privKey, challengeBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

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
		t.Fatalf("first enrollment failed: %d: %s", w.Code, w.Body.String())
	}

	// Try to enroll second DPU with same key
	t.Log("Attempting to enroll second DPU with same key")
	initBody = map[string]string{"serial": "SERIAL-dpu2"}
	initBodyBytes, _ = json.Marshal(initBody)
	req = httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(initBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&initResp)

	challengeBytes, _ = base64.StdEncoding.DecodeString(initResp.Challenge)
	signature = ed25519.Sign(privKey, challengeBytes)
	signatureB64 = base64.StdEncoding.EncodeToString(signature)

	completeBody = EnrollCompleteRequest{
		EnrollmentID:    initResp.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: signatureB64,
	}
	completeBodyBytes, _ = json.Marshal(completeBody)
	req = httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying error code is enroll.key_exists")
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["error"] != enrollment.ErrCodeKeyExists {
		t.Errorf("expected error code %s, got %s", enrollment.ErrCodeKeyExists, result["error"])
	}
}

// TestDPUEnrollComplete_MissingDPUID tests DPU enrollment with missing session DPUID.
func TestDPUEnrollComplete_MissingDPUID(t *testing.T) {
	t.Log("Testing POST /api/v1/enroll/complete with DPU session missing DPUID returns error")

	server, mux := setupTestServer(t)

	// Create a DPU enrollment session manually without DPUID
	t.Log("Creating DPU enrollment session without DPUID")
	challenge := make([]byte, 32)
	rand.Read(challenge)
	challengeHex := hex.EncodeToString(challenge)

	session := &store.EnrollmentSession{
		ID:            "enroll_nodpuid",
		SessionType:   "dpu",
		ChallengeBytesHex: challengeHex,
		DPUID:         nil, // Missing DPUID
		IPAddress:     "127.0.0.1",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	err := server.store.CreateEnrollmentSession(session)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Try to complete with the session
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	signature := ed25519.Sign(privKey, challenge)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	completeBody := EnrollCompleteRequest{
		EnrollmentID:    "enroll_nodpuid",
		PublicKey:       pubKeyB64,
		SignedChallenge: signatureB64,
	}
	completeBodyBytes, _ := json.Marshal(completeBody)
	req := httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Should fail because DPUID is missing
	if w.Code == http.StatusOK {
		t.Error("expected enrollment to fail for session missing DPUID, but it succeeded")
	}
	t.Logf("Got expected error status: %d", w.Code)
}
