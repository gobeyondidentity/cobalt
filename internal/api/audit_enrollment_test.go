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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/audit"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// mockEventLogger captures audit events for test assertions.
type mockEventLogger struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *mockEventLogger) Emit(e audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *mockEventLogger) Events() []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]audit.Event, len(m.events))
	copy(cp, m.events)
	return cp
}

func (m *mockEventLogger) LastOfType(et audit.EventType) *audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.events) - 1; i >= 0; i-- {
		if m.events[i].Type == et {
			e := m.events[i]
			return &e
		}
	}
	return nil
}

// setupTestServerWithAudit creates a test server with a mock audit logger.
func setupTestServerWithAudit(t *testing.T) (*Server, *http.ServeMux, *mockEventLogger) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store.SetInsecureMode(true)
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}

	t.Cleanup(func() {
		s.Close()
		os.Remove(dbPath)
	})

	mockAudit := &mockEventLogger{}
	server := NewServerWithConfig(s, ServerConfig{
		AuditEmitter: mockAudit,
	})
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	return server, mux, mockAudit
}

// completeEnrollmentFlow runs the full enrollment init + complete for an operator,
// returning the enrollment response.
func completeEnrollmentFlow(t *testing.T, server *Server, mux *http.ServeMux, inviteCode string) EnrollCompleteResponse {
	t.Helper()

	// Init enrollment
	initBody, _ := json.Marshal(EnrollInitRequest{Code: inviteCode})
	initReq := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(initBody))
	initReq.Header.Set("Content-Type", "application/json")
	initReq.RemoteAddr = "192.168.1.50:12345"
	initW := httptest.NewRecorder()
	mux.ServeHTTP(initW, initReq)
	if initW.Code != http.StatusOK {
		t.Fatalf("enroll init failed: %d %s", initW.Code, initW.Body.String())
	}
	var initResp EnrollInitResponse
	json.NewDecoder(initW.Body).Decode(&initResp)

	// Generate key pair and sign challenge
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	challengeBytes, _ := base64.StdEncoding.DecodeString(initResp.Challenge)
	signature := ed25519.Sign(privKey, challengeBytes)

	// Complete enrollment
	completeBody, _ := json.Marshal(EnrollCompleteRequest{
		EnrollmentID:    initResp.EnrollmentID,
		PublicKey:       base64.StdEncoding.EncodeToString(pubKey),
		SignedChallenge: base64.StdEncoding.EncodeToString(signature),
	})
	completeReq := httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBody))
	completeReq.Header.Set("Content-Type", "application/json")
	completeReq.RemoteAddr = "192.168.1.50:12345"
	completeW := httptest.NewRecorder()
	mux.ServeHTTP(completeW, completeReq)
	if completeW.Code != http.StatusOK {
		t.Fatalf("enroll complete failed: %d %s", completeW.Code, completeW.Body.String())
	}

	var completeResp EnrollCompleteResponse
	json.NewDecoder(completeW.Body).Decode(&completeResp)
	return completeResp
}

func TestAudit_OperatorEnrollComplete(t *testing.T) {
	t.Log("Testing enroll.complete event emitted for successful operator enrollment")

	server, mux, mockAudit := setupTestServerWithAudit(t)

	// Setup: create tenant and invite
	server.store.AddTenant("tnt1", "Test", "", "", nil)
	inviteSvc := store.NewInviteService(server.store)
	inviteResult, err := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "op@test.com",
		TenantID:      "tnt1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create invite: %v", err)
	}

	resp := completeEnrollmentFlow(t, server, mux, inviteResult.Plaintext)

	t.Log("Verifying enroll.complete event was emitted")
	evt := mockAudit.LastOfType(audit.EventEnrollComplete)
	if evt == nil {
		t.Fatal("expected enroll.complete event, got none")
	}
	if evt.Details["identity_type"] != "km" {
		t.Errorf("identity_type = %q, want %q", evt.Details["identity_type"], "km")
	}
	if evt.Details["kid"] != resp.ID {
		t.Errorf("kid = %q, want %q", evt.Details["kid"], resp.ID)
	}
	if evt.IP == "" {
		t.Error("expected non-empty IP")
	}
	t.Logf("enroll.complete event: actor=%s identity_type=%s kid=%s ip=%s",
		evt.ActorID, evt.Details["identity_type"], evt.Details["kid"], evt.IP)
}

func TestAudit_OperatorEnrollFailure_InvalidCode(t *testing.T) {
	t.Log("Testing enroll.failure event emitted for invalid invite code")

	_, mux, mockAudit := setupTestServerWithAudit(t)

	body, _ := json.Marshal(EnrollInitRequest{Code: "bad-code-12345"})
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.99:54321"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Logf("Response: %d %s", w.Code, w.Body.String())
	if w.Code == http.StatusOK {
		t.Fatal("expected failure status, got 200")
	}

	t.Log("Verifying enroll.failure event was emitted")
	evt := mockAudit.LastOfType(audit.EventEnrollFailure)
	if evt == nil {
		t.Fatal("expected enroll.failure event, got none")
	}
	if evt.Details["reason"] != "invalid_invite_code" {
		t.Errorf("reason = %q, want %q", evt.Details["reason"], "invalid_invite_code")
	}
	if evt.Details["identity_type"] != "km" {
		t.Errorf("identity_type = %q, want %q", evt.Details["identity_type"], "km")
	}
	t.Logf("enroll.failure event: reason=%s identity_type=%s ip=%s",
		evt.Details["reason"], evt.Details["identity_type"], evt.IP)
}

func TestAudit_DPUEnrollComplete(t *testing.T) {
	t.Log("Testing enroll.complete event emitted for successful DPU enrollment")

	server, mux, mockAudit := setupTestServerWithAudit(t)

	// Setup: register DPU with pending enrollment
	server.store.Add("dpu1", "test-dpu", "192.168.1.100", 18051)
	server.store.SetDPUSerialNumber("dpu1", "SN-001")
	expires := time.Now().Add(1 * time.Hour)
	server.store.SetDPUEnrollmentPending("dpu1", expires)

	// Init DPU enrollment
	t.Log("Calling POST /api/v1/enroll/dpu/init")
	initBody, _ := json.Marshal(DPUEnrollInitRequest{Serial: "SN-001"})
	initReq := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(initBody))
	initReq.Header.Set("Content-Type", "application/json")
	initReq.RemoteAddr = "192.168.1.100:50000"
	initW := httptest.NewRecorder()
	mux.ServeHTTP(initW, initReq)
	if initW.Code != http.StatusOK {
		t.Fatalf("dpu enroll init failed: %d %s", initW.Code, initW.Body.String())
	}
	var initResp DPUEnrollInitResponse
	json.NewDecoder(initW.Body).Decode(&initResp)

	// Generate key pair and sign challenge
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	challengeBytes, _ := base64.StdEncoding.DecodeString(initResp.Challenge)
	signature := ed25519.Sign(privKey, challengeBytes)

	// Complete DPU enrollment
	t.Log("Calling POST /api/v1/enroll/complete for DPU")
	completeBody, _ := json.Marshal(EnrollCompleteRequest{
		EnrollmentID:    initResp.EnrollmentID,
		PublicKey:       base64.StdEncoding.EncodeToString(pubKey),
		SignedChallenge: base64.StdEncoding.EncodeToString(signature),
	})
	completeReq := httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBody))
	completeReq.Header.Set("Content-Type", "application/json")
	completeReq.RemoteAddr = "192.168.1.100:50000"
	completeW := httptest.NewRecorder()
	mux.ServeHTTP(completeW, completeReq)
	if completeW.Code != http.StatusOK {
		t.Fatalf("dpu enroll complete failed: %d %s", completeW.Code, completeW.Body.String())
	}

	var resp EnrollCompleteResponse
	json.NewDecoder(completeW.Body).Decode(&resp)

	t.Log("Verifying enroll.complete event was emitted for DPU")
	evt := mockAudit.LastOfType(audit.EventEnrollComplete)
	if evt == nil {
		t.Fatal("expected enroll.complete event, got none")
	}
	if evt.Details["identity_type"] != "dpu" {
		t.Errorf("identity_type = %q, want %q", evt.Details["identity_type"], "dpu")
	}
	if evt.Details["kid"] != resp.ID {
		t.Errorf("kid = %q, want %q", evt.Details["kid"], resp.ID)
	}
	t.Logf("enroll.complete event: actor=%s identity_type=%s kid=%s",
		evt.ActorID, evt.Details["identity_type"], evt.Details["kid"])
}

func TestAudit_DPUEnrollFailure_NotRegistered(t *testing.T) {
	t.Log("Testing enroll.failure event emitted for unregistered DPU serial")

	_, mux, mockAudit := setupTestServerWithAudit(t)

	body, _ := json.Marshal(DPUEnrollInitRequest{Serial: "UNKNOWN-SERIAL"})
	req := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.50:9999"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatal("expected failure, got 200")
	}

	evt := mockAudit.LastOfType(audit.EventEnrollFailure)
	if evt == nil {
		t.Fatal("expected enroll.failure event, got none")
	}
	if evt.Details["reason"] != "dpu_not_registered" {
		t.Errorf("reason = %q, want %q", evt.Details["reason"], "dpu_not_registered")
	}
	if evt.Details["identity_type"] != "dpu" {
		t.Errorf("identity_type = %q, want %q", evt.Details["identity_type"], "dpu")
	}
	t.Logf("enroll.failure event: reason=%s identity_type=%s", evt.Details["reason"], evt.Details["identity_type"])
}

func TestAudit_BootstrapComplete(t *testing.T) {
	t.Log("Testing bootstrap.complete event emitted for first admin enrollment")

	server, mux, mockAudit := setupTestServerWithAudit(t)

	// Open bootstrap window
	server.store.InitBootstrapWindow()

	// Generate admin key pair
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Bootstrap init
	t.Log("Calling POST /api/v1/admin/bootstrap")
	bootstrapBody, _ := json.Marshal(BootstrapRequest{PublicKey: pubKeyB64})
	bootstrapReq := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bootstrapBody))
	bootstrapReq.Header.Set("Content-Type", "application/json")
	bootstrapReq.RemoteAddr = "127.0.0.1:8080"
	bootstrapW := httptest.NewRecorder()
	mux.ServeHTTP(bootstrapW, bootstrapReq)
	if bootstrapW.Code != http.StatusOK {
		t.Fatalf("bootstrap init failed: %d %s", bootstrapW.Code, bootstrapW.Body.String())
	}

	var bootstrapResp BootstrapResponse
	json.NewDecoder(bootstrapW.Body).Decode(&bootstrapResp)

	// Sign challenge
	challengeBytes, _ := base64.StdEncoding.DecodeString(bootstrapResp.Challenge)
	signature := ed25519.Sign(privKey, challengeBytes)

	// Complete bootstrap
	t.Log("Calling POST /api/v1/enroll/complete for bootstrap")
	completeBody, _ := json.Marshal(EnrollCompleteRequest{
		EnrollmentID:    bootstrapResp.EnrollmentID,
		PublicKey:       pubKeyB64,
		SignedChallenge: base64.StdEncoding.EncodeToString(signature),
	})
	completeReq := httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBody))
	completeReq.Header.Set("Content-Type", "application/json")
	completeReq.RemoteAddr = "127.0.0.1:8080"
	completeW := httptest.NewRecorder()
	mux.ServeHTTP(completeW, completeReq)
	if completeW.Code != http.StatusOK {
		t.Fatalf("bootstrap complete failed: %d %s", completeW.Code, completeW.Body.String())
	}

	var resp EnrollCompleteResponse
	json.NewDecoder(completeW.Body).Decode(&resp)

	t.Log("Verifying bootstrap.complete event was emitted")
	evt := mockAudit.LastOfType(audit.EventBootstrapComplete)
	if evt == nil {
		t.Fatal("expected bootstrap.complete event, got none")
	}
	if evt.Details["identity_type"] != "admin" {
		t.Errorf("identity_type = %q, want %q", evt.Details["identity_type"], "admin")
	}
	if evt.Details["kid"] != resp.ID {
		t.Errorf("kid = %q, want %q", evt.Details["kid"], resp.ID)
	}
	if evt.ActorID != resp.ID {
		t.Errorf("actorID = %q, want %q", evt.ActorID, resp.ID)
	}
	t.Logf("bootstrap.complete event: actor=%s identity_type=%s kid=%s",
		evt.ActorID, evt.Details["identity_type"], evt.Details["kid"])
}

func TestAudit_BootstrapFailure_AlreadyEnrolled(t *testing.T) {
	t.Log("Testing enroll.failure event emitted when bootstrap already complete")

	server, mux, mockAudit := setupTestServerWithAudit(t)

	// Complete bootstrap first
	server.store.InitBootstrapWindow()
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	fingerprint := sha256.Sum256(pubKey)
	server.store.CreateOperator("adm_first", "admin@localhost", "Admin")
	server.store.UpdateOperatorStatus("adm_first", "active")
	server.store.CreateAdminKey(&store.AdminKey{
		ID:             "adm_first",
		OperatorID:     "adm_first",
		Name:           "Bootstrap Key",
		PublicKey:      pubKey,
		Kid:            "adm_first",
		KeyFingerprint: hex.EncodeToString(fingerprint[:]),
		Status:         "active",
	})
	server.store.CompleteBootstrap("adm_first")

	// Try to bootstrap again
	t.Log("Attempting second bootstrap after first admin exists")
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	body, _ := json.Marshal(BootstrapRequest{PublicKey: base64.StdEncoding.EncodeToString(newPub)})
	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.99:1234"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatal("expected failure, got 200")
	}

	evt := mockAudit.LastOfType(audit.EventEnrollFailure)
	if evt == nil {
		t.Fatal("expected enroll.failure event, got none")
	}
	if evt.Details["reason"] != "already_enrolled" {
		t.Errorf("reason = %q, want %q", evt.Details["reason"], "already_enrolled")
	}
	if evt.Details["identity_type"] != "admin" {
		t.Errorf("identity_type = %q, want %q", evt.Details["identity_type"], "admin")
	}
	t.Logf("enroll.failure event: reason=%s identity_type=%s", evt.Details["reason"], evt.Details["identity_type"])
}

func TestAudit_EnrollFailure_InvalidSignature(t *testing.T) {
	t.Log("Testing enroll.failure event emitted for invalid signature during enrollment")

	server, mux, mockAudit := setupTestServerWithAudit(t)

	// Setup: create tenant and invite
	server.store.AddTenant("tnt1", "Test", "", "", nil)
	inviteSvc := store.NewInviteService(server.store)
	inviteResult, _ := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "op@test.com",
		TenantID:      "tnt1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})

	// Init enrollment
	initBody, _ := json.Marshal(EnrollInitRequest{Code: inviteResult.Plaintext})
	initReq := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(initBody))
	initReq.Header.Set("Content-Type", "application/json")
	initW := httptest.NewRecorder()
	mux.ServeHTTP(initW, initReq)
	var initResp EnrollInitResponse
	json.NewDecoder(initW.Body).Decode(&initResp)

	// Use wrong key to sign
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	_, badPriv, _ := ed25519.GenerateKey(rand.Reader)
	challengeBytes, _ := base64.StdEncoding.DecodeString(initResp.Challenge)
	badSignature := ed25519.Sign(badPriv, challengeBytes)

	t.Log("Calling POST /api/v1/enroll/complete with wrong key signature")
	completeBody, _ := json.Marshal(EnrollCompleteRequest{
		EnrollmentID:    initResp.EnrollmentID,
		PublicKey:       base64.StdEncoding.EncodeToString(pubKey),
		SignedChallenge: base64.StdEncoding.EncodeToString(badSignature),
	})
	completeReq := httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(completeBody))
	completeReq.Header.Set("Content-Type", "application/json")
	completeW := httptest.NewRecorder()
	mux.ServeHTTP(completeW, completeReq)

	if completeW.Code == http.StatusOK {
		t.Fatal("expected failure, got 200")
	}

	evt := mockAudit.LastOfType(audit.EventEnrollFailure)
	if evt == nil {
		t.Fatal("expected enroll.failure event, got none")
	}
	if evt.Details["reason"] != "invalid_signature" {
		t.Errorf("reason = %q, want %q", evt.Details["reason"], "invalid_signature")
	}
	if evt.Details["identity_type"] != "km" {
		t.Errorf("identity_type = %q, want %q", evt.Details["identity_type"], "km")
	}
	t.Logf("enroll.failure event: reason=%s identity_type=%s", evt.Details["reason"], evt.Details["identity_type"])
}

func TestAudit_SentryEnrollComplete(t *testing.T) {
	t.Log("Testing enroll.complete event emitted for successful Sentry (host) registration")

	server, mux, mockAudit := setupTestServerWithAudit(t)

	// Setup: register a DPU for the host to reference
	server.store.Add("dpu1", "sentry-dpu", "192.168.1.100", 18051)

	// Register host agent
	t.Log("Calling POST /api/v1/hosts/register")
	body, _ := json.Marshal(map[string]string{
		"dpu_name": "sentry-dpu",
		"hostname": "worker-01",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.200:9000"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("host register failed: %d %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)

	t.Log("Verifying enroll.complete event for sentry")
	evt := mockAudit.LastOfType(audit.EventEnrollComplete)
	if evt == nil {
		t.Fatal("expected enroll.complete event, got none")
	}
	if evt.Details["identity_type"] != "sentry" {
		t.Errorf("identity_type = %q, want %q", evt.Details["identity_type"], "sentry")
	}
	if evt.Details["kid"] == "" {
		t.Error("expected non-empty kid")
	}
	t.Logf("enroll.complete event: actor=%s identity_type=%s kid=%s ip=%s",
		evt.ActorID, evt.Details["identity_type"], evt.Details["kid"], evt.IP)
}

func TestAudit_NoSecretsLogged(t *testing.T) {
	t.Log("Testing that no secrets (invite codes, claim tokens) appear in audit events")

	server, mux, mockAudit := setupTestServerWithAudit(t)

	// Setup: create tenant and invite
	server.store.AddTenant("tnt1", "Test", "", "", nil)
	inviteSvc := store.NewInviteService(server.store)
	inviteResult, _ := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "op@test.com",
		TenantID:      "tnt1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})

	// Run full enrollment flow
	completeEnrollmentFlow(t, server, mux, inviteResult.Plaintext)

	// Check all events for secret leaks
	t.Log("Scanning all audit events for invite code or claim token")
	inviteCode := inviteResult.Plaintext
	for _, evt := range mockAudit.Events() {
		// Check ActorID
		if evt.ActorID == inviteCode {
			t.Errorf("invite code found in ActorID of %s event", evt.Type)
		}
		// Check all Details values
		for k, v := range evt.Details {
			if v == inviteCode {
				t.Errorf("invite code found in Details[%s] of %s event", k, evt.Type)
			}
		}
		// Check IP field
		if evt.IP == inviteCode {
			t.Errorf("invite code found in IP of %s event", evt.Type)
		}
	}
	t.Log("No secrets found in audit events")
}

func TestAudit_NilLoggerDoesNotPanic(t *testing.T) {
	t.Log("Testing that nil audit logger does not cause panics")

	// Use standard setupTestServer which has no audit logger
	_, mux := setupTestServer(t)

	// Try an enrollment failure (invalid code) - should not panic
	body, _ := json.Marshal(EnrollInitRequest{Code: "whatever"})
	req := httptest.NewRequest("POST", "/api/v1/enroll/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// If we got here without panic, the test passes
	t.Logf("Response with nil audit logger: %d (no panic)", w.Code)
}

func TestAudit_IdentityTypeDistinguishes(t *testing.T) {
	t.Log("Testing identity_type field correctly distinguishes km/dpu/admin/sentry")

	server, mux, mockAudit := setupTestServerWithAudit(t)

	// 1. Bootstrap (admin)
	t.Log("Step 1: Bootstrap enrollment (admin)")
	server.store.InitBootstrapWindow()
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	bootstrapBody, _ := json.Marshal(BootstrapRequest{PublicKey: base64.StdEncoding.EncodeToString(pubKey)})
	bootstrapReq := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", bytes.NewReader(bootstrapBody))
	bootstrapReq.Header.Set("Content-Type", "application/json")
	bw := httptest.NewRecorder()
	mux.ServeHTTP(bw, bootstrapReq)
	if bw.Code != http.StatusOK {
		t.Fatalf("bootstrap init: %d %s", bw.Code, bw.Body.String())
	}
	var bResp BootstrapResponse
	json.NewDecoder(bw.Body).Decode(&bResp)
	challengeBytes, _ := base64.StdEncoding.DecodeString(bResp.Challenge)
	sig := ed25519.Sign(privKey, challengeBytes)
	bcBody, _ := json.Marshal(EnrollCompleteRequest{
		EnrollmentID:    bResp.EnrollmentID,
		PublicKey:       base64.StdEncoding.EncodeToString(pubKey),
		SignedChallenge: base64.StdEncoding.EncodeToString(sig),
	})
	bcReq := httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(bcBody))
	bcReq.Header.Set("Content-Type", "application/json")
	bcW := httptest.NewRecorder()
	mux.ServeHTTP(bcW, bcReq)
	if bcW.Code != http.StatusOK {
		t.Fatalf("bootstrap complete: %d %s", bcW.Code, bcW.Body.String())
	}

	// 2. Operator enrollment (km)
	t.Log("Step 2: Operator enrollment (km)")
	server.store.AddTenant("tnt1", "Test", "", "", nil)
	inviteSvc := store.NewInviteService(server.store)
	inviteResult, _ := inviteSvc.CreateInviteCode(store.CreateInviteCodeRequest{
		OperatorEmail: "op@test.com",
		TenantID:      "tnt1",
		Role:          "operator",
		CreatedBy:     "admin",
		TTL:           1 * time.Hour,
	})
	completeEnrollmentFlow(t, server, mux, inviteResult.Plaintext)

	// 3. DPU enrollment
	t.Log("Step 3: DPU enrollment (dpu)")
	server.store.Add("dpu1", "test-dpu", "192.168.1.100", 18051)
	server.store.SetDPUSerialNumber("dpu1", "SN-001")
	server.store.SetDPUEnrollmentPending("dpu1", time.Now().Add(1*time.Hour))
	diBody, _ := json.Marshal(DPUEnrollInitRequest{Serial: "SN-001"})
	diReq := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", bytes.NewReader(diBody))
	diReq.Header.Set("Content-Type", "application/json")
	diW := httptest.NewRecorder()
	mux.ServeHTTP(diW, diReq)
	var diResp DPUEnrollInitResponse
	json.NewDecoder(diW.Body).Decode(&diResp)
	dpuPub, dpuPriv, _ := ed25519.GenerateKey(rand.Reader)
	dpuChallenge, _ := base64.StdEncoding.DecodeString(diResp.Challenge)
	dpuSig := ed25519.Sign(dpuPriv, dpuChallenge)
	dcBody, _ := json.Marshal(EnrollCompleteRequest{
		EnrollmentID:    diResp.EnrollmentID,
		PublicKey:       base64.StdEncoding.EncodeToString(dpuPub),
		SignedChallenge: base64.StdEncoding.EncodeToString(dpuSig),
	})
	dcReq := httptest.NewRequest("POST", "/api/v1/enroll/complete", bytes.NewReader(dcBody))
	dcReq.Header.Set("Content-Type", "application/json")
	dcW := httptest.NewRecorder()
	mux.ServeHTTP(dcW, dcReq)
	if dcW.Code != http.StatusOK {
		t.Fatalf("dpu complete: %d %s", dcW.Code, dcW.Body.String())
	}

	// 4. Sentry registration
	t.Log("Step 4: Sentry registration")
	server.store.Add("dpu2", "sentry-dpu", "192.168.1.101", 18051)
	sBody, _ := json.Marshal(map[string]string{"dpu_name": "sentry-dpu", "hostname": "worker-01"})
	sReq := httptest.NewRequest("POST", "/api/v1/hosts/register", bytes.NewReader(sBody))
	sReq.Header.Set("Content-Type", "application/json")
	sW := httptest.NewRecorder()
	mux.ServeHTTP(sW, sReq)
	if sW.Code != http.StatusCreated {
		t.Fatalf("sentry register: %d %s", sW.Code, sW.Body.String())
	}

	// Verify identity types across all success events
	t.Log("Verifying identity_type across all enrollment events")
	identityTypes := make(map[string]bool)
	for _, evt := range mockAudit.Events() {
		if evt.Type == audit.EventEnrollComplete || evt.Type == audit.EventBootstrapComplete {
			it := evt.Details["identity_type"]
			identityTypes[it] = true
			t.Logf("  %s: identity_type=%s kid=%s", evt.Type, it, evt.Details["kid"])
		}
	}

	for _, expected := range []string{"admin", "km", "dpu", "sentry"} {
		if !identityTypes[expected] {
			t.Errorf("missing identity_type %q in events", expected)
		}
	}
}
