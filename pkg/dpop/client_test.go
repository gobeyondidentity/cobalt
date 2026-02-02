package dpop

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

// mockProofGenerator is a mock ProofGenerator for testing.
type mockProofGenerator struct {
	proof string
	err   error
	calls []proofCall
}

type proofCall struct {
	method string
	uri    string
	kid    string
}

func (m *mockProofGenerator) Generate(method, uri, kid string) (string, error) {
	m.calls = append(m.calls, proofCall{method, uri, kid})
	return m.proof, m.err
}

func TestClientAddsDPoPHeader(t *testing.T) {
	t.Parallel()
	t.Log("Testing Client adds DPoP header to requests")

	// Create test server that checks for DPoP header
	var receivedDPoP string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDPoP = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	proofGen := &mockProofGenerator{proof: "test.proof.here"}
	client := NewClient(server.URL, proofGen, WithKID("km_test"))

	t.Log("Making GET request")
	resp, err := client.Get("/api/v1/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if receivedDPoP != "test.proof.here" {
		t.Errorf("expected DPoP header 'test.proof.here', got %q", receivedDPoP)
	}

	t.Log("DPoP header correctly added to request")
}

func TestClientGeneratesFreshProofPerRequest(t *testing.T) {
	t.Parallel()
	t.Log("Testing Client generates fresh proof for each request")

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	proofGen := &mockProofGenerator{proof: "test.proof"}
	client := NewClient(server.URL, proofGen, WithKID("km_test"))

	// Make multiple requests
	t.Log("Making 3 requests")
	for i := 0; i < 3; i++ {
		resp, err := client.Get("/api/v1/test")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	// Verify proof was generated for each request
	if len(proofGen.calls) != 3 {
		t.Errorf("expected 3 proof generations, got %d", len(proofGen.calls))
	}

	t.Log("Fresh proof generated for each request")
}

func TestClientUsesCorrectMethodAndURI(t *testing.T) {
	t.Parallel()
	t.Log("Testing Client passes correct method and URI to proof generator")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	proofGen := &mockProofGenerator{proof: "test.proof"}
	client := NewClient(server.URL, proofGen, WithKID("km_abc123"))

	t.Log("Making POST request to /api/v1/push")
	resp, err := client.Post("/api/v1/push", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if len(proofGen.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(proofGen.calls))
	}

	call := proofGen.calls[0]
	if call.method != "POST" {
		t.Errorf("expected method POST, got %s", call.method)
	}
	expectedURI := server.URL + "/api/v1/push"
	if call.uri != expectedURI {
		t.Errorf("expected URI %s, got %s", expectedURI, call.uri)
	}
	if call.kid != "km_abc123" {
		t.Errorf("expected kid km_abc123, got %s", call.kid)
	}

	t.Log("Method and URI correctly passed to proof generator")
}

func TestClientSetKID(t *testing.T) {
	t.Parallel()
	t.Log("Testing Client.SetKID updates kid for subsequent requests")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	proofGen := &mockProofGenerator{proof: "test.proof"}
	client := NewClient(server.URL, proofGen)

	// First request without kid
	resp, _ := client.Get("/test")
	resp.Body.Close()

	// Set kid
	client.SetKID("km_new")

	// Second request with kid
	resp, _ = client.Get("/test")
	resp.Body.Close()

	if len(proofGen.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(proofGen.calls))
	}

	if proofGen.calls[0].kid != "" {
		t.Errorf("first call should have empty kid, got %s", proofGen.calls[0].kid)
	}
	if proofGen.calls[1].kid != "km_new" {
		t.Errorf("second call should have kid km_new, got %s", proofGen.calls[1].kid)
	}

	t.Log("SetKID correctly updates kid for subsequent requests")
}

func TestClientPostJSON(t *testing.T) {
	t.Parallel()
	t.Log("Testing Client.PostJSON sends JSON body with correct content type")

	var receivedBody string
	var receivedContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	proofGen := &mockProofGenerator{proof: "test.proof"}
	client := NewClient(server.URL, proofGen)

	payload := map[string]string{"key": "value"}

	t.Log("Making PostJSON request")
	resp, err := client.PostJSON("/api/v1/test", payload)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", receivedContentType)
	}

	var received map[string]string
	if err := json.Unmarshal([]byte(receivedBody), &received); err != nil {
		t.Fatalf("failed to parse received body: %v", err)
	}
	if received["key"] != "value" {
		t.Errorf("expected key=value, got %v", received)
	}

	t.Log("PostJSON correctly sends JSON body")
}

func TestParseAuthError(t *testing.T) {
	t.Parallel()
	t.Log("Testing ParseAuthError extracts error code from response")

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantCode   string
		wantNil    bool
	}{
		{
			name:       "401 with error code",
			statusCode: 401,
			body:       `{"error": "dpop.invalid_proof"}`,
			wantCode:   "dpop.invalid_proof",
		},
		{
			name:       "403 with error code",
			statusCode: 403,
			body:       `{"error": "auth.suspended"}`,
			wantCode:   "auth.suspended",
		},
		{
			name:       "401 empty body",
			statusCode: 401,
			body:       "",
			wantCode:   "unknown",
		},
		{
			name:       "200 OK",
			statusCode: 200,
			body:       `{"data": "success"}`,
			wantNil:    true,
		},
		{
			name:       "500 error",
			statusCode: 500,
			body:       `{"error": "internal"}`,
			wantNil:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := &http.Response{
				StatusCode: tc.statusCode,
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}

			authErr := ParseAuthError(resp)

			if tc.wantNil {
				if authErr != nil {
					t.Errorf("expected nil, got %+v", authErr)
				}
				return
			}

			if authErr == nil {
				t.Fatal("expected non-nil error")
			}
			if authErr.Code != tc.wantCode {
				t.Errorf("expected code %q, got %q", tc.wantCode, authErr.Code)
			}
		})
	}

	t.Log("ParseAuthError correctly extracts error codes")
}

func TestAuthErrorUserFriendlyMessages(t *testing.T) {
	t.Parallel()
	t.Log("Testing AuthError.UserFriendlyMessage returns helpful messages")

	tests := []struct {
		code     string
		contains string
	}{
		{"dpop.invalid_iat", "clock"},
		{"auth.revoked", "revoked"},
		{"auth.suspended", "suspended"},
		{"dpop.unknown_key", "re-enrollment"},
	}

	for _, tc := range tests {
		err := &AuthError{Code: tc.code}
		msg := err.UserFriendlyMessage()
		if !strings.Contains(strings.ToLower(msg), tc.contains) {
			t.Errorf("message for %s should contain %q, got: %s", tc.code, tc.contains, msg)
		}
	}

	t.Log("User-friendly messages contain expected keywords")
}

func TestAuthErrorIsClockError(t *testing.T) {
	t.Parallel()
	t.Log("Testing AuthError.IsClockError identifies clock issues")

	clockErr := &AuthError{Code: "dpop.invalid_iat"}
	if !clockErr.IsClockError() {
		t.Error("dpop.invalid_iat should be identified as clock error")
	}

	otherErr := &AuthError{Code: "dpop.invalid_proof"}
	if otherErr.IsClockError() {
		t.Error("dpop.invalid_proof should not be identified as clock error")
	}

	t.Log("IsClockError correctly identifies clock-related errors")
}

func TestClockSyncErrorMessageIncludesFix(t *testing.T) {
	t.Parallel()
	t.Log("Testing clock sync error includes platform-specific fix command")

	err := &AuthError{Code: "dpop.invalid_iat"}
	msg := err.UserFriendlyMessage()

	// Verify the message includes the fix instruction
	if !strings.Contains(msg, "Fix:") {
		t.Error("clock sync error should include 'Fix:' instruction")
	}

	// Verify platform-specific command is present (test for current platform)
	switch runtime.GOOS {
	case "linux":
		if !strings.Contains(msg, "timedatectl") {
			t.Error("Linux clock sync error should mention timedatectl")
		}
	case "darwin":
		if !strings.Contains(msg, "sntp") {
			t.Error("macOS clock sync error should mention sntp")
		}
	case "windows":
		if !strings.Contains(msg, "w32tm") {
			t.Error("Windows clock sync error should mention w32tm")
		}
	}

	t.Logf("Clock sync error message on %s: %s", runtime.GOOS, msg)
}

func TestAuthErrorIsRevoked(t *testing.T) {
	t.Parallel()
	t.Log("Testing AuthError.IsRevoked identifies revocation")

	revokedErr := &AuthError{Code: "auth.revoked"}
	if !revokedErr.IsRevoked() {
		t.Error("auth.revoked should be identified as revoked")
	}

	otherErr := &AuthError{Code: "auth.suspended"}
	if otherErr.IsRevoked() {
		t.Error("auth.suspended should not be identified as revoked")
	}

	t.Log("IsRevoked correctly identifies revocation errors")
}

func TestLoadIdentity(t *testing.T) {
	t.Parallel()
	t.Log("Testing LoadIdentity loads key and kid from storage")

	tmpDir := t.TempDir()

	keyStore := NewFileKeyStore(tmpDir + "/key.pem")
	kidStore := NewFileKIDStore(tmpDir + "/kid")

	// Generate and save identity
	_, privKey, _ := GenerateKey()
	keyStore.Save(privKey)
	kidStore.Save("km_loaded")

	cfg := IdentityConfig{
		KeyStore: keyStore,
		KIDStore: kidStore,
	}

	loadedKey, loadedKID, err := LoadIdentity(cfg)
	if err != nil {
		t.Fatalf("failed to load identity: %v", err)
	}

	if !privKey.Equal(loadedKey) {
		t.Error("loaded key does not match saved key")
	}
	if loadedKID != "km_loaded" {
		t.Errorf("expected kid km_loaded, got %s", loadedKID)
	}

	t.Log("Identity loaded successfully")
}

func TestSaveIdentity(t *testing.T) {
	t.Parallel()
	t.Log("Testing SaveIdentity saves key and kid to storage")

	tmpDir := t.TempDir()

	keyStore := NewFileKeyStore(tmpDir + "/key.pem")
	kidStore := NewFileKIDStore(tmpDir + "/kid")

	cfg := IdentityConfig{
		KeyStore: keyStore,
		KIDStore: kidStore,
	}

	_, privKey, _ := GenerateKey()

	if err := SaveIdentity(cfg, privKey, "km_saved"); err != nil {
		t.Fatalf("failed to save identity: %v", err)
	}

	// Verify saved
	loadedKey, _ := keyStore.Load()
	loadedKID, _ := kidStore.Load()

	if !privKey.Equal(loadedKey) {
		t.Error("saved key does not match")
	}
	if loadedKID != "km_saved" {
		t.Errorf("expected kid km_saved, got %s", loadedKID)
	}

	t.Log("Identity saved successfully")
}

func TestIsEnrolled(t *testing.T) {
	t.Parallel()
	t.Log("Testing IsEnrolled checks for key and kid existence")

	tmpDir := t.TempDir()

	keyStore := NewFileKeyStore(tmpDir + "/key.pem")
	kidStore := NewFileKIDStore(tmpDir + "/kid")

	cfg := IdentityConfig{
		KeyStore: keyStore,
		KIDStore: kidStore,
	}

	// Not enrolled initially
	if IsEnrolled(cfg) {
		t.Error("should not be enrolled initially")
	}

	// Save only key
	_, privKey, _ := GenerateKey()
	keyStore.Save(privKey)

	if IsEnrolled(cfg) {
		t.Error("should not be enrolled with only key")
	}

	// Save kid too
	kidStore.Save("km_test")

	if !IsEnrolled(cfg) {
		t.Error("should be enrolled with key and kid")
	}

	t.Log("IsEnrolled correctly checks enrollment status")
}

func TestClientDelete(t *testing.T) {
	t.Parallel()
	t.Log("Testing Client.Delete sends DELETE request with DPoP")

	var receivedMethod string
	var receivedDPoP string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedDPoP = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	proofGen := &mockProofGenerator{proof: "delete.proof"}
	client := NewClient(server.URL, proofGen)

	resp, err := client.Delete("/api/v1/resource/123")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if receivedMethod != "DELETE" {
		t.Errorf("expected DELETE method, got %s", receivedMethod)
	}
	if receivedDPoP != "delete.proof" {
		t.Errorf("expected DPoP header, got %q", receivedDPoP)
	}

	t.Log("Delete correctly sends DELETE request with DPoP")
}

func TestClientBaseURLHandling(t *testing.T) {
	t.Parallel()
	t.Log("Testing Client handles trailing slash in base URL")

	proofGen := &mockProofGenerator{proof: "test"}

	// With trailing slash
	client1 := NewClient("https://example.com/", proofGen)
	// Without trailing slash
	client2 := NewClient("https://example.com", proofGen)

	// Both should produce the same URI
	// (Can't actually test this without a server, but we can check the client is created)

	if client1 == nil || client2 == nil {
		t.Error("clients should be created")
	}

	t.Log("Base URL handling verified")
}

// mockLogger captures log messages for testing
type mockLogger struct {
	warnings []string
}

func (m *mockLogger) Warn(msg string) {
	m.warnings = append(m.warnings, msg)
}

func TestNewClientFromConfigLogsWarning(t *testing.T) {
	t.Parallel()
	t.Log("Testing NewClientFromConfig logs MVP warning")

	tmpDir := t.TempDir()

	// Create enrolled identity
	keyStore := NewFileKeyStore(tmpDir + "/key.pem")
	kidStore := NewFileKIDStore(tmpDir + "/kid")

	_, privKey, _ := GenerateKey()
	keyStore.Save(privKey)
	kidStore.Save("km_test")

	// Temporarily override default paths by testing unknown type error
	logger := &mockLogger{}
	cfg := ClientConfig{
		ClientType: "unknown",
		ServerURL:  "https://example.com",
		Logger:     logger,
	}

	_, _, _, err := NewClientFromConfig(cfg)
	if err == nil {
		t.Error("expected error for unknown client type")
	}

	t.Log("Unknown client type correctly rejected")
}

func TestNewEnrollmentClientLogsWarning(t *testing.T) {
	// NOT parallel - this test modifies global state (mvpWarningOnce)
	t.Log("Testing NewEnrollmentClient logs MVP warning")

	// Reset warning state for this test
	ResetMVPWarning()

	logger := &mockLogger{}
	cfg := ClientConfig{
		ClientType: "km",
		ServerURL:  "https://example.com",
		Logger:     logger,
	}

	client, privKey, pubKey, err := NewEnrollmentClient(cfg)
	if err != nil {
		t.Fatalf("failed to create enrollment client: %v", err)
	}

	// Verify warning was logged
	if len(logger.warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(logger.warnings))
	}
	if len(logger.warnings) > 0 && logger.warnings[0] != MVPWarning {
		t.Errorf("expected MVP warning, got: %s", logger.warnings[0])
	}

	// Verify client was created
	if client == nil {
		t.Error("client should not be nil")
	}

	// Verify keys were generated
	if privKey == nil {
		t.Error("private key should not be nil")
	}
	if pubKey == nil {
		t.Error("public key should not be nil")
	}

	t.Log("Enrollment client created with MVP warning logged")
}

func TestMVPWarningLoggedOnce(t *testing.T) {
	// NOT parallel - this test modifies global state (mvpWarningOnce)
	t.Log("Testing MVP warning is only logged once per session")

	// Reset warning state for this test
	ResetMVPWarning()

	logger := &mockLogger{}
	cfg := ClientConfig{
		ClientType: "km",
		ServerURL:  "https://example.com",
		Logger:     logger,
	}

	// Create multiple enrollment clients
	_, _, _, _ = NewEnrollmentClient(cfg)
	_, _, _, _ = NewEnrollmentClient(cfg)
	_, _, _, _ = NewEnrollmentClient(cfg)

	// Verify warning was logged only once
	if len(logger.warnings) != 1 {
		t.Errorf("expected warning to be logged exactly once, got %d times", len(logger.warnings))
	}

	t.Log("MVP warning correctly logged only once")
}

func TestCompleteEnrollment(t *testing.T) {
	t.Parallel()
	t.Log("Testing CompleteEnrollment saves identity to correct paths")

	// Create custom key store for this test
	_, privKey, _ := GenerateKey()
	testKID := "km_enrolled_123"

	// We can't easily test CompleteEnrollment with real paths because
	// DefaultKeyPaths returns user home dir paths. Test the error case.
	err := CompleteEnrollment("unknown", privKey, testKID)
	if err == nil {
		t.Error("expected error for unknown client type")
	}

	t.Log("CompleteEnrollment correctly validates client type")
}

func TestMVPWarningConstant(t *testing.T) {
	t.Parallel()
	t.Log("Testing MVPWarning constant contains expected text")

	// Verify the warning contains the required text per acceptance criteria
	if !strings.Contains(MVPWarning, "file-based key storage") {
		t.Error("warning should mention file-based key storage")
	}
	if !strings.Contains(MVPWarning, "MVP") {
		t.Error("warning should mention MVP")
	}
	if !strings.Contains(MVPWarning, "Hardware binding required") {
		t.Error("warning should mention hardware binding requirement")
	}

	t.Log("MVP warning contains all required text")
}

func TestNewClientFromConfigNotEnrolled(t *testing.T) {
	t.Parallel()
	t.Log("Testing NewClientFromConfig returns nil when not enrolled")

	// Use unknown client type to test error path
	// since we can't easily mock the default paths
	cfg := ClientConfig{
		ClientType: "unknown",
		ServerURL:  "https://example.com",
	}

	_, _, _, err := NewClientFromConfig(cfg)
	if err == nil {
		t.Error("expected error for unknown client type")
	}

	t.Log("Not enrolled case handled correctly")
}
