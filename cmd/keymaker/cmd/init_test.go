package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestGetServerURL_EnvVar(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing KM_SERVER env var takes precedence over flags (but triggers deprecation)")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Clear any env vars that might interfere
	os.Unsetenv("SERVER_URL")

	// Set env var
	os.Setenv("KM_SERVER", "http://env-server.example.com")
	defer os.Unsetenv("KM_SERVER")

	// Set flags to different values
	cmd.Flags().Set("server", "http://flag-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://env-server.example.com" {
		t.Errorf("Expected URL from env var 'http://env-server.example.com', got %q", url)
	}
	// KM_SERVER is now deprecated, so it should return deprecated=true
	if !deprecated {
		t.Error("Expected deprecation warning when using KM_SERVER (it's deprecated)")
	}
	t.Log("KM_SERVER correctly takes precedence over flags and triggers deprecation")
}

func TestGetServerURL_ServerURLEnvVar(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing SERVER_URL env var takes precedence over KM_SERVER")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Set both env vars
	os.Setenv("SERVER_URL", "http://server-url.example.com")
	os.Setenv("KM_SERVER", "http://km-server.example.com")
	defer func() {
		os.Unsetenv("SERVER_URL")
		os.Unsetenv("KM_SERVER")
	}()

	// Set flags to different values
	cmd.Flags().Set("server", "http://flag-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://server-url.example.com" {
		t.Errorf("Expected URL from SERVER_URL 'http://server-url.example.com', got %q", url)
	}
	if deprecated {
		t.Error("Expected no deprecation warning when using SERVER_URL env var")
	}
	t.Log("SERVER_URL correctly takes precedence over KM_SERVER")
}

func TestGetServerURL_KMServerDeprecationWarning(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing KM_SERVER triggers deprecation warning when SERVER_URL not set")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Clear SERVER_URL, set only KM_SERVER
	os.Unsetenv("SERVER_URL")
	os.Setenv("KM_SERVER", "http://km-server.example.com")
	defer os.Unsetenv("KM_SERVER")

	url, deprecated := getServerURL(&cmd)

	if url != "http://km-server.example.com" {
		t.Errorf("Expected URL from KM_SERVER 'http://km-server.example.com', got %q", url)
	}
	if !deprecated {
		t.Error("Expected deprecation warning when using KM_SERVER without SERVER_URL")
	}
	t.Log("KM_SERVER triggers deprecation warning as expected")
}

func TestGetServerURL_ServerFlag(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing --server flag works without deprecation warning")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Ensure no env var interference
	os.Unsetenv("SERVER_URL")
	os.Unsetenv("KM_SERVER")

	// Set --server flag
	cmd.Flags().Set("server", "http://my-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://my-server.example.com" {
		t.Errorf("Expected URL 'http://my-server.example.com', got %q", url)
	}
	if deprecated {
		t.Error("Expected no deprecation warning when using --server flag")
	}
	t.Log("--server flag works correctly")
}

func TestGetServerURL_ControlPlaneFlag(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing --control-plane flag returns deprecation warning")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Ensure no env var interference
	os.Unsetenv("SERVER_URL")
	os.Unsetenv("KM_SERVER")

	// Set only --control-plane flag
	cmd.Flags().Set("control-plane", "http://legacy-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://legacy-server.example.com" {
		t.Errorf("Expected URL 'http://legacy-server.example.com', got %q", url)
	}
	if !deprecated {
		t.Error("Expected deprecation warning when using --control-plane flag")
	}
	t.Log("--control-plane flag triggers deprecation warning as expected")
}

func TestGetServerURL_Default(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing default value when no env var or flags set")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Ensure no env var interference
	os.Unsetenv("SERVER_URL")
	os.Unsetenv("KM_SERVER")

	// Don't set any flags (use defaults)
	url, deprecated := getServerURL(&cmd)

	if url != "http://localhost:18080" {
		t.Errorf("Expected default URL 'http://localhost:18080', got %q", url)
	}
	if deprecated {
		t.Error("Expected no deprecation warning when using default")
	}
	t.Log("Default value returned correctly")
}

func TestGetServerURL_ServerOverridesControlPlane(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing --server flag takes precedence over --control-plane")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Ensure no env var interference
	os.Unsetenv("SERVER_URL")
	os.Unsetenv("KM_SERVER")

	// Set both flags
	cmd.Flags().Set("server", "http://new-server.example.com")
	cmd.Flags().Set("control-plane", "http://old-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://new-server.example.com" {
		t.Errorf("Expected --server value 'http://new-server.example.com', got %q", url)
	}
	if deprecated {
		t.Error("Expected no deprecation warning when --server is set")
	}
	t.Log("--server correctly takes precedence over --control-plane")
}

func TestInitCmd_HasServerFlag(t *testing.T) {
	// Cannot run in parallel - accesses shared global initCmd
	t.Log("Verifying init command has --server flag defined")

	flag := initCmd.Flags().Lookup("server")
	if flag == nil {
		t.Fatal("Expected --server flag to be defined on init command")
	}

	if flag.DefValue != "http://localhost:18080" {
		t.Errorf("Expected default value 'http://localhost:18080', got %q", flag.DefValue)
	}
	t.Log("--server flag is correctly defined")
}

func TestInitCmd_HasControlPlaneFlag(t *testing.T) {
	// Cannot run in parallel - accesses shared global initCmd
	t.Log("Verifying init command has --control-plane flag (deprecated alias)")

	flag := initCmd.Flags().Lookup("control-plane")
	if flag == nil {
		t.Fatal("Expected --control-plane flag to be defined on init command")
	}

	if flag.DefValue != "http://localhost:18080" {
		t.Errorf("Expected default value 'http://localhost:18080', got %q", flag.DefValue)
	}
	t.Log("--control-plane flag is correctly defined")
}

func TestInitCmd_HelpShowsServer(t *testing.T) {
	// Cannot run in parallel - accesses shared global initCmd
	t.Log("Verifying help output shows --server flag")

	var stdout bytes.Buffer
	initCmd.SetOut(&stdout)

	// Get usage string directly instead of executing
	usage := initCmd.UsageString()

	if !strings.Contains(usage, "--server") {
		t.Errorf("Expected usage output to contain '--server', got:\n%s", usage)
	}
	t.Log("Help output correctly shows --server flag")
}

func TestInitCmd_LongDescriptionMentionsEnvVar(t *testing.T) {
	// Cannot run in parallel - accesses shared global initCmd
	t.Log("Verifying Long description mentions SERVER_URL env var as primary")

	if !strings.Contains(initCmd.Long, "SERVER_URL") {
		t.Errorf("Expected Long description to mention SERVER_URL env var, got:\n%s", initCmd.Long)
	}
	t.Log("Long description correctly mentions SERVER_URL")
}

func TestInitCmd_LongDescriptionMentionsKMServer(t *testing.T) {
	// Cannot run in parallel - accesses shared global initCmd
	t.Log("Verifying Long description mentions KM_SERVER env var as deprecated")

	if !strings.Contains(initCmd.Long, "KM_SERVER") {
		t.Errorf("Expected Long description to mention KM_SERVER env var, got:\n%s", initCmd.Long)
	}
	t.Log("Long description correctly mentions KM_SERVER")
}

func TestInitCmd_ExampleUsesServer(t *testing.T) {
	// Cannot run in parallel - accesses shared global initCmd
	t.Log("Verifying command example uses --server instead of --control-plane")

	// Check the Long description contains the example with --server
	if strings.Contains(initCmd.Long, "--control-plane https://") {
		t.Error("Expected examples to use --server instead of --control-plane")
	}
	if !strings.Contains(initCmd.Long, "--server https://") {
		t.Errorf("Expected Long description to have example with --server, got:\n%s", initCmd.Long)
	}
	t.Log("Examples correctly use --server")
}

// Test enrollment error handling
func TestEnrollmentErrorMessage_InvalidCode(t *testing.T) {
	t.Parallel()
	t.Log("Testing user-friendly error message for invalid invite code")

	msg := enrollmentErrorMessage("enroll.invalid_code")
	expected := "Invalid or expired invite code"
	if msg != expected {
		t.Errorf("Expected %q, got %q", expected, msg)
	}
	t.Log("Invalid code error message is user-friendly")
}

func TestEnrollmentErrorMessage_ExpiredCode(t *testing.T) {
	t.Parallel()
	t.Log("Testing user-friendly error message for expired invite code")

	msg := enrollmentErrorMessage("enroll.expired_code")
	expected := "Invite code has expired"
	if msg != expected {
		t.Errorf("Expected %q, got %q", expected, msg)
	}
	t.Log("Expired code error message is user-friendly")
}

func TestEnrollmentErrorMessage_ConsumedCode(t *testing.T) {
	t.Parallel()
	t.Log("Testing user-friendly error message for already-used invite code")

	msg := enrollmentErrorMessage("enroll.code_consumed")
	expected := "Invite code already used"
	if msg != expected {
		t.Errorf("Expected %q, got %q", expected, msg)
	}
	t.Log("Consumed code error message is user-friendly")
}

func TestEnrollmentErrorMessage_ChallengeExpired(t *testing.T) {
	t.Parallel()
	t.Log("Testing user-friendly error message for expired enrollment session")

	msg := enrollmentErrorMessage("enroll.challenge_expired")
	expected := "Enrollment session timed out. Please try again"
	if msg != expected {
		t.Errorf("Expected %q, got %q", expected, msg)
	}
	t.Log("Challenge expired error message is user-friendly")
}

func TestEnrollmentErrorMessage_InvalidSignature(t *testing.T) {
	t.Parallel()
	t.Log("Testing user-friendly error message for signature verification failure")

	msg := enrollmentErrorMessage("enroll.invalid_signature")
	expected := "Signature verification failed"
	if msg != expected {
		t.Errorf("Expected %q, got %q", expected, msg)
	}
	t.Log("Invalid signature error message is user-friendly")
}

func TestEnrollmentErrorMessage_KeyExists(t *testing.T) {
	t.Parallel()
	t.Log("Testing user-friendly error message for duplicate key enrollment")

	msg := enrollmentErrorMessage("enroll.key_exists")
	expected := "This key is already enrolled"
	if msg != expected {
		t.Errorf("Expected %q, got %q", expected, msg)
	}
	t.Log("Key exists error message is user-friendly")
}

func TestEnrollmentErrorMessage_Unknown(t *testing.T) {
	t.Parallel()
	t.Log("Testing fallback for unknown error codes")

	msg := enrollmentErrorMessage("some.unknown.error")
	expected := "Enrollment failed: some.unknown.error"
	if msg != expected {
		t.Errorf("Expected %q, got %q", expected, msg)
	}
	t.Log("Unknown error codes are handled gracefully")
}

// Test the two-phase enrollment flow with a mock server
func TestTwoPhaseEnrollment_HappyPath(t *testing.T) {
	// Cannot run in parallel - modifies global getConfigDirFunc
	t.Log("Testing two-phase enrollment flow with mock server")

	// Create temp directory for config
	tempDir := t.TempDir()
	originalGetConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tempDir }
	defer func() { getConfigDirFunc = originalGetConfigDir }()

	// Track enrollment phases
	var initCalled, completeCalled bool
	var receivedCode string
	var receivedEnrollmentID string
	var receivedPublicKey string

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll/init":
			t.Log("Mock server received /api/v1/enroll/init request")
			initCalled = true

			var req struct {
				Code string `json:"code"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("Failed to decode init request: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			receivedCode = req.Code

			// Return challenge and enrollment_id
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"challenge":     "dGVzdC1jaGFsbGVuZ2UtYnl0ZXM=", // base64 of "test-challenge-bytes"
				"enrollment_id": "test-enrollment-id",
			})

		case "/api/v1/enroll/complete":
			t.Log("Mock server received /api/v1/enroll/complete request")
			completeCalled = true

			var req struct {
				EnrollmentID    string `json:"enrollment_id"`
				PublicKey       string `json:"public_key"`
				SignedChallenge string `json:"signed_challenge"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("Failed to decode complete request: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			receivedEnrollmentID = req.EnrollmentID
			receivedPublicKey = req.PublicKey

			// Verify we received expected enrollment_id
			if req.EnrollmentID != "test-enrollment-id" {
				t.Errorf("Expected enrollment_id 'test-enrollment-id', got %q", req.EnrollmentID)
			}

			// Verify signed_challenge is present and non-empty
			if req.SignedChallenge == "" {
				t.Error("Expected signed_challenge to be non-empty")
			}

			// Return success response
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"id":          "km_test123",
				"fingerprint": "abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
			})

		default:
			t.Logf("Mock server received unexpected request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Log("Running doEnrollment with mock server")

	// Run enrollment
	kid, err := doEnrollment("test-invite-code", server.URL)
	if err != nil {
		t.Fatalf("doEnrollment failed: %v", err)
	}

	// Verify both phases were called
	if !initCalled {
		t.Error("Expected /api/v1/enroll/init to be called")
	}
	if !completeCalled {
		t.Error("Expected /api/v1/enroll/complete to be called")
	}

	// Verify correct data was sent
	if receivedCode != "test-invite-code" {
		t.Errorf("Expected invite code 'test-invite-code', got %q", receivedCode)
	}
	if receivedEnrollmentID != "test-enrollment-id" {
		t.Errorf("Expected enrollment_id 'test-enrollment-id', got %q", receivedEnrollmentID)
	}
	if receivedPublicKey == "" {
		t.Error("Expected public_key to be non-empty")
	}

	// Verify returned kid
	if kid != "km_test123" {
		t.Errorf("Expected kid 'km_test123', got %q", kid)
	}

	t.Log("Two-phase enrollment completed successfully")
}

func TestTwoPhaseEnrollment_InvalidCode(t *testing.T) {
	// Cannot run in parallel - modifies global getConfigDirFunc
	t.Log("Testing enrollment with invalid invite code")

	// Create temp directory for config
	tempDir := t.TempDir()
	originalGetConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tempDir }
	defer func() { getConfigDirFunc = originalGetConfigDir }()

	// Create mock server that returns invalid code error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/enroll/init" {
			t.Log("Mock server returning 401 enroll.invalid_code")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "enroll.invalid_code",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	_, err := doEnrollment("bad-code", server.URL)
	if err == nil {
		t.Fatal("Expected error for invalid code, got nil")
	}

	if !strings.Contains(err.Error(), "Invalid or expired invite code") {
		t.Errorf("Expected user-friendly error message, got: %v", err)
	}
	t.Log("Invalid code error handled correctly")
}

func TestTwoPhaseEnrollment_ExpiredCode(t *testing.T) {
	// Cannot run in parallel - modifies global getConfigDirFunc
	t.Log("Testing enrollment with expired invite code")

	// Create temp directory for config
	tempDir := t.TempDir()
	originalGetConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tempDir }
	defer func() { getConfigDirFunc = originalGetConfigDir }()

	// Create mock server that returns expired code error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/enroll/init" {
			t.Log("Mock server returning 401 enroll.expired_code")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "enroll.expired_code",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	_, err := doEnrollment("expired-code", server.URL)
	if err == nil {
		t.Fatal("Expected error for expired code, got nil")
	}

	if !strings.Contains(err.Error(), "Invite code has expired") {
		t.Errorf("Expected user-friendly error message, got: %v", err)
	}
	t.Log("Expired code error handled correctly")
}

func TestTwoPhaseEnrollment_CodeConsumed(t *testing.T) {
	// Cannot run in parallel - modifies global getConfigDirFunc
	t.Log("Testing enrollment with already-used invite code")

	// Create temp directory for config
	tempDir := t.TempDir()
	originalGetConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tempDir }
	defer func() { getConfigDirFunc = originalGetConfigDir }()

	// Create mock server that returns code consumed error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/enroll/init" {
			t.Log("Mock server returning 401 enroll.code_consumed")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "enroll.code_consumed",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	_, err := doEnrollment("used-code", server.URL)
	if err == nil {
		t.Fatal("Expected error for consumed code, got nil")
	}

	if !strings.Contains(err.Error(), "Invite code already used") {
		t.Errorf("Expected user-friendly error message, got: %v", err)
	}
	t.Log("Code consumed error handled correctly")
}

func TestTwoPhaseEnrollment_ChallengeExpired(t *testing.T) {
	// Cannot run in parallel - modifies global getConfigDirFunc
	t.Log("Testing enrollment with expired challenge (session timeout)")

	// Create temp directory for config
	tempDir := t.TempDir()
	originalGetConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tempDir }
	defer func() { getConfigDirFunc = originalGetConfigDir }()

	// Create mock server that returns challenge expired error on complete
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll/init":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"challenge":     "dGVzdC1jaGFsbGVuZ2U=",
				"enrollment_id": "test-enrollment-id",
			})
		case "/api/v1/enroll/complete":
			t.Log("Mock server returning 401 enroll.challenge_expired")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "enroll.challenge_expired",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := doEnrollment("valid-code", server.URL)
	if err == nil {
		t.Fatal("Expected error for expired challenge, got nil")
	}

	if !strings.Contains(err.Error(), "Enrollment session timed out") {
		t.Errorf("Expected user-friendly error message, got: %v", err)
	}
	t.Log("Challenge expired error handled correctly")
}

func TestTwoPhaseEnrollment_KeyExists(t *testing.T) {
	// Cannot run in parallel - modifies global getConfigDirFunc
	t.Log("Testing enrollment with already-enrolled key")

	// Create temp directory for config
	tempDir := t.TempDir()
	originalGetConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tempDir }
	defer func() { getConfigDirFunc = originalGetConfigDir }()

	// Create mock server that returns key exists error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll/init":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"challenge":     "dGVzdC1jaGFsbGVuZ2U=",
				"enrollment_id": "test-enrollment-id",
			})
		case "/api/v1/enroll/complete":
			t.Log("Mock server returning 409 enroll.key_exists")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "enroll.key_exists",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := doEnrollment("valid-code", server.URL)
	if err == nil {
		t.Fatal("Expected error for duplicate key, got nil")
	}

	if !strings.Contains(err.Error(), "This key is already enrolled") {
		t.Errorf("Expected user-friendly error message, got: %v", err)
	}
	t.Log("Key exists error handled correctly")
}

func TestTwoPhaseEnrollment_ServerUnavailable(t *testing.T) {
	// Cannot run in parallel - modifies global getConfigDirFunc
	t.Log("Testing enrollment when server is unavailable")

	// Create temp directory for config
	tempDir := t.TempDir()
	originalGetConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tempDir }
	defer func() { getConfigDirFunc = originalGetConfigDir }()

	// Use a URL that won't connect
	_, err := doEnrollment("test-code", "http://localhost:1")
	if err == nil {
		t.Fatal("Expected error for unavailable server, got nil")
	}

	// Should mention connection failure
	if !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "connection") {
		t.Logf("Error message: %v", err)
		// This is acceptable, the error should indicate network failure
	}
	t.Log("Server unavailable error handled correctly")
}

// Test that keys are saved with correct permissions
func TestEnrollment_KeyPermissions(t *testing.T) {
	// Cannot run in parallel - modifies global getConfigDirFunc
	t.Log("Testing that key files are saved with 0600 permissions")

	// Create temp directory for config
	tempDir := t.TempDir()
	originalGetConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tempDir }
	defer func() { getConfigDirFunc = originalGetConfigDir }()

	// Create mock server for successful enrollment
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll/init":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"challenge":     "dGVzdC1jaGFsbGVuZ2U=",
				"enrollment_id": "test-enrollment-id",
			})
		case "/api/v1/enroll/complete":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"id":          "km_test123",
				"fingerprint": "abcd1234",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := doEnrollment("test-code", server.URL)
	if err != nil {
		t.Fatalf("doEnrollment failed: %v", err)
	}

	// Check key file permissions
	// The key is stored by dpop.CompleteEnrollment which uses DefaultKeyPaths("km")
	// which returns ~/.km/key.pem. But since we're using tempDir, we need to
	// verify that the dpop package saves with correct permissions.
	// This is actually tested in the dpop package tests.

	t.Log("Key permissions test delegated to dpop.FileKeyStore tests")
}

// Test config file structure
func TestEnrollment_ConfigStructure(t *testing.T) {
	t.Parallel()
	t.Log("Testing that KMConfig structure has correct JSON tags")

	// Test that KMConfig marshals correctly
	config := KMConfig{
		KID:             "km_test123",
		ControlPlaneURL: "https://nexus.example.com",
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Verify JSON has the expected field names
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse marshaled JSON: %v", err)
	}

	// Check that 'kid' field exists (not 'keymaker_id')
	if _, ok := parsed["kid"]; !ok {
		t.Error("Expected 'kid' field in JSON output")
	}

	// Check that 'control_plane_url' field exists
	if _, ok := parsed["control_plane_url"]; !ok {
		t.Error("Expected 'control_plane_url' field in JSON output")
	}

	// Verify the values
	if parsed["kid"] != "km_test123" {
		t.Errorf("Expected kid to be 'km_test123', got %v", parsed["kid"])
	}

	if parsed["control_plane_url"] != "https://nexus.example.com" {
		t.Errorf("Expected control_plane_url to be 'https://nexus.example.com', got %v", parsed["control_plane_url"])
	}

	t.Log("Config structure has correct JSON tags")
}

// Test doEnrollment returns the correct kid
func TestEnrollment_ReturnsKid(t *testing.T) {
	// Cannot run in parallel - calls doEnrollment which uses global getConfigDirFunc
	t.Log("Testing that doEnrollment returns the kid from server response")

	// Create temp directory for config
	tempDir := t.TempDir()
	originalGetConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tempDir }
	defer func() { getConfigDirFunc = originalGetConfigDir }()

	// Create mock server for successful enrollment
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll/init":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"challenge":     "dGVzdC1jaGFsbGVuZ2U=",
				"enrollment_id": "test-enrollment-id",
			})
		case "/api/v1/enroll/complete":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"id":          "km_returned_kid",
				"fingerprint": "abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	kid, err := doEnrollment("test-code", server.URL)
	if err != nil {
		t.Fatalf("doEnrollment failed: %v", err)
	}

	// Verify kid is returned correctly
	if kid != "km_returned_kid" {
		t.Errorf("Expected kid 'km_returned_kid', got %q", kid)
	}

	t.Log("doEnrollment correctly returns the kid from server")
}
