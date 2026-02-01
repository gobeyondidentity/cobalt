package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nmelo/secure-infra/pkg/dpop"
)

func TestInitCmd_HappyPath(t *testing.T) {
	t.Log("Testing successful bootstrap enrollment flow")

	// Create temp directory for test config
	tmpDir := t.TempDir()
	homeDir := tmpDir

	// Override home directory for dpop paths
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	t.Log("Setting up mock server that accepts bootstrap requests")

	// Track enrollment state
	var capturedPubKey []byte
	var capturedChallenge []byte

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Mock server received: %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/api/v1/admin/bootstrap":
			t.Log("Handling bootstrap request")

			var req bootstrapRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("Failed to decode bootstrap request: %v", err)
				http.Error(w, `{"error": "invalid_request"}`, http.StatusBadRequest)
				return
			}

			// Decode and store public key
			var err error
			capturedPubKey, err = base64.StdEncoding.DecodeString(req.PublicKey)
			if err != nil {
				t.Errorf("Failed to decode public key: %v", err)
				http.Error(w, `{"error": "invalid_public_key"}`, http.StatusBadRequest)
				return
			}

			if len(capturedPubKey) != ed25519.PublicKeySize {
				t.Errorf("Invalid public key size: got %d, want %d", len(capturedPubKey), ed25519.PublicKeySize)
				http.Error(w, `{"error": "invalid_public_key_size"}`, http.StatusBadRequest)
				return
			}

			t.Logf("Received valid public key (length: %d bytes)", len(capturedPubKey))

			// Generate challenge
			capturedChallenge = []byte("test-challenge-32-bytes-long!!")
			challengeBase64 := base64.StdEncoding.EncodeToString(capturedChallenge)

			resp := bootstrapResponse{
				Challenge:    challengeBase64,
				EnrollmentID: "enroll_test_admin",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			t.Log("Bootstrap challenge sent")

		case "/api/v1/enroll/complete":
			t.Log("Handling enrollment complete request")

			var req enrollCompleteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("Failed to decode complete request: %v", err)
				http.Error(w, `{"error": "invalid_request"}`, http.StatusBadRequest)
				return
			}

			if req.EnrollmentID != "enroll_test_admin" {
				t.Errorf("Unexpected enrollment ID: %s", req.EnrollmentID)
				http.Error(w, `{"error": "invalid_enrollment_id"}`, http.StatusBadRequest)
				return
			}

			// Verify signature
			pubKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
			if err != nil {
				t.Errorf("Failed to decode public key in complete: %v", err)
				http.Error(w, `{"error": "invalid_public_key"}`, http.StatusBadRequest)
				return
			}

			sig, err := base64.StdEncoding.DecodeString(req.SignedChallenge)
			if err != nil {
				t.Errorf("Failed to decode signature: %v", err)
				http.Error(w, `{"error": "invalid_signature"}`, http.StatusBadRequest)
				return
			}

			if !ed25519.Verify(pubKey, capturedChallenge, sig) {
				t.Error("Signature verification failed")
				http.Error(w, `{"error": "enroll.invalid_signature"}`, http.StatusUnauthorized)
				return
			}

			t.Log("Signature verified successfully")

			resp := enrollCompleteResponse{
				ID:          "adm_test123",
				Fingerprint: "sha256:abc123def456",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			t.Log("Enrollment complete response sent")

		default:
			t.Errorf("Unexpected request path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Log("Mock server started at " + server.URL)

	// Set server URL via flag
	serverFlag = server.URL
	defer func() { serverFlag = "" }()

	t.Log("Executing init command")

	// Run the command
	err := runInit(initCmd, []string{})
	if err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	t.Log("Verifying identity was saved")

	// Verify identity was saved
	keyPath, kidPath := dpop.DefaultKeyPaths("bluectl")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Private key file was not created")
	}
	if _, err := os.Stat(kidPath); os.IsNotExist(err) {
		t.Error("KID file was not created")
	}

	// Verify KID content
	kidData, err := os.ReadFile(kidPath)
	if err != nil {
		t.Fatalf("Failed to read kid file: %v", err)
	}
	if string(kidData) != "adm_test123" {
		t.Errorf("KID mismatch: got %q, want %q", string(kidData), "adm_test123")
	}

	t.Log("Identity saved successfully with correct KID")
}

func TestInitCmd_BootstrapWindowClosed(t *testing.T) {
	t.Log("Testing bootstrap window closed error handling")

	// Create temp directory for test config
	tmpDir := t.TempDir()
	homeDir := tmpDir

	// Override home directory for dpop paths
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	t.Log("Setting up mock server that returns window_closed error")

	// Create mock server that returns window closed error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Mock server received: %s %s", r.Method, r.URL.Path)

		if r.URL.Path == "/api/v1/admin/bootstrap" {
			t.Log("Returning bootstrap.window_closed error")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(errorResponse{Error: "bootstrap.window_closed"})
			return
		}

		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	// Set server URL via flag
	serverFlag = server.URL
	defer func() { serverFlag = "" }()

	t.Log("Executing init command (expecting window closed error)")

	// Run the command
	err := runInit(initCmd, []string{})
	if err == nil {
		t.Fatal("Expected error for window closed, got nil")
	}

	if err.Error() != "bootstrap window closed" {
		t.Errorf("Unexpected error message: %v", err)
	}

	t.Log("Window closed error handled correctly")
}

func TestInitCmd_AlreadyEnrolled(t *testing.T) {
	t.Log("Testing already enrolled error handling")

	// Create temp directory for test config
	tmpDir := t.TempDir()
	homeDir := tmpDir

	// Override home directory for dpop paths
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	t.Log("Setting up mock server that returns already_enrolled error")

	// Create mock server that returns already enrolled error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Mock server received: %s %s", r.Method, r.URL.Path)

		if r.URL.Path == "/api/v1/admin/bootstrap" {
			t.Log("Returning bootstrap.already_enrolled error")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(errorResponse{Error: "bootstrap.already_enrolled"})
			return
		}

		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	// Set server URL via flag
	serverFlag = server.URL
	defer func() { serverFlag = "" }()

	t.Log("Executing init command (expecting already enrolled error)")

	// Run the command
	err := runInit(initCmd, []string{})
	if err == nil {
		t.Fatal("Expected error for already enrolled, got nil")
	}

	if err.Error() != "first admin already enrolled" {
		t.Errorf("Unexpected error message: %v", err)
	}

	t.Log("Already enrolled error handled correctly")
}

func TestInitCmd_AlreadyEnrolledLocally(t *testing.T) {
	t.Log("Testing local enrollment check (already enrolled locally)")

	// Create temp directory for test config
	tmpDir := t.TempDir()
	homeDir := tmpDir

	// Override home directory for dpop paths
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	t.Log("Creating existing identity files")

	// Create existing identity
	keyPath, kidPath := dpop.DefaultKeyPaths("bluectl")
	keyDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("Failed to create key directory: %v", err)
	}

	// Create dummy key file
	if err := os.WriteFile(keyPath, []byte("dummy-key"), 0600); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	// Create dummy kid file
	if err := os.WriteFile(kidPath, []byte("adm_existing"), 0600); err != nil {
		t.Fatalf("Failed to create kid file: %v", err)
	}

	// Set server URL via flag (won't be used since we're already enrolled)
	serverFlag = "http://localhost:18080"
	defer func() { serverFlag = "" }()

	t.Log("Executing init command without --force (expecting already enrolled error)")

	// Run the command without --force
	err := runInit(initCmd, []string{})
	if err == nil {
		t.Fatal("Expected error for local already enrolled, got nil")
	}

	if err.Error() != "already enrolled. Use --force to re-enroll" {
		t.Errorf("Unexpected error message: %v", err)
	}

	t.Log("Local already enrolled check works correctly")
}

func TestInitCmd_ForceReenrollment(t *testing.T) {
	t.Log("Testing force re-enrollment with --force flag")

	// Create temp directory for test config
	tmpDir := t.TempDir()
	homeDir := tmpDir

	// Override home directory for dpop paths
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	t.Log("Creating existing identity files")

	// Create existing identity
	keyPath, kidPath := dpop.DefaultKeyPaths("bluectl")
	keyDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("Failed to create key directory: %v", err)
	}

	// Create dummy key file
	if err := os.WriteFile(keyPath, []byte("dummy-key"), 0600); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	// Create dummy kid file
	if err := os.WriteFile(kidPath, []byte("adm_existing"), 0600); err != nil {
		t.Fatalf("Failed to create kid file: %v", err)
	}

	t.Log("Setting up mock server for re-enrollment")

	// Track enrollment state
	var capturedChallenge []byte

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Mock server received: %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/api/v1/admin/bootstrap":
			var req bootstrapRequest
			json.NewDecoder(r.Body).Decode(&req)

			capturedChallenge = []byte("test-challenge-for-force-reroll")
			challengeBase64 := base64.StdEncoding.EncodeToString(capturedChallenge)

			resp := bootstrapResponse{
				Challenge:    challengeBase64,
				EnrollmentID: "enroll_force_admin",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case "/api/v1/enroll/complete":
			var req enrollCompleteRequest
			json.NewDecoder(r.Body).Decode(&req)

			// Verify signature
			pubKey, _ := base64.StdEncoding.DecodeString(req.PublicKey)
			sig, _ := base64.StdEncoding.DecodeString(req.SignedChallenge)

			if !ed25519.Verify(pubKey, capturedChallenge, sig) {
				http.Error(w, `{"error": "enroll.invalid_signature"}`, http.StatusUnauthorized)
				return
			}

			resp := enrollCompleteResponse{
				ID:          "adm_force_new",
				Fingerprint: "sha256:newfingerprint",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Set server URL via flag
	serverFlag = server.URL
	defer func() { serverFlag = "" }()

	t.Log("Executing init command with --force flag")

	// Set force flag
	initCmd.Flags().Set("force", "true")
	defer initCmd.Flags().Set("force", "false")

	// Run the command with --force
	err := runInit(initCmd, []string{})
	if err != nil {
		t.Fatalf("runInit with --force failed: %v", err)
	}

	t.Log("Verifying new identity was saved")

	// Verify new KID was saved
	kidData, err := os.ReadFile(kidPath)
	if err != nil {
		t.Fatalf("Failed to read kid file: %v", err)
	}
	if string(kidData) != "adm_force_new" {
		t.Errorf("KID mismatch after force: got %q, want %q", string(kidData), "adm_force_new")
	}

	t.Log("Force re-enrollment completed successfully")
}

func TestInitCmd_ServerConfigSaved(t *testing.T) {
	t.Log("Testing that server URL is saved to config on success")

	// Create temp directory for test config
	tmpDir := t.TempDir()
	homeDir := tmpDir

	// Override home directory for dpop paths
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	// Track enrollment state
	var capturedChallenge []byte

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/admin/bootstrap":
			var req bootstrapRequest
			json.NewDecoder(r.Body).Decode(&req)

			capturedChallenge = []byte("config-test-challenge-bytes!!")
			challengeBase64 := base64.StdEncoding.EncodeToString(capturedChallenge)

			resp := bootstrapResponse{
				Challenge:    challengeBase64,
				EnrollmentID: "enroll_config_test",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case "/api/v1/enroll/complete":
			var req enrollCompleteRequest
			json.NewDecoder(r.Body).Decode(&req)

			pubKey, _ := base64.StdEncoding.DecodeString(req.PublicKey)
			sig, _ := base64.StdEncoding.DecodeString(req.SignedChallenge)

			if !ed25519.Verify(pubKey, capturedChallenge, sig) {
				http.Error(w, `{"error": "enroll.invalid_signature"}`, http.StatusUnauthorized)
				return
			}

			resp := enrollCompleteResponse{
				ID:          "adm_config_test",
				Fingerprint: "sha256:configtest",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Set server URL via flag
	serverFlag = server.URL
	defer func() { serverFlag = "" }()

	t.Log("Executing init command")

	// Run the command
	err := runInit(initCmd, []string{})
	if err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	t.Log("Verifying config was saved with server URL")

	// Verify config was saved
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Server != server.URL {
		t.Errorf("Config server mismatch: got %q, want %q", cfg.Server, server.URL)
	}

	t.Log("Server URL saved to config successfully")
}

func TestInitCmd_HasForceFlag(t *testing.T) {
	t.Log("Verifying init command has --force flag defined")

	flag := initCmd.Flags().Lookup("force")
	if flag == nil {
		t.Fatal("Expected --force flag to be defined on init command")
	}

	if flag.DefValue != "false" {
		t.Errorf("Expected default value 'false', got %q", flag.DefValue)
	}

	t.Log("--force flag is correctly defined")
}

func TestInitCmd_ShortDescription(t *testing.T) {
	t.Log("Verifying init command has appropriate short description")

	if initCmd.Short == "" {
		t.Error("Expected Short description to be set")
	}

	if initCmd.Long == "" {
		t.Error("Expected Long description to be set")
	}

	t.Log("Command descriptions are set correctly")
}
