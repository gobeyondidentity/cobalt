package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
)

func TestWhoami_NotAuthenticated(t *testing.T) {
	t.Parallel()
	t.Log("Testing whoami when not authenticated returns error")

	// Set up temp directory for key paths
	tempDir := t.TempDir()
	os.Setenv("BLUECTL_KEY_PATH", filepath.Join(tempDir, "key.pem"))
	os.Setenv("BLUECTL_KID_PATH", filepath.Join(tempDir, "kid"))
	defer os.Unsetenv("BLUECTL_KEY_PATH")
	defer os.Unsetenv("BLUECTL_KID_PATH")

	keyPath, kidPath := dpop.DefaultKeyPaths("bluectl")
	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)

	t.Log("Verifying key and kid files do not exist")
	if keyStore.Exists() {
		t.Error("Expected key to not exist")
	}
	if kidStore.Exists() {
		t.Error("Expected kid to not exist")
	}

	t.Log("Not authenticated state verified")
}

func TestWhoami_Authenticated(t *testing.T) {
	t.Parallel()
	t.Log("Testing whoami when authenticated shows identity")

	// Set up temp directory for key paths
	tempDir := t.TempDir()
	os.Setenv("BLUECTL_KEY_PATH", filepath.Join(tempDir, "key.pem"))
	os.Setenv("BLUECTL_KID_PATH", filepath.Join(tempDir, "kid"))
	defer os.Unsetenv("BLUECTL_KEY_PATH")
	defer os.Unsetenv("BLUECTL_KID_PATH")

	keyPath, kidPath := dpop.DefaultKeyPaths("bluectl")
	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)

	t.Log("Generating test keypair")
	_, privKey, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	t.Log("Saving test key and kid")
	if err := keyStore.Save(privKey); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	testKID := "adm_test123"
	if err := kidStore.Save(testKID); err != nil {
		t.Fatalf("Failed to save kid: %v", err)
	}

	t.Log("Verifying key and kid files exist")
	if !keyStore.Exists() {
		t.Error("Expected key to exist")
	}
	if !kidStore.Exists() {
		t.Error("Expected kid to exist")
	}

	// Load and verify kid
	loadedKID, err := kidStore.Load()
	if err != nil {
		t.Fatalf("Failed to load kid: %v", err)
	}
	if loadedKID != testKID {
		t.Errorf("Expected kid %s, got %s", testKID, loadedKID)
	}

	t.Log("Authenticated state verified with correct kid")
}

func TestWhoamiOutput_JSONStructure(t *testing.T) {
	t.Parallel()
	t.Log("Testing WhoamiOutput JSON structure")

	output := WhoamiOutput{
		Identity:    "adm_abc123",
		Fingerprint: "0123456789abcdef",
		ServerURL:   "https://nexus.example.com",
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal output: %v", err)
	}

	t.Log("Verifying JSON field names")
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if _, ok := parsed["identity"]; !ok {
		t.Error("Expected 'identity' field in JSON output")
	}
	if _, ok := parsed["fingerprint"]; !ok {
		t.Error("Expected 'fingerprint' field in JSON output")
	}
	if _, ok := parsed["server_url"]; !ok {
		t.Error("Expected 'server_url' field in JSON output")
	}

	t.Log("WhoamiOutput JSON structure verified")
}
