package cmd

import (
	"bytes"
	jsonPkg "encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
)

func TestAuthStatusNotEnrolled(t *testing.T) {
	t.Log("Testing auth status when not enrolled")

	// Use temp directory for key paths
	tmpDir := t.TempDir()
	t.Setenv("KM_KEY_PATH", filepath.Join(tmpDir, "key.pem"))
	t.Setenv("KM_KID_PATH", filepath.Join(tmpDir, "kid"))

	// Override config loading to return no config
	origConfigDir := getConfigDirFunc
	getConfigDirFunc = func() string { return tmpDir }
	defer func() { getConfigDirFunc = origConfigDir }()

	status := AuthStatus{}

	keyPath, kidPath := dpop.DefaultKeyPaths("km")
	status.KeyPath = keyPath
	status.KIDPath = kidPath

	keyStore := dpop.NewFileKeyStore(keyPath)
	status.KeyExists = keyStore.Exists()

	kidStore := dpop.NewFileKIDStore(kidPath)
	status.KIDExists = kidStore.Exists()

	status.Enrolled = status.KeyExists && status.KIDExists

	if status.Enrolled {
		t.Error("expected not enrolled when key files don't exist")
	}
	if status.KeyExists {
		t.Error("expected key to not exist")
	}
	if status.KIDExists {
		t.Error("expected kid to not exist")
	}

	t.Log("Auth status correctly shows not enrolled state")
}

func TestAuthStatusEnrolled(t *testing.T) {
	t.Log("Testing auth status when enrolled")

	// Use temp directory for key paths
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	kidPath := filepath.Join(tmpDir, "kid")
	t.Setenv("KM_KEY_PATH", keyPath)
	t.Setenv("KM_KID_PATH", kidPath)

	// Create mock key and kid files
	if err := os.WriteFile(keyPath, []byte("mock key"), 0600); err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	if err := os.WriteFile(kidPath, []byte("km_test123"), 0600); err != nil {
		t.Fatalf("failed to create kid file: %v", err)
	}

	status := AuthStatus{}

	keyPath2, kidPath2 := dpop.DefaultKeyPaths("km")
	status.KeyPath = keyPath2
	status.KIDPath = kidPath2

	keyStore := dpop.NewFileKeyStore(keyPath2)
	status.KeyExists = keyStore.Exists()

	kidStore := dpop.NewFileKIDStore(kidPath2)
	status.KIDExists = kidStore.Exists()

	status.Enrolled = status.KeyExists && status.KIDExists

	if !status.Enrolled {
		t.Error("expected enrolled when key files exist")
	}
	if !status.KeyExists {
		t.Error("expected key to exist")
	}
	if !status.KIDExists {
		t.Error("expected kid to exist")
	}

	t.Log("Auth status correctly shows enrolled state")
}

func TestCheckServerConnectivity(t *testing.T) {
	t.Log("Testing server connectivity check")

	// Test with a mock server that responds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	ok, errMsg := checkServerConnectivity(server.URL)
	if !ok {
		t.Errorf("expected server to be reachable, got error: %s", errMsg)
	}

	t.Log("Connectivity check passes for reachable server")
}

func TestCheckServerConnectivityUnreachable(t *testing.T) {
	t.Log("Testing server connectivity check for unreachable server")

	// Use a URL that will definitely fail
	ok, errMsg := checkServerConnectivity("http://localhost:1")
	if ok {
		t.Error("expected server to be unreachable")
	}
	if errMsg == "" {
		t.Error("expected error message for unreachable server")
	}

	t.Log("Connectivity check correctly identifies unreachable server")
}

func TestAuthStatusJSONOutput(t *testing.T) {
	t.Log("Testing auth status JSON output structure")

	status := AuthStatus{
		Enrolled:    true,
		KeyPath:     "/home/user/.km/key.pem",
		KeyExists:   true,
		KIDPath:     "/home/user/.km/kid",
		KIDExists:   true,
		ServerURL:   "https://example.com",
		ServerOK:    true,
		ServerError: "",
	}

	// Verify JSON marshaling works via encoding/json directly
	var buf bytes.Buffer
	enc := jsonPkg.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(status); err != nil {
		t.Fatalf("failed to encode status as JSON: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"enrolled": true`) {
		t.Errorf("JSON output missing enrolled field, got: %s", output)
	}
	if !strings.Contains(output, `"key_path"`) {
		t.Errorf("JSON output missing key_path field, got: %s", output)
	}
	if !strings.Contains(output, `"server_reachable": true`) {
		t.Errorf("JSON output missing server_reachable field, got: %s", output)
	}

	t.Log("Auth status JSON output has correct structure")
}
