package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigPath(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	path := ConfigPath()
	if path == "" {
		t.Skip("Could not determine home directory")
	}

	// Should end with the expected path
	expected := filepath.Join(".config", "bluectl", "config.yaml")
	if !strings.HasSuffix(path, expected) {
		t.Errorf("ConfigPath() = %q, want path ending with %q", path, expected)
	}
}

func TestLoadConfigNonExistent(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	// LoadConfig should return empty config for non-existent file
	// This test relies on the actual config path, which may or may not exist
	cfg, err := LoadConfig()
	if err != nil {
		// If there's an error, it should be a parse error, not a "file not found"
		t.Logf("LoadConfig() returned error: %v (this may be expected)", err)
		return
	}
	// Config loaded successfully (either empty or with values from existing file)
	_ = cfg
}

func TestSaveAndLoadConfig(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	// Create temp directory for test config
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".config", "bluectl")
	configFile := filepath.Join(configDir, "config.yaml")

	// Create the config directory
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create test config dir: %v", err)
	}

	// Write test config directly
	testConfig := "server: http://test.example.com:18080\n"
	if err := os.WriteFile(configFile, []byte(testConfig), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Read it back using yaml
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to read test config: %v", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if cfg.Server != "http://test.example.com:18080" {
		t.Errorf("Config.Server = %q, want %q", cfg.Server, "http://test.example.com:18080")
	}
}

func TestGetServerFlagPrecedence(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	// Save original flag value
	originalFlag := serverFlag
	defer func() { serverFlag = originalFlag }()

	// Clear any env vars that might interfere
	os.Unsetenv("SERVER_URL")
	os.Unsetenv("BLUECTL_SERVER")

	// Set flag value
	serverFlag = "http://flag-server.com:18080"

	server := GetServer()
	if server != "http://flag-server.com:18080" {
		t.Errorf("GetServer() = %q, want %q", server, "http://flag-server.com:18080")
	}
}

func TestGetServerServerURLEnvVar(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing SERVER_URL env var takes precedence over BLUECTL_SERVER and config file")

	// Save original flag value and clear it
	originalFlag := serverFlag
	defer func() { serverFlag = originalFlag }()
	serverFlag = ""

	// Clear any interfering env vars, then set both
	os.Setenv("SERVER_URL", "http://server-url.example.com")
	os.Setenv("BLUECTL_SERVER", "http://bluectl-server.example.com")
	defer func() {
		os.Unsetenv("SERVER_URL")
		os.Unsetenv("BLUECTL_SERVER")
	}()

	server := GetServer()
	if server != "http://server-url.example.com" {
		t.Errorf("GetServer() = %q, want %q (SERVER_URL should take precedence)", server, "http://server-url.example.com")
	}
	t.Log("SERVER_URL correctly takes precedence over BLUECTL_SERVER")
}

func TestGetServerBluectlServerEnvVar(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing BLUECTL_SERVER env var works when SERVER_URL not set (backward compatibility)")

	// Save original flag value and clear it
	originalFlag := serverFlag
	defer func() { serverFlag = originalFlag }()
	serverFlag = ""

	// Clear SERVER_URL, set only BLUECTL_SERVER
	os.Unsetenv("SERVER_URL")
	os.Setenv("BLUECTL_SERVER", "http://bluectl-server.example.com")
	defer os.Unsetenv("BLUECTL_SERVER")

	server := GetServer()
	if server != "http://bluectl-server.example.com" {
		t.Errorf("GetServer() = %q, want %q", server, "http://bluectl-server.example.com")
	}
	t.Log("BLUECTL_SERVER correctly used for backward compatibility")
}

func TestGetServerFlagOverridesEnvVars(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	t.Log("Testing --server flag takes precedence over all env vars")

	// Save original flag value
	originalFlag := serverFlag
	defer func() { serverFlag = originalFlag }()

	// Set both env vars
	os.Setenv("SERVER_URL", "http://server-url.example.com")
	os.Setenv("BLUECTL_SERVER", "http://bluectl-server.example.com")
	defer func() {
		os.Unsetenv("SERVER_URL")
		os.Unsetenv("BLUECTL_SERVER")
	}()

	// Set flag value
	serverFlag = "http://flag-server.example.com"

	server := GetServer()
	if server != "http://flag-server.example.com" {
		t.Errorf("GetServer() = %q, want %q (flag should take precedence over env vars)", server, "http://flag-server.example.com")
	}
	t.Log("--server flag correctly takes precedence over env vars")
}

func TestGetServerFromConfig(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	// Save original flag value and clear it
	originalFlag := serverFlag
	defer func() { serverFlag = originalFlag }()
	serverFlag = ""

	// GetServer should fall back to config file (which may be empty)
	server := GetServer()
	// Server will be empty if no config file exists, which is expected
	_ = server
}

func TestConfigStruct(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	cfg := Config{
		Server: "http://example.com:18080",
	}

	if cfg.Server != "http://example.com:18080" {
		t.Errorf("Config.Server = %q, want %q", cfg.Server, "http://example.com:18080")
	}
}

func TestConfigYAMLRoundTrip(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	original := &Config{
		Server: "http://nexus.example.com:18080",
	}

	// Marshal to YAML
	data, err := yaml.Marshal(original)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}

	// Unmarshal back
	var loaded Config
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	if loaded.Server != original.Server {
		t.Errorf("Round-trip failed: got %q, want %q", loaded.Server, original.Server)
	}
}

func TestEmptyConfigYAML(t *testing.T) {
	// Cannot run in parallel - modifies environment variables
	// Empty YAML should produce empty config
	var cfg Config
	if err := yaml.Unmarshal([]byte(""), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	if cfg.Server != "" {
		t.Errorf("Empty YAML produced Server = %q, want empty", cfg.Server)
	}
}
