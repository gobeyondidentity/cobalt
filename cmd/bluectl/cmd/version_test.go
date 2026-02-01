package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/internal/version"
	"github.com/gobeyondidentity/secure-infra/internal/versioncheck"
)

func TestVersionCommand_BasicOutput(t *testing.T) {
	// Test that version command shows current version
	cmd := newVersionCmd()

	// Capture output
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	// Execute without --check flag
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	output := stdout.String()

	// Should contain "bluectl version X.Y.Z"
	expectedPrefix := "bluectl version " + version.Version
	if !strings.HasPrefix(strings.TrimSpace(output), expectedPrefix) {
		t.Errorf("expected output to start with %q, got %q", expectedPrefix, output)
	}
}

func TestVersionCommand_CheckFlag_UpdateAvailable(t *testing.T) {
	// Save and restore original version (may be "dev" in dev builds)
	originalVersion := version.Version
	version.Version = "1.0.0"
	defer func() { version.Version = originalVersion }()

	// Mock server that returns a newer version
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"tag_name": "v99.99.99",
			"html_url": "https://github.com/gobeyondidentity/secure-infra/releases/tag/v99.99.99"
		}`))
	}))
	defer server.Close()

	// Use temp cache to avoid polluting real cache
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	// Create checker with mock server
	checker := &versioncheck.Checker{
		GitHubClient: versioncheck.NewGitHubClient(server.URL),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	cmd := newVersionCmdWithChecker(checker)

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--check"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("version --check failed: %v", err)
	}

	output := stdout.String()

	// Should show current version
	if !strings.Contains(output, "bluectl version "+version.Version) {
		t.Errorf("expected output to contain current version, got %q", output)
	}

	// Should show newer version available
	if !strings.Contains(output, "A newer version is available: 99.99.99") {
		t.Errorf("expected output to contain newer version message, got %q", output)
	}

	// Should show release notes URL
	if !strings.Contains(output, "Release notes:") {
		t.Errorf("expected output to contain release notes, got %q", output)
	}

	// Should show upgrade command
	if !strings.Contains(output, "To upgrade:") {
		t.Errorf("expected output to contain upgrade instructions, got %q", output)
	}
}

func TestVersionCommand_CheckFlag_NoUpdate(t *testing.T) {
	// Mock server that returns current version
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return the same version as current
		_, _ = w.Write([]byte(`{
			"tag_name": "v` + version.Version + `",
			"html_url": "https://github.com/gobeyondidentity/secure-infra/releases/tag/v` + version.Version + `"
		}`))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	checker := &versioncheck.Checker{
		GitHubClient: versioncheck.NewGitHubClient(server.URL),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	cmd := newVersionCmdWithChecker(checker)

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--check"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("version --check failed: %v", err)
	}

	output := stdout.String()

	// Should show current version
	if !strings.Contains(output, "bluectl version "+version.Version) {
		t.Errorf("expected output to contain current version, got %q", output)
	}

	// Should indicate no update available
	if !strings.Contains(output, "You are running the latest version") {
		t.Errorf("expected 'latest version' message, got %q", output)
	}
}

func TestVersionCommand_CheckFlag_NetworkError(t *testing.T) {
	// Mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")
	// No cache exists, so the check should fail gracefully

	checker := &versioncheck.Checker{
		GitHubClient: versioncheck.NewGitHubClient(server.URL),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	cmd := newVersionCmdWithChecker(checker)

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--check"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("version --check should not error on network failure: %v", err)
	}

	output := stdout.String()

	// Should still show current version
	if !strings.Contains(output, "bluectl version "+version.Version) {
		t.Errorf("expected output to contain current version, got %q", output)
	}

	// Should show graceful error message
	if !strings.Contains(output, "Could not check for updates") {
		t.Errorf("expected graceful error message, got %q", output)
	}
}

func TestVersionCommand_SkipUpdateCheck(t *testing.T) {
	// Server should NOT be called when --skip-update-check is set
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	checker := &versioncheck.Checker{
		GitHubClient: versioncheck.NewGitHubClient(server.URL),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	cmd := newVersionCmdWithChecker(checker)

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--skip-update-check"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("version --skip-update-check failed: %v", err)
	}

	if serverCalled {
		t.Error("server should not be called when --skip-update-check is set")
	}

	output := stdout.String()

	// Should only show version
	if !strings.Contains(output, "bluectl version "+version.Version) {
		t.Errorf("expected output to contain version, got %q", output)
	}

	// Should NOT contain update check messages
	if strings.Contains(output, "newer version") || strings.Contains(output, "latest version") {
		t.Errorf("should not contain update check messages, got %q", output)
	}
}

func TestVersionCommand_NoFlags_ShowsOnlyVersion(t *testing.T) {
	// Without flags, should only show version (no network call)
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	checker := &versioncheck.Checker{
		GitHubClient: versioncheck.NewGitHubClient(server.URL),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	cmd := newVersionCmdWithChecker(checker)

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	// No args

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	if serverCalled {
		t.Error("server should not be called without --check flag")
	}

	output := stdout.String()
	expected := "bluectl version " + version.Version + "\n"
	if output != expected {
		t.Errorf("expected exactly %q, got %q", expected, output)
	}
}

func TestVersionCommand_OutputFormat(t *testing.T) {
	// Verify exact output format matches spec
	cmd := newVersionCmd()

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	output := stdout.String()

	// Should be exactly "bluectl version X.Y.Z\n"
	expected := "bluectl version " + version.Version + "\n"
	if output != expected {
		t.Errorf("output format mismatch:\nexpected: %q\ngot:      %q", expected, output)
	}
}

// TestVersionCommandRegistered verifies version command is added to root
func TestVersionCommandRegistered(t *testing.T) {
	// Find version command in rootCmd
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "version" {
			found = true
			break
		}
	}

	if !found {
		t.Error("version command not found in rootCmd")
	}
}

// TestRootCmdVersionFieldRemoved verifies we removed the built-in Version field
func TestRootCmdVersionFieldRemoved(t *testing.T) {
	// rootCmd.Version should be empty since we use a subcommand instead
	if rootCmd.Version != "" {
		t.Errorf("rootCmd.Version should be empty (we use version subcommand), got %q", rootCmd.Version)
	}
}
