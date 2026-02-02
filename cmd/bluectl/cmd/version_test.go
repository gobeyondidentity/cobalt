package cmd

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/internal/testutil/cli"
	"github.com/gobeyondidentity/secure-infra/internal/testutil/mockhttp"
	"github.com/gobeyondidentity/secure-infra/internal/version"
	"github.com/gobeyondidentity/secure-infra/internal/versioncheck"
)

func TestVersionCommand_BasicOutput(t *testing.T) {
	// Cannot run in parallel - uses shared cobra command state
	t.Log("Test that version command shows current version")

	cmd := newVersionCmd()
	result := cli.Run(cmd)
	result.AssertSuccess(t)

	// Should contain "bluectl version X.Y.Z"
	expectedPrefix := "bluectl version " + version.Version
	result.AssertPrefix(t, expectedPrefix)
}

func TestVersionCommand_CheckFlag_UpdateAvailable(t *testing.T) {
	// Cannot run in parallel - uses shared cobra command state
	t.Log("Test that version --check shows newer version available")

	// Save and restore original version (may be "dev" in dev builds)
	originalVersion := version.Version
	version.Version = "1.0.0"
	defer func() { version.Version = originalVersion }()

	// Mock server that returns a newer version using mockhttp builder
	url, close := mockhttp.New().
		JSON("/repos/gobeyondidentity/secure-infra/releases/latest", map[string]string{
			"tag_name": "v99.99.99",
			"html_url": "https://github.com/gobeyondidentity/secure-infra/releases/tag/v99.99.99",
		}).
		BuildURL()
	defer close()

	// Use temp cache to avoid polluting real cache
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	// Create checker with mock server
	checker := &versioncheck.Checker{
		GitHubClient: versioncheck.NewGitHubClient(url),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	cmd := newVersionCmdWithChecker(checker)
	result := cli.Run(cmd, "--check")
	result.AssertSuccess(t)

	// Should show current version
	result.AssertContains(t, "bluectl version "+version.Version)

	// Should show newer version available
	result.AssertContains(t, "A newer version is available: 99.99.99")

	// Should show release notes URL
	result.AssertContains(t, "Release notes:")

	// Should show upgrade command
	result.AssertContains(t, "To upgrade:")
}

func TestVersionCommand_CheckFlag_NoUpdate(t *testing.T) {
	// Cannot run in parallel - uses shared cobra command state
	t.Log("Test that version --check shows up to date when current")

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
	result := cli.Run(cmd, "--check")
	result.AssertSuccess(t)

	// Should show current version
	result.AssertContains(t, "bluectl version "+version.Version)

	// Should indicate no update available
	result.AssertContains(t, "You are running the latest version")
}

func TestVersionCommand_CheckFlag_NetworkError(t *testing.T) {
	// Cannot run in parallel - uses shared cobra command state
	t.Log("Test that version --check handles network errors gracefully")

	// Mock server that returns an error using mockhttp builder
	url, close := mockhttp.New().
		Status("/repos/gobeyondidentity/secure-infra/releases/latest", http.StatusServiceUnavailable).
		BuildURL()
	defer close()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")
	// No cache exists, so the check should fail gracefully

	checker := &versioncheck.Checker{
		GitHubClient: versioncheck.NewGitHubClient(url),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	cmd := newVersionCmdWithChecker(checker)
	result := cli.Run(cmd, "--check")
	result.AssertSuccess(t)

	// Should still show current version
	result.AssertContains(t, "bluectl version "+version.Version)

	// Should show graceful error message
	result.AssertContains(t, "Could not check for updates")
}

func TestVersionCommand_SkipUpdateCheck(t *testing.T) {
	// Cannot run in parallel - uses shared cobra command state
	t.Log("Test that version --skip-update-check does not contact server")

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
	result := cli.Run(cmd, "--skip-update-check")
	result.AssertSuccess(t)

	if serverCalled {
		t.Error("server should not be called when --skip-update-check is set")
	}

	// Should only show version
	result.AssertContains(t, "bluectl version "+version.Version)

	// Should NOT contain update check messages
	result.AssertNotContains(t, "newer version")
	result.AssertNotContains(t, "latest version")
}

func TestVersionCommand_NoFlags_ShowsOnlyVersion(t *testing.T) {
	// Cannot run in parallel - uses shared cobra command state
	t.Log("Test that version without flags shows only version")

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
	result := cli.Run(cmd)
	result.AssertSuccess(t)

	if serverCalled {
		t.Error("server should not be called without --check flag")
	}

	expected := "bluectl version " + version.Version + "\n"
	result.AssertExact(t, expected)
}

func TestVersionCommand_OutputFormat(t *testing.T) {
	// Cannot run in parallel - uses shared cobra command state
	t.Log("Verify exact output format matches spec")

	cmd := newVersionCmd()
	result := cli.Run(cmd)
	result.AssertSuccess(t)

	// Should be exactly "bluectl version X.Y.Z\n"
	expected := "bluectl version " + version.Version + "\n"
	result.AssertExact(t, expected)
}

// TestVersionCommandRegistered verifies version command is added to root
func TestVersionCommandRegistered(t *testing.T) {
	// Cannot run in parallel - uses shared cobra command state
	t.Log("Verify version command is registered in rootCmd")

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
	// Cannot run in parallel - uses shared cobra command state
	t.Log("Verify rootCmd.Version is empty (we use version subcommand)")

	// rootCmd.Version should be empty since we use a subcommand instead
	if rootCmd.Version != "" {
		t.Errorf("rootCmd.Version should be empty (we use version subcommand), got %q", rootCmd.Version)
	}
}
