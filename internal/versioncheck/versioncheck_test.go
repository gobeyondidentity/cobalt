package versioncheck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/internal/testutil/mockhttp"
)

// ----- InstallMethod Detection Tests -----

func TestDetectInstallMethod_Homebrew_Cellar(t *testing.T) {
	// Test with /Cellar/ in path
	method := DetectInstallMethodFromPath("/usr/local/Cellar/bluectl/0.5.2/bin/bluectl")
	if method != Homebrew {
		t.Errorf("expected Homebrew, got %v", method)
	}
}

func TestDetectInstallMethod_Homebrew_HomePath(t *testing.T) {
	// Test with /homebrew/ in path
	method := DetectInstallMethodFromPath("/opt/homebrew/bin/bluectl")
	if method != Homebrew {
		t.Errorf("expected Homebrew, got %v", method)
	}
}

func TestDetectInstallMethod_DirectDownload(t *testing.T) {
	// Default fallback when no detection matches
	method := DetectInstallMethodFromPath("/usr/local/bin/bluectl")
	if method != DirectDownload {
		t.Errorf("expected DirectDownload, got %v", method)
	}
}

// ----- Version Comparison Tests -----

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		latest   string
		expected bool
	}{
		{"newer available", "0.5.1", "0.5.2", true},
		{"current is latest", "0.5.2", "0.5.2", false},
		{"current is newer", "0.5.3", "0.5.2", false},
		{"major version bump", "0.5.2", "1.0.0", true},
		{"with v prefix current", "v0.5.1", "0.5.2", true},
		{"with v prefix latest", "0.5.1", "v0.5.2", true},
		{"both with v prefix", "v0.5.1", "v0.5.2", true},
		{"pre-release lower than release", "0.5.2-rc1", "0.5.2", true},
		{"pre-release comparison", "0.5.2-alpha", "0.5.2-beta", true},
		{"build metadata ignored", "0.5.2+build123", "0.5.2", false},
		{"invalid current", "invalid", "0.5.2", false},
		{"invalid latest", "0.5.1", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNewerVersion(tt.current, tt.latest)
			if result != tt.expected {
				t.Errorf("IsNewerVersion(%s, %s) = %v, want %v",
					tt.current, tt.latest, result, tt.expected)
			}
		})
	}
}

// ----- Cache Tests -----

func TestCacheReadWrite(t *testing.T) {
	// Use temp directory for test
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	entry := &CacheEntry{
		LatestVersion: "0.5.2",
		ReleaseURL:    "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.2",
		CheckedAt:     time.Now().UTC(),
	}

	// Write cache
	err := WriteCacheFile(cacheFile, entry)
	if err != nil {
		t.Fatalf("WriteCacheFile failed: %v", err)
	}

	// Read cache
	read, err := ReadCacheFile(cacheFile)
	if err != nil {
		t.Fatalf("ReadCacheFile failed: %v", err)
	}

	if read.LatestVersion != entry.LatestVersion {
		t.Errorf("expected LatestVersion %s, got %s", entry.LatestVersion, read.LatestVersion)
	}
	if read.ReleaseURL != entry.ReleaseURL {
		t.Errorf("expected ReleaseURL %s, got %s", entry.ReleaseURL, read.ReleaseURL)
	}
}

func TestCacheValid(t *testing.T) {
	// Fresh cache (checked 1 hour ago)
	fresh := &CacheEntry{
		LatestVersion: "0.5.2",
		CheckedAt:     time.Now().Add(-1 * time.Hour),
	}
	if !fresh.IsValid(24 * time.Hour) {
		t.Error("expected fresh cache to be valid")
	}

	// Expired cache (checked 25 hours ago)
	expired := &CacheEntry{
		LatestVersion: "0.5.2",
		CheckedAt:     time.Now().Add(-25 * time.Hour),
	}
	if expired.IsValid(24 * time.Hour) {
		t.Error("expected expired cache to be invalid")
	}
}

func TestCacheReadNonExistent(t *testing.T) {
	_, err := ReadCacheFile("/nonexistent/path/cache.json")
	if err == nil {
		t.Error("expected error for nonexistent cache file")
	}
}

func TestCacheWriteCreatesDir(t *testing.T) {
	tmpDir := t.TempDir()
	nestedPath := filepath.Join(tmpDir, "subdir", "version-cache.json")

	entry := &CacheEntry{
		LatestVersion: "0.5.2",
		CheckedAt:     time.Now().UTC(),
	}

	err := WriteCacheFile(nestedPath, entry)
	if err != nil {
		t.Fatalf("WriteCacheFile failed to create nested dir: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(nestedPath); err != nil {
		t.Errorf("cache file not created: %v", err)
	}
}

// ----- Upgrade Command Tests -----

func TestGetUpgradeCommand(t *testing.T) {
	tests := []struct {
		method   InstallMethod
		toolName string
		version  string
		expected string
	}{
		{
			Homebrew, "bluectl", "0.5.2",
			"brew upgrade nmelo/tap/bluectl",
		},
		{
			Homebrew, "km", "0.5.2",
			"brew upgrade nmelo/tap/km",
		},
		{
			Apt, "bluectl", "0.5.2",
			"sudo apt update && sudo apt upgrade bluectl",
		},
		{
			Apt, "km", "0.5.2",
			"sudo apt update && sudo apt upgrade km",
		},
		{
			Rpm, "bluectl", "0.5.2",
			"sudo dnf upgrade bluectl",
		},
		{
			Docker, "bluectl", "0.5.2",
			"docker pull ghcr.io/gobeyondidentity/secureinfra-host-agent:0.5.2",
		},
		{
			Docker, "km", "0.5.2",
			"", // km not available via Docker
		},
		{
			DirectDownload, "bluectl", "0.5.2",
			"Download from https://github.com/gobeyondidentity/secure-infra/releases",
		},
		{
			DirectDownload, "km", "0.5.2",
			"Download from https://github.com/gobeyondidentity/secure-infra/releases",
		},
	}

	for _, tt := range tests {
		t.Run(tt.method.String()+"_"+tt.toolName, func(t *testing.T) {
			result := GetUpgradeCommand(tt.method, tt.toolName, tt.version)
			if result != tt.expected {
				t.Errorf("GetUpgradeCommand(%v, %s, %s) = %q, want %q",
					tt.method, tt.toolName, tt.version, result, tt.expected)
			}
		})
	}
}

// ----- InstallMethod String Tests -----

func TestInstallMethodString(t *testing.T) {
	tests := []struct {
		method   InstallMethod
		expected string
	}{
		{DirectDownload, "direct-download"},
		{Homebrew, "homebrew"},
		{Apt, "apt"},
		{Rpm, "rpm"},
		{Docker, "docker"},
	}

	for _, tt := range tests {
		if tt.method.String() != tt.expected {
			t.Errorf("InstallMethod(%d).String() = %s, want %s",
				tt.method, tt.method.String(), tt.expected)
		}
	}
}

// ----- GitHub API Client Tests -----

func TestParseGitHubRelease(t *testing.T) {
	responseJSON := `{
		"tag_name": "v0.5.2",
		"html_url": "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.2",
		"name": "Release 0.5.2"
	}`

	var release GitHubRelease
	err := json.Unmarshal([]byte(responseJSON), &release)
	if err != nil {
		t.Fatalf("failed to parse GitHub release: %v", err)
	}

	if release.TagName != "v0.5.2" {
		t.Errorf("expected tag_name v0.5.2, got %s", release.TagName)
	}
	if release.HTMLURL != "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.2" {
		t.Errorf("unexpected html_url: %s", release.HTMLURL)
	}
}

func TestFetchLatestVersion_Success(t *testing.T) {
	// Mock GitHub API server using mockhttp builder
	url, close := mockhttp.New().
		JSON("/repos/gobeyondidentity/secure-infra/releases/latest", map[string]string{
			"tag_name": "v0.5.2",
			"html_url": "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.2",
		}).
		BuildURL()
	defer close()

	// Use custom client with mock server
	client := NewGitHubClient(url)
	release, err := client.FetchLatestRelease()
	if err != nil {
		t.Fatalf("FetchLatestRelease failed: %v", err)
	}

	if release.TagName != "v0.5.2" {
		t.Errorf("expected tag_name v0.5.2, got %s", release.TagName)
	}
}

func TestFetchLatestVersion_Timeout(t *testing.T) {
	// Mock server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // Longer than timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewGitHubClientWithTimeout(server.URL, 100*time.Millisecond)
	_, err := client.FetchLatestRelease()
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestFetchLatestVersion_NotFound(t *testing.T) {
	url, close := mockhttp.New().
		Status("/repos/gobeyondidentity/secure-infra/releases/latest", http.StatusNotFound).
		BuildURL()
	defer close()

	client := NewGitHubClient(url)
	_, err := client.FetchLatestRelease()
	if err == nil {
		t.Error("expected error for 404, got nil")
	}
}

// ----- Integration Tests -----

func TestCheck_WithMockServer(t *testing.T) {
	// Mock GitHub API server using mockhttp builder
	url, close := mockhttp.New().
		JSON("/repos/gobeyondidentity/secure-infra/releases/latest", map[string]string{
			"tag_name": "v0.5.3",
			"html_url": "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.3",
		}).
		BuildURL()
	defer close()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	checker := &Checker{
		GitHubClient: NewGitHubClient(url),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	result := checker.Check("0.5.2")

	if result.Error != nil {
		t.Fatalf("Check failed: %v", result.Error)
	}
	if !result.UpdateAvailable {
		t.Error("expected UpdateAvailable = true")
	}
	if result.CurrentVersion != "0.5.2" {
		t.Errorf("expected CurrentVersion 0.5.2, got %s", result.CurrentVersion)
	}
	if result.LatestVersion != "0.5.3" {
		t.Errorf("expected LatestVersion 0.5.3, got %s", result.LatestVersion)
	}
	if result.FromCache {
		t.Error("expected FromCache = false for fresh fetch")
	}
}

func TestCheck_UsesCache(t *testing.T) {
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	// Pre-populate cache
	entry := &CacheEntry{
		LatestVersion: "0.5.5",
		ReleaseURL:    "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.5",
		CheckedAt:     time.Now().Add(-1 * time.Hour), // 1 hour ago, still valid
	}
	if err := WriteCacheFile(cacheFile, entry); err != nil {
		t.Fatalf("failed to pre-populate cache: %v", err)
	}

	// Server that should NOT be called
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := &Checker{
		GitHubClient: NewGitHubClient(server.URL),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	result := checker.Check("0.5.2")

	if serverCalled {
		t.Error("server should not be called when cache is valid")
	}
	if result.Error != nil {
		t.Fatalf("Check failed: %v", result.Error)
	}
	if !result.FromCache {
		t.Error("expected FromCache = true")
	}
	if result.LatestVersion != "0.5.5" {
		t.Errorf("expected LatestVersion from cache (0.5.5), got %s", result.LatestVersion)
	}
}

func TestCheck_ExpiredCacheFetchesFresh(t *testing.T) {
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	// Pre-populate expired cache
	entry := &CacheEntry{
		LatestVersion: "0.5.3",
		ReleaseURL:    "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.3",
		CheckedAt:     time.Now().Add(-25 * time.Hour), // 25 hours ago, expired
	}
	if err := WriteCacheFile(cacheFile, entry); err != nil {
		t.Fatalf("failed to pre-populate cache: %v", err)
	}

	// Server returns newer version
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"tag_name": "v0.5.6",
			"html_url": "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.6"
		}`))
	}))
	defer server.Close()

	checker := &Checker{
		GitHubClient: NewGitHubClient(server.URL),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	result := checker.Check("0.5.2")

	if result.Error != nil {
		t.Fatalf("Check failed: %v", result.Error)
	}
	if result.FromCache {
		t.Error("expected FromCache = false after expired cache refresh")
	}
	if result.LatestVersion != "0.5.6" {
		t.Errorf("expected fresh LatestVersion (0.5.6), got %s", result.LatestVersion)
	}
}

func TestCheck_FetchFailsUsesStaleCache(t *testing.T) {
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	// Pre-populate expired cache
	entry := &CacheEntry{
		LatestVersion: "0.5.4",
		ReleaseURL:    "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.4",
		CheckedAt:     time.Now().Add(-25 * time.Hour), // expired
	}
	if err := WriteCacheFile(cacheFile, entry); err != nil {
		t.Fatalf("failed to pre-populate cache: %v", err)
	}

	// Server returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	checker := &Checker{
		GitHubClient: NewGitHubClient(server.URL),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	result := checker.Check("0.5.2")

	// Should use stale cache
	if result.LatestVersion != "0.5.4" {
		t.Errorf("expected stale cache version (0.5.4), got %s", result.LatestVersion)
	}
	if !result.FromCache {
		t.Error("expected FromCache = true when using stale cache")
	}
	// Error should still be reported
	if result.Error == nil {
		t.Error("expected Error to be set when using stale cache")
	}
}

func TestCheck_FetchFailsNoCacheReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")
	// No cache file exists

	// Server returns error using mockhttp builder
	url, close := mockhttp.New().
		Status("/repos/gobeyondidentity/secure-infra/releases/latest", http.StatusServiceUnavailable).
		BuildURL()
	defer close()

	checker := &Checker{
		GitHubClient: NewGitHubClient(url),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	result := checker.Check("0.5.2")

	if result.Error == nil {
		t.Error("expected Error when fetch fails and no cache")
	}
	if result.LatestVersion != "" {
		t.Errorf("expected empty LatestVersion, got %s", result.LatestVersion)
	}
}

func TestCheck_NoUpdateAvailable(t *testing.T) {
	url, close := mockhttp.New().
		JSON("/repos/gobeyondidentity/secure-infra/releases/latest", map[string]string{
			"tag_name": "v0.5.2",
			"html_url": "https://github.com/gobeyondidentity/secure-infra/releases/tag/v0.5.2",
		}).
		BuildURL()
	defer close()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "version-cache.json")

	checker := &Checker{
		GitHubClient: NewGitHubClient(url),
		CachePath:    cacheFile,
		CacheTTL:     24 * time.Hour,
	}

	result := checker.Check("0.5.2")

	if result.Error != nil {
		t.Fatalf("Check failed: %v", result.Error)
	}
	if result.UpdateAvailable {
		t.Error("expected UpdateAvailable = false when current equals latest")
	}
}

// ----- Helper function for cache path tests -----

func TestGetCachePath(t *testing.T) {
	// Test with XDG_CACHE_HOME set
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	path := GetCachePath()
	expected := filepath.Join(tmpDir, "secureinfra", "version-cache.json")
	if path != expected {
		t.Errorf("expected cache path %s, got %s", expected, path)
	}

	// Test without XDG_CACHE_HOME (uses ~/.config)
	t.Setenv("XDG_CACHE_HOME", "")
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	path = GetCachePath()
	expected = filepath.Join(homeDir, ".config", "secureinfra", "version-cache.json")
	if path != expected {
		t.Errorf("expected cache path %s, got %s", expected, path)
	}
}

// ----- Normalize version tests -----

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0.5.2", "v0.5.2"},
		{"v0.5.2", "v0.5.2"},
		{"1.0.0", "v1.0.0"},
		{"v1.0.0", "v1.0.0"},
		{"0.5.2-rc1", "v0.5.2-rc1"},
		{"v0.5.2-rc1", "v0.5.2-rc1"},
		{"0.5.2+build", "v0.5.2+build"},
	}

	for _, tt := range tests {
		result := NormalizeVersion(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeVersion(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}
