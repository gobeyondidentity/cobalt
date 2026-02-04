// Package versioncheck provides version checking functionality for CLI tools.
// It fetches the latest release from GitHub and provides upgrade instructions
// based on how the tool was installed.
package versioncheck

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// InstallMethod indicates how the CLI was installed.
type InstallMethod int

const (
	// DirectDownload is the default fallback when no package manager detected.
	DirectDownload InstallMethod = iota
	// Homebrew indicates the tool was installed via Homebrew.
	Homebrew
	// Apt indicates the tool was installed via apt (Debian/Ubuntu).
	Apt
	// Rpm indicates the tool was installed via rpm/dnf (RHEL/Fedora).
	Rpm
	// Docker indicates the tool is running inside a container.
	Docker
)

// String returns a human-readable name for the install method.
func (m InstallMethod) String() string {
	switch m {
	case DirectDownload:
		return "direct-download"
	case Homebrew:
		return "homebrew"
	case Apt:
		return "apt"
	case Rpm:
		return "rpm"
	case Docker:
		return "docker"
	default:
		return "unknown"
	}
}

// CheckResult contains the result of a version check.
type CheckResult struct {
	// CurrentVersion is the version of the running binary.
	CurrentVersion string
	// LatestVersion is the newest version available.
	LatestVersion string
	// ReleaseURL is the URL to the release page for changelog.
	ReleaseURL string
	// UpdateAvailable is true if LatestVersion > CurrentVersion.
	UpdateAvailable bool
	// InstallMethod indicates how the CLI was installed.
	InstallMethod InstallMethod
	// UpgradeCommand is the command to upgrade the tool.
	UpgradeCommand string
	// FromCache indicates whether the result came from cache.
	FromCache bool
	// Error contains any error that occurred during the check.
	// When set, the result may still contain cached data.
	Error error
}

// Checker performs version checks with caching support.
type Checker struct {
	GitHubClient *GitHubClient
	CachePath    string
	CacheTTL     time.Duration
}

// NewChecker creates a new Checker with default settings.
func NewChecker() *Checker {
	return &Checker{
		GitHubClient: NewGitHubClient(DefaultGitHubAPI),
		CachePath:    GetCachePath(),
		CacheTTL:     24 * time.Hour,
	}
}

// Check performs a version check for the given current version.
// It uses cache when valid, and falls back to stale cache on fetch errors.
func (c *Checker) Check(currentVersion string) *CheckResult {
	result := &CheckResult{
		CurrentVersion: currentVersion,
		InstallMethod:  DetectInstallMethod(),
	}

	// Try to read cache first
	cached, cacheErr := ReadCacheFile(c.CachePath)
	cacheValid := cacheErr == nil && cached.IsValid(c.CacheTTL)

	if cacheValid {
		// Use valid cache
		result.LatestVersion = cached.LatestVersion
		result.ReleaseURL = cached.ReleaseURL
		result.FromCache = true
	} else {
		// Cache invalid or missing; fetch from GitHub
		release, fetchErr := c.GitHubClient.FetchLatestRelease()
		if fetchErr != nil {
			result.Error = fetchErr
			// Try to use stale cache if available
			if cacheErr == nil && cached != nil {
				result.LatestVersion = cached.LatestVersion
				result.ReleaseURL = cached.ReleaseURL
				result.FromCache = true
			}
			// If no cache available, leave LatestVersion empty
			if result.LatestVersion == "" {
				return result
			}
		} else {
			// Update result with fresh data
			result.LatestVersion = stripVPrefix(release.TagName)
			result.ReleaseURL = release.HTMLURL

			// Update cache
			entry := &CacheEntry{
				LatestVersion: result.LatestVersion,
				ReleaseURL:    result.ReleaseURL,
				CheckedAt:     time.Now().UTC(),
			}
			// Ignore cache write errors; they shouldn't fail the check
			_ = WriteCacheFile(c.CachePath, entry)
		}
	}

	// Determine if update is available
	result.UpdateAvailable = IsNewerVersion(currentVersion, result.LatestVersion)

	// Get upgrade command
	result.UpgradeCommand = GetUpgradeCommand(result.InstallMethod, "", result.LatestVersion)

	return result
}

// DetectInstallMethod determines how the CLI was installed by examining
// the executable path and system markers.
func DetectInstallMethod() InstallMethod {
	execPath, err := os.Executable()
	if err != nil {
		return DirectDownload
	}
	return DetectInstallMethodFromPath(execPath)
}

// DetectInstallMethodFromPath determines install method from a given path.
// This is separated for testability.
func DetectInstallMethodFromPath(execPath string) InstallMethod {
	// Homebrew: binary path contains /Cellar/ or /homebrew/
	if strings.Contains(execPath, "/Cellar/") || strings.Contains(execPath, "/homebrew/") {
		return Homebrew
	}

	// Debian/Ubuntu: check for dpkg info file
	if _, err := os.Stat("/var/lib/dpkg/info/bluectl.list"); err == nil {
		return Apt
	}

	// RPM: check if rpm query succeeds (skip in tests)
	// This is a simple heuristic; a more robust implementation would
	// actually run `rpm -q bluectl`

	// Docker: check for /.dockerenv marker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return Docker
	}

	return DirectDownload
}

// GetUpgradeCommand returns the appropriate upgrade command for the given
// install method, tool name, and version.
func GetUpgradeCommand(method InstallMethod, toolName string, newVersion string) string {
	// Normalize toolName to handle empty default
	if toolName == "" {
		toolName = "bluectl"
	}

	switch method {
	case Homebrew:
		return "brew upgrade nmelo/tap/" + toolName
	case Apt:
		return "sudo apt update && sudo apt upgrade " + toolName
	case Rpm:
		return "sudo dnf upgrade " + toolName
	case Docker:
		if toolName == "km" {
			return "" // km not available via Docker
		}
		return "docker pull ghcr.io/gobeyondidentity/secureinfra-host-agent:" + newVersion
	case DirectDownload:
		fallthrough
	default:
		return "Download from https://github.com/gobeyondidentity/cobalt/releases"
	}
}

// IsNewerVersion returns true if latest is newer than current.
// Uses semantic versioning comparison, handling v prefix and pre-releases.
func IsNewerVersion(current, latest string) bool {
	// Normalize versions to have v prefix for semver package
	currentNorm := NormalizeVersion(current)
	latestNorm := NormalizeVersion(latest)

	// Validate versions
	if !semver.IsValid(currentNorm) || !semver.IsValid(latestNorm) {
		return false
	}

	// Compare: returns -1 if current < latest
	return semver.Compare(currentNorm, latestNorm) < 0
}

// NormalizeVersion ensures a version string has the v prefix required by semver.
func NormalizeVersion(v string) string {
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// stripVPrefix removes the v prefix from a version string.
func stripVPrefix(v string) string {
	return strings.TrimPrefix(v, "v")
}

// GetCachePath returns the path to the version cache file.
// Uses XDG_CACHE_HOME if set, otherwise ~/.config.
func GetCachePath() string {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(os.TempDir(), "secureinfra", "version-cache.json")
		}
		cacheDir = filepath.Join(homeDir, ".config")
	}
	return filepath.Join(cacheDir, "secureinfra", "version-cache.json")
}
