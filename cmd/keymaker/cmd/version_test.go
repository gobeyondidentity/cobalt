package cmd

import (
	"strings"
	"testing"

	"github.com/gobeyondidentity/cobalt/internal/testutil/cli"
	"github.com/gobeyondidentity/cobalt/internal/version"
)

func TestVersionCommand_BasicOutput(t *testing.T) {
	// Cannot run in parallel - modifies shared global rootCmd
	t.Log("Test that version command shows current version")

	result := cli.Run(rootCmd, "version")
	result.AssertSuccess(t)

	// Should contain "km version X.X.X"
	expectedPrefix := "km version " + version.String()
	result.AssertPrefix(t, expectedPrefix)
}

func TestVersionCommand_CheckFlag(t *testing.T) {
	// Cannot run in parallel - modifies shared global rootCmd
	t.Log("Test that version --check shows version and update status")

	result := cli.Run(rootCmd, "version", "--check")
	result.AssertSuccess(t)

	// Should contain version info
	result.AssertContains(t, "km version "+version.String())

	// Should contain either:
	// - "You are running the latest version."
	// - "A newer version is available:"
	// - "(Could not check for updates)"
	hasUpdateInfo := strings.Contains(result.Stdout, "You are running the latest version.") ||
		strings.Contains(result.Stdout, "A newer version is available:") ||
		strings.Contains(result.Stdout, "(Could not check for updates)")

	if !hasUpdateInfo {
		t.Errorf("expected output to contain update check result, got %q", result.Stdout)
	}
}

func TestVersionCommand_SkipUpdateCheckFlag(t *testing.T) {
	// Cannot run in parallel - modifies shared global rootCmd
	t.Log("Test that version --skip-update-check shows only version")

	result := cli.Run(rootCmd, "version", "--skip-update-check")
	result.AssertSuccess(t)

	// Should contain version info
	expectedPrefix := "km version " + version.String()
	result.AssertPrefix(t, expectedPrefix)

	// Should NOT contain update check info (since we skipped)
	result.AssertNotContains(t, "You are running the latest version.")
	result.AssertNotContains(t, "A newer version is available:")
}
