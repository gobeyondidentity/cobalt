package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gobeyondidentity/secure-infra/internal/version"
)

func TestVersionCommand_BasicOutput(t *testing.T) {
	// Cannot run in parallel - modifies shared global rootCmd
	// Capture output
	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetArgs([]string{"version"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	output := stdout.String()

	// Should contain "km version X.X.X"
	expectedPrefix := "km version " + version.Version
	if !strings.HasPrefix(output, expectedPrefix) {
		t.Errorf("expected output to start with %q, got %q", expectedPrefix, output)
	}
}

func TestVersionCommand_CheckFlag(t *testing.T) {
	// Cannot run in parallel - modifies shared global rootCmd
	// Capture output
	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetArgs([]string{"version", "--check"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("version --check command failed: %v", err)
	}

	output := stdout.String()

	// Should contain version info
	if !strings.Contains(output, "km version "+version.Version) {
		t.Errorf("expected output to contain version, got %q", output)
	}

	// Should contain either:
	// - "You are running the latest version."
	// - "A newer version is available:"
	// - "(Could not check for updates)"
	hasUpdateInfo := strings.Contains(output, "You are running the latest version.") ||
		strings.Contains(output, "A newer version is available:") ||
		strings.Contains(output, "(Could not check for updates)")

	if !hasUpdateInfo {
		t.Errorf("expected output to contain update check result, got %q", output)
	}
}

func TestVersionCommand_SkipUpdateCheckFlag(t *testing.T) {
	// Cannot run in parallel - modifies shared global rootCmd
	// Capture output
	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetArgs([]string{"version", "--skip-update-check"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("version --skip-update-check command failed: %v", err)
	}

	output := stdout.String()

	// Should contain version info
	expectedPrefix := "km version " + version.Version
	if !strings.HasPrefix(output, expectedPrefix) {
		t.Errorf("expected output to start with %q, got %q", expectedPrefix, output)
	}

	// Should NOT contain update check info (since we skipped)
	if strings.Contains(output, "You are running the latest version.") ||
		strings.Contains(output, "A newer version is available:") {
		t.Errorf("expected --skip-update-check to skip update info, got %q", output)
	}
}
