package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// CommandResult captures the output and error from a command execution.
type CommandResult struct {
	Stdout string
	Stderr string
	Err    error
}

// Run executes a cobra command with the given arguments and captures output.
// It sets up stdout/stderr capture, executes the command, and returns the result.
//
// Example:
//
//	result := cli.Run(versionCmd, "--check")
//	result.AssertSuccess(t)
//	result.AssertContains(t, "version")
func Run(cmd *cobra.Command, args ...string) *CommandResult {
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)

	err := cmd.Execute()

	return &CommandResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Err:    err,
	}
}

// CommandRunner wraps a cobra command for fluent test execution.
type CommandRunner struct {
	cmd *cobra.Command
}

// Reset creates a CommandRunner that resets command state before execution.
// Use this for commands with persistent flags or state between test runs.
//
// Example:
//
//	result := cli.Reset(rootCmd).Run("--help")
func Reset(cmd *cobra.Command) *CommandRunner {
	// Reset args to empty to clear any previous test state
	cmd.SetArgs([]string{})
	return &CommandRunner{cmd: cmd}
}

// Run executes the command with the given arguments.
func (r *CommandRunner) Run(args ...string) *CommandResult {
	return Run(r.cmd, args...)
}

// AssertSuccess fails the test if the command returned an error.
func (r *CommandResult) AssertSuccess(t *testing.T) {
	t.Helper()
	if r.Err != nil {
		t.Fatalf("expected command to succeed, got error: %v\nstdout: %s\nstderr: %s",
			r.Err, r.Stdout, r.Stderr)
	}
}

// AssertError fails the test if the command did not return an error.
func (r *CommandResult) AssertError(t *testing.T) {
	t.Helper()
	if r.Err == nil {
		t.Fatalf("expected command to fail, but it succeeded\nstdout: %s", r.Stdout)
	}
}

// AssertContains fails the test if stdout does not contain the expected string.
func (r *CommandResult) AssertContains(t *testing.T, expected string) {
	t.Helper()
	if !strings.Contains(r.Stdout, expected) {
		t.Errorf("expected stdout to contain %q, got:\n%s", expected, r.Stdout)
	}
}

// AssertNotContains fails the test if stdout contains the unexpected string.
func (r *CommandResult) AssertNotContains(t *testing.T, unexpected string) {
	t.Helper()
	if strings.Contains(r.Stdout, unexpected) {
		t.Errorf("expected stdout NOT to contain %q, got:\n%s", unexpected, r.Stdout)
	}
}

// AssertPrefix fails the test if stdout does not start with the expected prefix.
func (r *CommandResult) AssertPrefix(t *testing.T, expected string) {
	t.Helper()
	trimmed := strings.TrimSpace(r.Stdout)
	if !strings.HasPrefix(trimmed, expected) {
		t.Errorf("expected stdout to start with %q, got:\n%s", expected, r.Stdout)
	}
}

// AssertExact fails the test if stdout does not exactly match the expected string.
func (r *CommandResult) AssertExact(t *testing.T, expected string) {
	t.Helper()
	if r.Stdout != expected {
		t.Errorf("expected stdout to be exactly %q, got %q", expected, r.Stdout)
	}
}

// AssertStderrContains fails the test if stderr does not contain the expected string.
func (r *CommandResult) AssertStderrContains(t *testing.T, expected string) {
	t.Helper()
	if !strings.Contains(r.Stderr, expected) {
		t.Errorf("expected stderr to contain %q, got:\n%s", expected, r.Stderr)
	}
}

// TempConfigDir creates a temporary config directory structure for CLI testing.
// It creates the directory at <tmpdir>/.config/<appName>/ and returns the
// base temp directory path.
//
// The returned path can be used to override config directory lookups.
// The directory is automatically cleaned up when the test completes.
//
// Example:
//
//	baseDir := cli.TempConfigDir(t, "bluectl")
//	// baseDir = "/tmp/TestXXX123"
//	// Creates: /tmp/TestXXX123/.config/bluectl/
func TempConfigDir(t *testing.T, appName string) string {
	t.Helper()
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".config", appName)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create temp config dir: %v", err)
	}
	return tmpDir
}

// TempConfigDirPath returns the full path to the config directory.
// This is a convenience wrapper that returns the .config/<appName> path directly.
//
// Example:
//
//	configPath := cli.TempConfigDirPath(t, "bluectl")
//	// configPath = "/tmp/TestXXX123/.config/bluectl"
func TempConfigDirPath(t *testing.T, appName string) string {
	t.Helper()
	baseDir := TempConfigDir(t, appName)
	return filepath.Join(baseDir, ".config", appName)
}

// WriteConfigFile writes a config file to the temp config directory.
// It creates the file at <baseDir>/.config/<appName>/<filename>.
//
// Example:
//
//	baseDir := cli.TempConfigDir(t, "bluectl")
//	cli.WriteConfigFile(t, baseDir, "bluectl", "config.yaml", "server: http://localhost:18080")
func WriteConfigFile(t *testing.T, baseDir, appName, filename, content string) string {
	t.Helper()
	configPath := filepath.Join(baseDir, ".config", appName, filename)
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	return configPath
}
