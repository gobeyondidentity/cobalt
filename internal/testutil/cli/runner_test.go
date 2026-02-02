package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestRun_CapturesStdout(t *testing.T) {
	t.Parallel()
	t.Log("Testing that Run captures stdout from command")

	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("hello world")
		},
	}

	result := Run(cmd)
	result.AssertSuccess(t)

	if result.Stdout != "hello world\n" {
		t.Errorf("expected stdout 'hello world\\n', got %q", result.Stdout)
	}
}

func TestRun_CapturesStderr(t *testing.T) {
	t.Parallel()
	t.Log("Testing that Run captures stderr from command")

	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.PrintErrln("error message")
		},
	}

	result := Run(cmd)
	result.AssertSuccess(t)

	if result.Stderr != "error message\n" {
		t.Errorf("expected stderr 'error message\\n', got %q", result.Stderr)
	}
}

func TestRun_CapturesError(t *testing.T) {
	t.Parallel()
	t.Log("Testing that Run captures command errors")

	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("command failed")
		},
	}

	result := Run(cmd)
	result.AssertError(t)

	if result.Err == nil || result.Err.Error() != "command failed" {
		t.Errorf("expected error 'command failed', got %v", result.Err)
	}
}

func TestRun_PassesArguments(t *testing.T) {
	t.Parallel()
	t.Log("Testing that Run passes arguments to command")

	var receivedArgs []string
	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {
			receivedArgs = args
			cmd.Printf("args: %v", args)
		},
	}

	result := Run(cmd, "arg1", "arg2", "arg3")
	result.AssertSuccess(t)

	if len(receivedArgs) != 3 {
		t.Errorf("expected 3 args, got %d", len(receivedArgs))
	}
	if receivedArgs[0] != "arg1" || receivedArgs[1] != "arg2" || receivedArgs[2] != "arg3" {
		t.Errorf("expected args [arg1 arg2 arg3], got %v", receivedArgs)
	}
}

func TestReset_ClearsState(t *testing.T) {
	t.Parallel()
	t.Log("Testing that Reset clears command state")

	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("args count: %d", len(args))
		},
	}

	// First run with args
	cmd.SetArgs([]string{"old", "args"})

	// Reset and run with new args
	result := Reset(cmd).Run("new")
	result.AssertSuccess(t)
	result.AssertContains(t, "args count: 1")
}

func TestAssertSuccess_PassesOnSuccess(t *testing.T) {
	t.Parallel()
	t.Log("Testing that AssertSuccess passes when command succeeds")

	result := &CommandResult{
		Stdout: "output",
		Err:    nil,
	}

	// This should not fail
	result.AssertSuccess(t)
}

func TestAssertError_PassesOnError(t *testing.T) {
	t.Parallel()
	t.Log("Testing that AssertError passes when command fails")

	result := &CommandResult{
		Err: errors.New("some error"),
	}

	// This should not fail
	result.AssertError(t)
}

func TestAssertContains_PassesWhenFound(t *testing.T) {
	t.Parallel()
	t.Log("Testing that AssertContains passes when string is found")

	result := &CommandResult{
		Stdout: "hello world version 1.0",
	}

	result.AssertContains(t, "version")
	result.AssertContains(t, "hello")
	result.AssertContains(t, "1.0")
}

func TestAssertNotContains_PassesWhenNotFound(t *testing.T) {
	t.Parallel()
	t.Log("Testing that AssertNotContains passes when string is not found")

	result := &CommandResult{
		Stdout: "hello world",
	}

	result.AssertNotContains(t, "goodbye")
	result.AssertNotContains(t, "version")
}

func TestAssertPrefix_PassesWithCorrectPrefix(t *testing.T) {
	t.Parallel()
	t.Log("Testing that AssertPrefix passes when prefix matches")

	result := &CommandResult{
		Stdout: "km version 1.0.0\n",
	}

	result.AssertPrefix(t, "km version")
}

func TestAssertPrefix_TrimsWhitespace(t *testing.T) {
	t.Parallel()
	t.Log("Testing that AssertPrefix trims whitespace before checking")

	result := &CommandResult{
		Stdout: "  \n  km version 1.0.0\n",
	}

	result.AssertPrefix(t, "km version")
}

func TestAssertExact_PassesWithExactMatch(t *testing.T) {
	t.Parallel()
	t.Log("Testing that AssertExact passes with exact match")

	result := &CommandResult{
		Stdout: "exact output\n",
	}

	result.AssertExact(t, "exact output\n")
}

func TestAssertStderrContains_PassesWhenFound(t *testing.T) {
	t.Parallel()
	t.Log("Testing that AssertStderrContains passes when string is in stderr")

	result := &CommandResult{
		Stderr: "Warning: deprecated flag",
	}

	result.AssertStderrContains(t, "deprecated")
}

func TestTempConfigDir_CreatesDirectory(t *testing.T) {
	t.Parallel()
	t.Log("Testing that TempConfigDir creates the expected directory structure")

	baseDir := TempConfigDir(t, "testapp")

	// Check that the config directory exists
	configDir := filepath.Join(baseDir, ".config", "testapp")
	info, err := os.Stat(configDir)
	if err != nil {
		t.Fatalf("config directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("config path should be a directory")
	}
}

func TestTempConfigDirPath_ReturnsFullPath(t *testing.T) {
	t.Parallel()
	t.Log("Testing that TempConfigDirPath returns the full config directory path")

	configPath := TempConfigDirPath(t, "testapp")

	// Path should end with .config/testapp
	if !filepath.IsAbs(configPath) {
		t.Error("expected absolute path")
	}
	if filepath.Base(configPath) != "testapp" {
		t.Errorf("expected path to end with 'testapp', got %s", filepath.Base(configPath))
	}
	if filepath.Base(filepath.Dir(configPath)) != ".config" {
		t.Errorf("expected parent to be '.config', got %s", filepath.Base(filepath.Dir(configPath)))
	}

	// Directory should exist
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("config directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("config path should be a directory")
	}
}

func TestWriteConfigFile_WritesFile(t *testing.T) {
	t.Parallel()
	t.Log("Testing that WriteConfigFile creates the config file with correct content")

	baseDir := TempConfigDir(t, "testapp")
	content := "server: http://localhost:8080\n"

	configFile := WriteConfigFile(t, baseDir, "testapp", "config.yaml", content)

	// File should exist and have correct content
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	if string(data) != content {
		t.Errorf("expected content %q, got %q", content, string(data))
	}

	// File should have 0600 permissions
	info, err := os.Stat(configFile)
	if err != nil {
		t.Fatalf("failed to stat config file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestRun_WithFlags(t *testing.T) {
	t.Parallel()
	t.Log("Testing that Run works with command flags")

	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {
			verbose, _ := cmd.Flags().GetBool("verbose")
			if verbose {
				cmd.Println("verbose mode")
			} else {
				cmd.Println("normal mode")
			}
		},
	}
	cmd.Flags().Bool("verbose", false, "verbose output")

	// Test without flag
	result := Run(cmd)
	result.AssertSuccess(t)
	result.AssertContains(t, "normal mode")

	// Test with flag
	result = Run(cmd, "--verbose")
	result.AssertSuccess(t)
	result.AssertContains(t, "verbose mode")
}

func TestRun_WithSubcommands(t *testing.T) {
	t.Parallel()
	t.Log("Testing that Run works with subcommands")

	rootCmd := &cobra.Command{
		Use: "root",
	}
	subCmd := &cobra.Command{
		Use: "sub",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("subcommand executed")
		},
	}
	rootCmd.AddCommand(subCmd)

	result := Run(rootCmd, "sub")
	result.AssertSuccess(t)
	result.AssertContains(t, "subcommand executed")
}
