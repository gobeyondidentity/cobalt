// Package cli provides shared test utilities for CLI testing with cobra commands.
//
// This package eliminates boilerplate when testing cobra CLI applications by
// providing helpers for command execution, output capture, and assertions.
//
// # Basic Usage
//
// Execute a command and check output:
//
//	result := cli.Run(myCmd, "--help")
//	result.AssertSuccess(t)
//	result.AssertContains(t, "Usage:")
//
// # Output Capture
//
// The Run function captures both stdout and stderr:
//
//	result := cli.Run(myCmd, "version")
//	if result.Err != nil {
//		t.Fatalf("command failed: %v", result.Err)
//	}
//	fmt.Println(result.Stdout)  // captured stdout
//	fmt.Println(result.Stderr)  // captured stderr
//
// # Temp Config Directories
//
// Create temporary config directories with standard structure:
//
//	configDir := cli.TempConfigDir(t, "bluectl")
//	// Creates: <tmpdir>/.config/bluectl/
//	// Returns the full path to <tmpdir>
//
// # Assertion Methods
//
// CommandResult provides fluent assertion methods:
//
//	result := cli.Run(myCmd)
//	result.AssertSuccess(t)                    // No error
//	result.AssertError(t)                      // Expects error
//	result.AssertContains(t, "expected text")  // Stdout contains
//	result.AssertPrefix(t, "km version")       // Stdout starts with
//	result.AssertExact(t, "exact output\n")    // Stdout equals exactly
//
// # Resetting Commands
//
// For commands with persistent state, use Reset before execution:
//
//	result := cli.Reset(rootCmd).Run("--help")
package cli
