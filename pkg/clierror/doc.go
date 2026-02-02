// Package clierror provides structured error handling for CLI commands.
//
// CLI errors include an exit code, user-facing message, and optional
// troubleshooting hints. This separates internal error details from
// what gets displayed to operators.
//
// # Usage
//
//	if err != nil {
//	    return clierror.New(1, "enrollment failed", err).
//	        WithHint("Check that the invite code is valid")
//	}
package clierror
