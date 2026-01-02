// Package clierror provides structured errors for CLI output with codes,
// exit codes, and remediation hints.
package clierror

import (
	"encoding/json"
	"fmt"
	"os"
)

// Exit codes following the taxonomy from batch9-cli-polish.md
const (
	ExitSuccess     = 0 // Operation completed successfully
	ExitGeneral     = 1 // Unknown/unhandled error
	ExitAuth        = 2 // Not authenticated, token expired
	ExitAttestation = 3 // Stale, failed, unavailable attestation
	ExitNotFound    = 4 // Resource doesn't exist
	ExitRateLimited = 5 // Too many requests
)

// Error codes (strings) for programmatic error handling
const (
	CodeAttestationStale       = "ATTESTATION_STALE"
	CodeAttestationFailed      = "ATTESTATION_FAILED"
	CodeAttestationUnavailable = "ATTESTATION_UNAVAILABLE"
	CodeNotAuthorized          = "NOT_AUTHORIZED"
	CodeTokenExpired           = "TOKEN_EXPIRED"
	CodeDeviceNotFound         = "DEVICE_NOT_FOUND"
	CodeCANotFound             = "CA_NOT_FOUND"
	CodeOperatorNotFound       = "OPERATOR_NOT_FOUND"
	CodeAlreadyExists          = "ALREADY_EXISTS"
	CodeRateLimited            = "RATE_LIMITED"
	CodeConnectionFailed       = "CONNECTION_FAILED"
	CodeInternalError          = "INTERNAL_ERROR"
)

// CLIError represents a structured error for CLI output.
type CLIError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Hint      string `json:"hint,omitempty"`
	Retryable bool   `json:"retryable"`
	ExitCode  int    `json:"-"` // Not serialized, used for os.Exit
}

// Error implements the error interface.
func (e *CLIError) Error() string {
	return e.Message
}

// AttestationStale creates an error for stale attestation data.
func AttestationStale(age string) *CLIError {
	return &CLIError{
		Code:      CodeAttestationStale,
		Message:   fmt.Sprintf("attestation data is stale (age: %s)", age),
		Hint:      "Run 'bluectl attest refresh' to update attestation",
		Retryable: true,
		ExitCode:  ExitAttestation,
	}
}

// AttestationFailed creates an error for failed attestation verification.
func AttestationFailed(reason string) *CLIError {
	return &CLIError{
		Code:      CodeAttestationFailed,
		Message:   fmt.Sprintf("attestation verification failed: %s", reason),
		Hint:      "Check device firmware integrity and security configuration",
		Retryable: false,
		ExitCode:  ExitAttestation,
	}
}

// AttestationUnavailable creates an error when attestation service is unreachable.
func AttestationUnavailable() *CLIError {
	return &CLIError{
		Code:      CodeAttestationUnavailable,
		Message:   "attestation service unavailable",
		Hint:      "Verify the DPU agent is running and network connectivity",
		Retryable: true,
		ExitCode:  ExitAttestation,
	}
}

// NotAuthorized creates an error for authorization failures.
func NotAuthorized(resource string) *CLIError {
	return &CLIError{
		Code:      CodeNotAuthorized,
		Message:   fmt.Sprintf("not authorized to access '%s'", resource),
		Hint:      "Check your permissions or contact an administrator",
		Retryable: false,
		ExitCode:  ExitAuth,
	}
}

// TokenExpired creates an error for expired authentication tokens.
func TokenExpired() *CLIError {
	return &CLIError{
		Code:      CodeTokenExpired,
		Message:   "authentication token has expired",
		Hint:      "Re-authenticate with 'km init' or 'bluectl login'",
		Retryable: true,
		ExitCode:  ExitAuth,
	}
}

// DeviceNotFound creates an error when a device doesn't exist.
func DeviceNotFound(name string) *CLIError {
	return &CLIError{
		Code:      CodeDeviceNotFound,
		Message:   fmt.Sprintf("device '%s' not found", name),
		Hint:      fmt.Sprintf("Check device name with 'bluectl dpu list'"),
		Retryable: false,
		ExitCode:  ExitNotFound,
	}
}

// CANotFound creates an error when a certificate authority doesn't exist.
func CANotFound(name string) *CLIError {
	return &CLIError{
		Code:      CodeCANotFound,
		Message:   fmt.Sprintf("certificate authority '%s' not found", name),
		Hint:      "Check CA name with 'km ssh-ca list'",
		Retryable: false,
		ExitCode:  ExitNotFound,
	}
}

// OperatorNotFound creates an error when an operator doesn't exist.
func OperatorNotFound(email string) *CLIError {
	return &CLIError{
		Code:      CodeOperatorNotFound,
		Message:   fmt.Sprintf("operator '%s' not found", email),
		Hint:      "Check operator email with 'km operator list'",
		Retryable: false,
		ExitCode:  ExitNotFound,
	}
}

// AlreadyExists creates an error when a resource already exists.
func AlreadyExists(resource, name string) *CLIError {
	return &CLIError{
		Code:      CodeAlreadyExists,
		Message:   fmt.Sprintf("%s '%s' already exists", resource, name),
		Hint:      "Use a different name or delete the existing resource first",
		Retryable: false,
		ExitCode:  ExitGeneral,
	}
}

// RateLimited creates an error for rate limiting.
func RateLimited() *CLIError {
	return &CLIError{
		Code:      CodeRateLimited,
		Message:   "rate limit exceeded",
		Hint:      "Wait a moment before retrying",
		Retryable: true,
		ExitCode:  ExitRateLimited,
	}
}

// ConnectionFailed creates an error for connection failures.
func ConnectionFailed(target string) *CLIError {
	return &CLIError{
		Code:      CodeConnectionFailed,
		Message:   fmt.Sprintf("failed to connect to '%s'", target),
		Hint:      "Check network connectivity and target address",
		Retryable: true,
		ExitCode:  ExitGeneral,
	}
}

// InternalError creates an error for unexpected internal errors.
func InternalError(err error) *CLIError {
	msg := "an unexpected internal error occurred"
	if err != nil {
		msg = fmt.Sprintf("internal error: %s", err.Error())
	}
	return &CLIError{
		Code:      CodeInternalError,
		Message:   msg,
		Hint:      "",
		Retryable: false,
		ExitCode:  ExitGeneral,
	}
}

// FormatError returns the error formatted for the given output format.
// Supported formats: "json" for JSON output, anything else for human-readable table format.
func FormatError(err *CLIError, outputFormat string) string {
	if outputFormat == "json" {
		data, jsonErr := json.MarshalIndent(err, "", "  ")
		if jsonErr != nil {
			// Fallback to simple JSON if marshaling fails
			return fmt.Sprintf(`{"code":"%s","message":"%s"}`, err.Code, err.Message)
		}
		return string(data)
	}

	// Human-readable table format
	output := fmt.Sprintf("Error [%s]: %s", err.Code, err.Message)
	if err.Hint != "" {
		output += fmt.Sprintf("\nHint: %s", err.Hint)
	}
	return output
}

// PrintError prints the error to stderr in the appropriate format.
func PrintError(err *CLIError, outputFormat string) {
	fmt.Fprintln(os.Stderr, FormatError(err, outputFormat))
}
