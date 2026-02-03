package authz

import (
	"errors"
	"fmt"
	"net/http"
)

// Authorization error codes.
const (
	ErrCodeForbidden              = "authz.forbidden"               // Policy denied access
	ErrCodeAttestationStale       = "authz.attestation_stale"       // DPU attestation is stale
	ErrCodeAttestationUnavailable = "authz.attestation_unavailable" // DPU attestation unavailable
	ErrCodeAttestationFailed      = "authz.attestation_failed"      // DPU attestation failed (hard block)
	ErrCodeUnknownAction          = "authz.unknown_action"          // Action not in registry
	ErrCodeUnknownRoute           = "authz.unknown_route"           // Route not in action registry
	ErrCodePolicyError            = "authz.policy_error"            // Policy evaluation error
)

// httpStatusMap maps error codes to HTTP status codes.
var httpStatusMap = map[string]int{
	ErrCodeForbidden:              http.StatusForbidden,           // 403
	ErrCodeAttestationStale:       http.StatusPreconditionFailed,  // 412
	ErrCodeAttestationUnavailable: http.StatusPreconditionFailed,  // 412
	ErrCodeAttestationFailed:      http.StatusPreconditionFailed,  // 412
	ErrCodeUnknownAction:          http.StatusBadRequest,          // 400
	ErrCodeUnknownRoute:           http.StatusNotFound,            // 404
	ErrCodePolicyError:            http.StatusInternalServerError, // 500
}

// AuthzError represents an authorization error with a structured code.
type AuthzError struct {
	Code    string // One of the ErrCode* constants
	Message string // Human-readable error description
	Status  int    // HTTP status code
}

// Error implements the error interface.
func (e *AuthzError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// HTTPStatus returns the appropriate HTTP status code for this error.
func (e *AuthzError) HTTPStatus() int {
	return e.Status
}

// Unwrap allows errors.Is and errors.As to work with wrapped errors.
func (e *AuthzError) Unwrap() error {
	return nil
}

// newError creates an AuthzError with appropriate HTTP status.
func newError(code, message string) *AuthzError {
	return &AuthzError{
		Code:    code,
		Message: message,
		Status:  httpStatusMap[code],
	}
}

// ErrForbidden creates an error for policy-denied access.
func ErrForbidden(reason string) *AuthzError {
	return newError(ErrCodeForbidden, reason)
}

// ErrAttestationStale creates an error for stale attestation.
func ErrAttestationStale(dpuID string) *AuthzError {
	return newError(ErrCodeAttestationStale, fmt.Sprintf("DPU %s attestation is stale", dpuID))
}

// ErrAttestationUnavailable creates an error for unavailable attestation.
func ErrAttestationUnavailable(dpuID string) *AuthzError {
	return newError(ErrCodeAttestationUnavailable, fmt.Sprintf("DPU %s attestation unavailable", dpuID))
}

// ErrAttestationFailed creates an error for failed attestation (cannot be bypassed).
func ErrAttestationFailed(dpuID string) *AuthzError {
	return newError(ErrCodeAttestationFailed, fmt.Sprintf("DPU %s attestation failed - cannot bypass", dpuID))
}

// ErrUnknownAction creates an error for unknown action (fail-closed).
func ErrUnknownAction(action string) *AuthzError {
	return newError(ErrCodeUnknownAction, fmt.Sprintf("unknown action %q", action))
}

// ErrPolicyError creates an error for policy evaluation failures.
func ErrPolicyError(detail string) *AuthzError {
	return newError(ErrCodePolicyError, fmt.Sprintf("policy evaluation error: %s", detail))
}

// ErrUnknownRoute creates an error for routes not in the action registry.
// SECURITY: Unknown routes return error (fail-secure), not silent pass.
func ErrUnknownRoute(method, path string) *AuthzError {
	return newError(ErrCodeUnknownRoute, fmt.Sprintf("unknown route %s %s", method, path))
}

// ErrorCode extracts the authz error code from an error.
// Returns empty string if the error is not an AuthzError.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var authzErr *AuthzError
	if errors.As(err, &authzErr) {
		return authzErr.Code
	}
	return ""
}

// IsAuthzError returns true if the error is or wraps an AuthzError.
func IsAuthzError(err error) bool {
	if err == nil {
		return false
	}
	var authzErr *AuthzError
	return errors.As(err, &authzErr)
}
