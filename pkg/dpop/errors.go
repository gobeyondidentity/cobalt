package dpop

import (
	"errors"
	"fmt"
)

// Error codes for DPoP authentication failures.
// These match the codes defined in security-architecture.md Section 5.
const (
	ErrCodeMissingProof    = "dpop.missing_proof"    // No DPoP header in request
	ErrCodeInvalidProof    = "dpop.invalid_proof"    // DPoP JWT parse failure or wrong typ/alg
	ErrCodeUnknownKey      = "dpop.unknown_key"      // kid not found in key store
	ErrCodeInvalidSignature = "dpop.invalid_signature" // Ed25519 signature verification failed
	ErrCodeInvalidIAT      = "dpop.invalid_iat"      // iat timestamp outside acceptable window
	ErrCodeMethodMismatch  = "dpop.method_mismatch"  // htm doesn't match HTTP request method
	ErrCodeURIMismatch     = "dpop.uri_mismatch"     // htu doesn't match HTTP request URI
	ErrCodeReplay          = "dpop.replay"           // jti already used (replay attempt)
)

// DPoPError represents a DPoP authentication error with a structured code.
type DPoPError struct {
	Code    string // One of the ErrCode* constants
	Message string // Human-readable error description
}

// Error implements the error interface.
func (e *DPoPError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap allows errors.Is and errors.As to work with wrapped errors.
func (e *DPoPError) Unwrap() error {
	return nil
}

// ErrMissingProof creates an error for missing DPoP header.
func ErrMissingProof() *DPoPError {
	return &DPoPError{
		Code:    ErrCodeMissingProof,
		Message: "DPoP header required but not present",
	}
}

// ErrInvalidProof creates an error for malformed or invalid DPoP proof.
func ErrInvalidProof(reason string) *DPoPError {
	return &DPoPError{
		Code:    ErrCodeInvalidProof,
		Message: fmt.Sprintf("DPoP proof invalid: %s", reason),
	}
}

// ErrUnknownKey creates an error when the kid is not found.
func ErrUnknownKey(kid string) *DPoPError {
	return &DPoPError{
		Code:    ErrCodeUnknownKey,
		Message: fmt.Sprintf("key identifier %q not found", kid),
	}
}

// ErrInvalidSignature creates an error for signature verification failure.
func ErrInvalidSignature() *DPoPError {
	return &DPoPError{
		Code:    ErrCodeInvalidSignature,
		Message: "signature verification failed",
	}
}

// ErrInvalidIAT creates an error when iat is outside the acceptable window.
func ErrInvalidIAT(ageSeconds, maxAgeSeconds int64) *DPoPError {
	return &DPoPError{
		Code:    ErrCodeInvalidIAT,
		Message: fmt.Sprintf("proof timestamp outside acceptable window (age: %ds, max: %ds)", ageSeconds, maxAgeSeconds),
	}
}

// ErrMethodMismatch creates an error when htm doesn't match the request method.
func ErrMethodMismatch(expected, actual string) *DPoPError {
	return &DPoPError{
		Code:    ErrCodeMethodMismatch,
		Message: fmt.Sprintf("HTTP method mismatch: proof claims %q but request is %q", expected, actual),
	}
}

// ErrURIMismatch creates an error when htu doesn't match the request URI.
func ErrURIMismatch(expected, actual string) *DPoPError {
	return &DPoPError{
		Code:    ErrCodeURIMismatch,
		Message: fmt.Sprintf("HTTP URI mismatch: proof claims %q but request is %q", expected, actual),
	}
}

// ErrReplay creates an error when a jti has already been used.
func ErrReplay(jti string) *DPoPError {
	return &DPoPError{
		Code:    ErrCodeReplay,
		Message: fmt.Sprintf("proof with jti %q has already been used", jti),
	}
}

// ErrorCode extracts the DPoP error code from an error.
// Returns empty string if the error is not a DPoPError.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var dpopErr *DPoPError
	if errors.As(err, &dpopErr) {
		return dpopErr.Code
	}
	return ""
}

// IsDPoPError returns true if the error is or wraps a DPoPError.
func IsDPoPError(err error) bool {
	if err == nil {
		return false
	}
	var dpopErr *DPoPError
	return errors.As(err, &dpopErr)
}
