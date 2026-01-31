// Package enrollment provides shared enrollment utilities for secure infrastructure.
// Used by km, bluectl, aegis, and nexus for enrollment operations.
package enrollment

import (
	"errors"
	"fmt"
	"net/http"
)

// Enrollment error codes as defined in security-architecture.md Section 5.
const (
	ErrCodeInvalidCode        = "enroll.invalid_code"        // HTTP 401 - Invite/claim code not found
	ErrCodeExpiredCode        = "enroll.expired_code"        // HTTP 401 - Invite/claim code TTL exceeded
	ErrCodeCodeConsumed       = "enroll.code_consumed"       // HTTP 401 - Invite/claim code already used
	ErrCodeInvalidSession     = "enroll.invalid_session"     // HTTP 400 - Enrollment ID not found
	ErrCodeChallengeExpired   = "enroll.challenge_expired"   // HTTP 401 - Challenge TTL exceeded
	ErrCodeInvalidSignature   = "enroll.invalid_signature"   // HTTP 401 - Challenge signature verification failed
	ErrCodeKeyExists          = "enroll.key_exists"          // HTTP 409 - Public key fingerprint already enrolled
	ErrCodeDICESerialMismatch = "enroll.dice_serial_mismatch" // HTTP 401 - Serial in DICE certs doesn't match registration
	ErrCodeInvalidDICEChain   = "enroll.invalid_dice_chain"  // HTTP 401 - DICE certificate chain validation failed
)

// Bootstrap error codes.
const (
	ErrCodeWindowClosed    = "bootstrap.window_closed"    // HTTP 403 - Bootstrap window expired
	ErrCodeAlreadyEnrolled = "bootstrap.already_enrolled" // HTTP 403 - First admin already enrolled
)

// Attestation error codes.
const (
	ErrCodeMissingAttestation       = "enroll.missing_attestation"        // HTTP 400 - Attestation data required but not provided
	ErrCodeInvalidAttestation       = "enroll.invalid_attestation"        // HTTP 401 - Attestation validation failed
	ErrCodeAttestationNonceMismatch = "enroll.attestation_nonce_mismatch" // HTTP 401 - Attestation nonce does not match expected binding
)

// httpStatusMap maps error codes to their HTTP status codes.
var httpStatusMap = map[string]int{
	ErrCodeInvalidCode:        http.StatusUnauthorized,
	ErrCodeExpiredCode:        http.StatusUnauthorized,
	ErrCodeCodeConsumed:       http.StatusUnauthorized,
	ErrCodeInvalidSession:     http.StatusBadRequest,
	ErrCodeChallengeExpired:   http.StatusUnauthorized,
	ErrCodeInvalidSignature:   http.StatusUnauthorized,
	ErrCodeKeyExists:          http.StatusConflict,
	ErrCodeDICESerialMismatch: http.StatusUnauthorized,
	ErrCodeInvalidDICEChain:   http.StatusUnauthorized,
	ErrCodeWindowClosed:            http.StatusForbidden,
	ErrCodeAlreadyEnrolled:         http.StatusForbidden,
	ErrCodeMissingAttestation:      http.StatusBadRequest,
	ErrCodeInvalidAttestation:      http.StatusUnauthorized,
	ErrCodeAttestationNonceMismatch: http.StatusUnauthorized,
}

// EnrollmentError represents an enrollment error with a structured code.
type EnrollmentError struct {
	Code    string // One of the ErrCode* constants
	Message string // Human-readable error description
	Status  int    // HTTP status code
}

// Error implements the error interface.
func (e *EnrollmentError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// HTTPStatus returns the HTTP status code for this error.
func (e *EnrollmentError) HTTPStatus() int {
	return e.Status
}

// Unwrap allows errors.Is and errors.As to work with wrapped errors.
func (e *EnrollmentError) Unwrap() error {
	return nil
}

// newError creates an EnrollmentError with the given code and message.
func newError(code, message string) *EnrollmentError {
	return &EnrollmentError{
		Code:    code,
		Message: message,
		Status:  httpStatusMap[code],
	}
}

// ErrInvalidCode creates an error for invite code not found.
func ErrInvalidCode() *EnrollmentError {
	return newError(ErrCodeInvalidCode, "invite code not found")
}

// ErrExpiredCode creates an error for invite code TTL exceeded.
func ErrExpiredCode() *EnrollmentError {
	return newError(ErrCodeExpiredCode, "invite code has expired")
}

// ErrCodeConsumed creates an error for invite code already used.
func ErrCodeConsumed() *EnrollmentError {
	return newError(ErrCodeCodeConsumed, "invite code has already been used")
}

// ErrInvalidSession creates an error for enrollment ID not found.
func ErrInvalidSession(enrollmentID string) *EnrollmentError {
	return newError(ErrCodeInvalidSession, fmt.Sprintf("enrollment session %q not found", enrollmentID))
}

// ErrChallengeExpired creates an error for challenge TTL exceeded.
func ErrChallengeExpired() *EnrollmentError {
	return newError(ErrCodeChallengeExpired, "challenge has expired")
}

// ErrInvalidSignature creates an error for challenge signature verification failure.
func ErrInvalidSignature() *EnrollmentError {
	return newError(ErrCodeInvalidSignature, "challenge signature verification failed")
}

// ErrKeyExists creates an error for public key already enrolled.
func ErrKeyExists(fingerprint string) *EnrollmentError {
	return newError(ErrCodeKeyExists, fmt.Sprintf("key with fingerprint %q already enrolled", fingerprint))
}

// ErrDICESerialMismatch creates an error for serial mismatch in DICE certificates.
func ErrDICESerialMismatch(expected, actual string) *EnrollmentError {
	return newError(ErrCodeDICESerialMismatch, fmt.Sprintf("DICE serial mismatch: expected %q, got %q", expected, actual))
}

// ErrInvalidDICEChain creates an error for DICE certificate chain validation failure.
func ErrInvalidDICEChain(reason string) *EnrollmentError {
	return newError(ErrCodeInvalidDICEChain, fmt.Sprintf("invalid DICE certificate chain: %s", reason))
}

// ErrWindowClosed creates an error for bootstrap window expired.
func ErrWindowClosed() *EnrollmentError {
	return newError(ErrCodeWindowClosed, "bootstrap window has expired")
}

// ErrAlreadyEnrolled creates an error for first admin already enrolled.
func ErrAlreadyEnrolled() *EnrollmentError {
	return newError(ErrCodeAlreadyEnrolled, "first admin has already been enrolled")
}

// ErrMissingAttestation creates an error for attestation data required but not provided.
func ErrMissingAttestation() *EnrollmentError {
	return newError(ErrCodeMissingAttestation, "attestation data required for DPU enrollment")
}

// ErrInvalidAttestation creates an error for attestation validation failure.
func ErrInvalidAttestation(reason string) *EnrollmentError {
	return newError(ErrCodeInvalidAttestation, reason)
}

// ErrAttestationNonceMismatch creates an error for attestation nonce mismatch.
func ErrAttestationNonceMismatch() *EnrollmentError {
	return newError(ErrCodeAttestationNonceMismatch, "attestation nonce does not match expected binding")
}

// ErrorCode extracts the enrollment error code from an error.
// Returns empty string if the error is not an EnrollmentError.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var enrollErr *EnrollmentError
	if errors.As(err, &enrollErr) {
		return enrollErr.Code
	}
	return ""
}

// IsEnrollmentError returns true if the error is or wraps an EnrollmentError.
func IsEnrollmentError(err error) bool {
	if err == nil {
		return false
	}
	var enrollErr *EnrollmentError
	return errors.As(err, &enrollErr)
}
