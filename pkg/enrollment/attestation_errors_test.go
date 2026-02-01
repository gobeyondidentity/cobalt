package enrollment

import (
	"net/http"
	"testing"
)

// TestAttestationErrorCodes tests the new attestation-related error constructors.
func TestAttestationErrorCodes(t *testing.T) {
	t.Log("Testing attestation error constructors")

	t.Run("ErrMissingAttestation", func(t *testing.T) {
		t.Log("Creating ErrMissingAttestation error")
		err := ErrMissingAttestation()

		if err.Code != ErrCodeMissingAttestation {
			t.Errorf("Expected code %q, got %q", ErrCodeMissingAttestation, err.Code)
		}
		if err.HTTPStatus() != http.StatusBadRequest {
			t.Errorf("Expected HTTP status %d, got %d", http.StatusBadRequest, err.HTTPStatus())
		}
		if err.Message == "" {
			t.Error("Message should not be empty")
		}
		t.Logf("Error message: %s", err.Message)
	})

	t.Run("ErrInvalidAttestation", func(t *testing.T) {
		t.Log("Creating ErrInvalidAttestation error with reason")
		err := ErrInvalidAttestation("certificate chain validation failed")

		if err.Code != ErrCodeInvalidAttestation {
			t.Errorf("Expected code %q, got %q", ErrCodeInvalidAttestation, err.Code)
		}
		if err.HTTPStatus() != http.StatusUnauthorized {
			t.Errorf("Expected HTTP status %d, got %d", http.StatusUnauthorized, err.HTTPStatus())
		}
		expectedMsg := "certificate chain validation failed"
		if err.Message != expectedMsg {
			t.Errorf("Expected message %q, got %q", expectedMsg, err.Message)
		}
		t.Logf("Error: %s", err.Error())
	})

	t.Run("ErrAttestationNonceMismatch", func(t *testing.T) {
		t.Log("Creating ErrAttestationNonceMismatch error")
		err := ErrAttestationNonceMismatch()

		if err.Code != ErrCodeAttestationNonceMismatch {
			t.Errorf("Expected code %q, got %q", ErrCodeAttestationNonceMismatch, err.Code)
		}
		if err.HTTPStatus() != http.StatusUnauthorized {
			t.Errorf("Expected HTTP status %d, got %d", http.StatusUnauthorized, err.HTTPStatus())
		}
		if err.Message == "" {
			t.Error("Message should not be empty")
		}
		t.Logf("Error message: %s", err.Message)
	})
}

// TestAttestationErrorCodeExtraction tests that ErrorCode() works with the new errors.
func TestAttestationErrorCodeExtraction(t *testing.T) {
	t.Log("Testing error code extraction for attestation errors")

	tests := []struct {
		name     string
		err      *EnrollmentError
		wantCode string
	}{
		{"MissingAttestation", ErrMissingAttestation(), ErrCodeMissingAttestation},
		{"InvalidAttestation", ErrInvalidAttestation("test"), ErrCodeInvalidAttestation},
		{"NonceMismatch", ErrAttestationNonceMismatch(), ErrCodeAttestationNonceMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := ErrorCode(tt.err)
			if code != tt.wantCode {
				t.Errorf("ErrorCode() = %q, want %q", code, tt.wantCode)
			}
			t.Logf("ErrorCode() correctly extracted: %s", code)
		})
	}
}

// TestAttestationErrorIsEnrollmentError tests that IsEnrollmentError() works with the new errors.
func TestAttestationErrorIsEnrollmentError(t *testing.T) {
	t.Log("Testing IsEnrollmentError for attestation errors")

	errors := []*EnrollmentError{
		ErrMissingAttestation(),
		ErrInvalidAttestation("reason"),
		ErrAttestationNonceMismatch(),
	}

	for _, err := range errors {
		if !IsEnrollmentError(err) {
			t.Errorf("IsEnrollmentError() should return true for %s", err.Code)
		}
	}

	t.Log("All attestation errors correctly identified as EnrollmentErrors")
}
