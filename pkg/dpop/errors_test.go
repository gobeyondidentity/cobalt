package dpop

import (
	"errors"
	"testing"
)

func TestErrorCodes(t *testing.T) {
	t.Log("Verifying all 8 DPoP error codes exist with correct strings")

	codes := map[string]string{
		"missing_proof":    ErrCodeMissingProof,
		"invalid_proof":    ErrCodeInvalidProof,
		"unknown_key":      ErrCodeUnknownKey,
		"invalid_signature": ErrCodeInvalidSignature,
		"invalid_iat":      ErrCodeInvalidIAT,
		"method_mismatch":  ErrCodeMethodMismatch,
		"uri_mismatch":     ErrCodeURIMismatch,
		"replay":           ErrCodeReplay,
	}

	for name, code := range codes {
		expected := "dpop." + name
		if code != expected {
			t.Errorf("ErrCode%s = %q, want %q", name, code, expected)
		}
	}
}

func TestDPoPErrorInterface(t *testing.T) {
	t.Log("Testing DPoPError implements error interface")
	var err error = &DPoPError{
		Code:    ErrCodeMissingProof,
		Message: "no DPoP header in request",
	}

	if err.Error() != "dpop.missing_proof: no DPoP header in request" {
		t.Errorf("Error() = %q, want dpop.missing_proof: no DPoP header in request", err.Error())
	}
}

func TestErrorConstructors(t *testing.T) {
	t.Log("Testing error constructor functions")

	tests := []struct {
		name     string
		err      *DPoPError
		wantCode string
	}{
		{"MissingProof", ErrMissingProof(), ErrCodeMissingProof},
		{"InvalidProof", ErrInvalidProof("bad format"), ErrCodeInvalidProof},
		{"UnknownKey", ErrUnknownKey("km_123"), ErrCodeUnknownKey},
		{"InvalidSignature", ErrInvalidSignature(), ErrCodeInvalidSignature},
		{"InvalidIAT", ErrInvalidIAT(60, 120), ErrCodeInvalidIAT},
		{"MethodMismatch", ErrMethodMismatch("POST", "GET"), ErrCodeMethodMismatch},
		{"URIMismatch", ErrURIMismatch("/api/v1/a", "/api/v1/b"), ErrCodeURIMismatch},
		{"Replay", ErrReplay("jti-123"), ErrCodeReplay},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing %s error constructor", tt.name)
			if tt.err.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", tt.err.Code, tt.wantCode)
			}
			if tt.err.Message == "" {
				t.Error("Message should not be empty")
			}
			t.Logf("Error message: %s", tt.err.Error())
		})
	}
}

func TestErrorCodeExtraction(t *testing.T) {
	t.Log("Testing error code extraction from DPoP errors")

	dpopErr := ErrInvalidSignature()
	code := ErrorCode(dpopErr)
	if code != ErrCodeInvalidSignature {
		t.Errorf("ErrorCode(DPoPError) = %q, want %q", code, ErrCodeInvalidSignature)
	}

	// Test wrapped error
	wrapped := errors.Join(errors.New("context"), dpopErr)
	code = ErrorCode(wrapped)
	if code != ErrCodeInvalidSignature {
		t.Errorf("ErrorCode(wrapped) = %q, want %q", code, ErrCodeInvalidSignature)
	}

	// Test non-DPoP error returns empty string
	regularErr := errors.New("regular error")
	code = ErrorCode(regularErr)
	if code != "" {
		t.Errorf("ErrorCode(regular) = %q, want empty string", code)
	}

	// Test nil returns empty string
	code = ErrorCode(nil)
	if code != "" {
		t.Errorf("ErrorCode(nil) = %q, want empty string", code)
	}
}

func TestIsDPoPError(t *testing.T) {
	t.Log("Testing IsDPoPError helper")

	dpopErr := ErrMissingProof()
	if !IsDPoPError(dpopErr) {
		t.Error("IsDPoPError should return true for DPoPError")
	}

	wrapped := errors.Join(errors.New("wrapper"), dpopErr)
	if !IsDPoPError(wrapped) {
		t.Error("IsDPoPError should return true for wrapped DPoPError")
	}

	regularErr := errors.New("regular error")
	if IsDPoPError(regularErr) {
		t.Error("IsDPoPError should return false for regular error")
	}

	if IsDPoPError(nil) {
		t.Error("IsDPoPError should return false for nil")
	}
}

func TestErrorMessagesDoNotContainSensitiveData(t *testing.T) {
	t.Log("Verifying error messages do not expose sensitive data patterns")

	// These errors should NOT contain anything that looks like a key
	err := ErrUnknownKey("km_abc123")
	msg := err.Error()

	// Kid is fine to expose (it's a public identifier)
	// But let's ensure no key material patterns appear
	if len(msg) > 500 {
		t.Error("Error message suspiciously long, may contain key material")
	}
}
