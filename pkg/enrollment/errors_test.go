package enrollment

import (
	"errors"
	"net/http"
	"testing"
)

func TestEnrollmentErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		wantCode string
	}{
		{"InvalidCode", ErrCodeInvalidCode, "enroll.invalid_code"},
		{"ExpiredCode", ErrCodeExpiredCode, "enroll.expired_code"},
		{"CodeConsumed", ErrCodeCodeConsumed, "enroll.code_consumed"},
		{"InvalidSession", ErrCodeInvalidSession, "enroll.invalid_session"},
		{"ChallengeExpired", ErrCodeChallengeExpired, "enroll.challenge_expired"},
		{"InvalidSignature", ErrCodeInvalidSignature, "enroll.invalid_signature"},
		{"KeyExists", ErrCodeKeyExists, "enroll.key_exists"},
		{"DICESerialMismatch", ErrCodeDICESerialMismatch, "enroll.dice_serial_mismatch"},
		{"InvalidDICEChain", ErrCodeInvalidDICEChain, "enroll.invalid_dice_chain"},
		{"WindowClosed", ErrCodeWindowClosed, "bootstrap.window_closed"},
		{"AlreadyEnrolled", ErrCodeAlreadyEnrolled, "bootstrap.already_enrolled"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.code != tc.wantCode {
				t.Errorf("ErrCode%s = %q, want %q", tc.name, tc.code, tc.wantCode)
			}
		})
	}
}

func TestEnrollmentErrorHTTPStatuses(t *testing.T) {
	tests := []struct {
		name       string
		err        *EnrollmentError
		wantStatus int
	}{
		{"InvalidCode", ErrInvalidCode(), http.StatusUnauthorized},
		{"ExpiredCode", ErrExpiredCode(), http.StatusUnauthorized},
		{"CodeConsumed", ErrCodeConsumed(), http.StatusUnauthorized},
		{"InvalidSession", ErrInvalidSession("test-id"), http.StatusBadRequest},
		{"ChallengeExpired", ErrChallengeExpired(), http.StatusUnauthorized},
		{"InvalidSignature", ErrInvalidSignature(), http.StatusUnauthorized},
		{"KeyExists", ErrKeyExists("abc123"), http.StatusConflict},
		{"DICESerialMismatch", ErrDICESerialMismatch("expected", "actual"), http.StatusUnauthorized},
		{"InvalidDICEChain", ErrInvalidDICEChain("invalid cert"), http.StatusUnauthorized},
		{"WindowClosed", ErrWindowClosed(), http.StatusForbidden},
		{"AlreadyEnrolled", ErrAlreadyEnrolled(), http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Checking HTTP status for %s error", tc.name)
			if tc.err.HTTPStatus() != tc.wantStatus {
				t.Errorf("%s.HTTPStatus() = %d, want %d", tc.name, tc.err.HTTPStatus(), tc.wantStatus)
			}
		})
	}
}

func TestEnrollmentErrorString(t *testing.T) {
	t.Log("Testing error string format")
	err := ErrInvalidCode()
	// Generic message to prevent invite code enumeration
	want := "enroll.invalid_code: invalid or expired invite code"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestErrorCodeExtraction(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{"EnrollmentError", ErrInvalidCode(), ErrCodeInvalidCode},
		{"WrappedError", errors.New("wrapped"), ""},
		{"NilError", nil, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Extracting error code from %v", tc.err)
			got := ErrorCode(tc.err)
			if got != tc.wantCode {
				t.Errorf("ErrorCode(%v) = %q, want %q", tc.err, got, tc.wantCode)
			}
		})
	}
}

func TestIsEnrollmentError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"EnrollmentError", ErrInvalidCode(), true},
		{"StandardError", errors.New("standard"), false},
		{"NilError", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Checking if %v is EnrollmentError", tc.err)
			got := IsEnrollmentError(tc.err)
			if got != tc.want {
				t.Errorf("IsEnrollmentError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
