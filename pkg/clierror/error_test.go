package clierror

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExitCodes(t *testing.T) {
	t.Parallel()
	// Verify exit code constants match spec
	tests := []struct {
		name     string
		got      int
		expected int
	}{
		{"ExitSuccess", ExitSuccess, 0},
		{"ExitGeneral", ExitGeneral, 1},
		{"ExitAuth", ExitAuth, 2},
		{"ExitAttestation", ExitAttestation, 3},
		{"ExitNotFound", ExitNotFound, 4},
		{"ExitRateLimited", ExitRateLimited, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestErrorCodes(t *testing.T) {
	t.Parallel()
	// Verify error code constants match spec
	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"CodeAttestationStale", CodeAttestationStale, "ATTESTATION_STALE"},
		{"CodeAttestationFailed", CodeAttestationFailed, "ATTESTATION_FAILED"},
		{"CodeAttestationUnavailable", CodeAttestationUnavailable, "ATTESTATION_UNAVAILABLE"},
		{"CodeNotAuthorized", CodeNotAuthorized, "NOT_AUTHORIZED"},
		{"CodeTokenExpired", CodeTokenExpired, "TOKEN_EXPIRED"},
		{"CodeDeviceNotFound", CodeDeviceNotFound, "DEVICE_NOT_FOUND"},
		{"CodeCANotFound", CodeCANotFound, "CA_NOT_FOUND"},
		{"CodeOperatorNotFound", CodeOperatorNotFound, "OPERATOR_NOT_FOUND"},
		{"CodeAlreadyExists", CodeAlreadyExists, "ALREADY_EXISTS"},
		{"CodeRateLimited", CodeRateLimited, "RATE_LIMITED"},
		{"CodeConnectionFailed", CodeConnectionFailed, "CONNECTION_FAILED"},
		{"CodeInternalError", CodeInternalError, "INTERNAL_ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestCLIError_Error(t *testing.T) {
	t.Parallel()
	err := &CLIError{
		Code:    CodeDeviceNotFound,
		Message: "device 'test-dpu' not found",
	}

	if err.Error() != "device 'test-dpu' not found" {
		t.Errorf("Error() = %q, want %q", err.Error(), "device 'test-dpu' not found")
	}
}

func TestAttestationStale(t *testing.T) {
	t.Parallel()
	err := AttestationStale("15m30s")

	if err.Code != CodeAttestationStale {
		t.Errorf("Code = %q, want %q", err.Code, CodeAttestationStale)
	}
	if err.ExitCode != ExitAttestation {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitAttestation)
	}
	if !strings.Contains(err.Message, "15m30s") {
		t.Errorf("Message should contain age, got %q", err.Message)
	}
	if err.Hint == "" {
		t.Error("Hint should not be empty")
	}
	if !err.Retryable {
		t.Error("Retryable should be true for stale attestation")
	}
}

func TestAttestationFailed(t *testing.T) {
	t.Parallel()
	err := AttestationFailed("PCR mismatch")

	if err.Code != CodeAttestationFailed {
		t.Errorf("Code = %q, want %q", err.Code, CodeAttestationFailed)
	}
	if err.ExitCode != ExitAttestation {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitAttestation)
	}
	if !strings.Contains(err.Message, "PCR mismatch") {
		t.Errorf("Message should contain reason, got %q", err.Message)
	}
	if err.Retryable {
		t.Error("Retryable should be false for failed attestation")
	}
}

func TestAttestationUnavailable(t *testing.T) {
	t.Parallel()
	err := AttestationUnavailable()

	if err.Code != CodeAttestationUnavailable {
		t.Errorf("Code = %q, want %q", err.Code, CodeAttestationUnavailable)
	}
	if err.ExitCode != ExitAttestation {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitAttestation)
	}
	if err.Hint == "" {
		t.Error("Hint should not be empty")
	}
	if !err.Retryable {
		t.Error("Retryable should be true for unavailable attestation")
	}
}

func TestNotAuthorized(t *testing.T) {
	t.Parallel()
	err := NotAuthorized("ssh-ca/ops-ca")

	if err.Code != CodeNotAuthorized {
		t.Errorf("Code = %q, want %q", err.Code, CodeNotAuthorized)
	}
	if err.ExitCode != ExitAuth {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitAuth)
	}
	if !strings.Contains(err.Message, "ssh-ca/ops-ca") {
		t.Errorf("Message should contain resource, got %q", err.Message)
	}
	if err.Retryable {
		t.Error("Retryable should be false for authorization errors")
	}
}

func TestTokenExpired(t *testing.T) {
	t.Parallel()
	err := TokenExpired()

	if err.Code != CodeTokenExpired {
		t.Errorf("Code = %q, want %q", err.Code, CodeTokenExpired)
	}
	if err.ExitCode != ExitAuth {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitAuth)
	}
	if err.Hint == "" {
		t.Error("Hint should not be empty")
	}
	if !err.Retryable {
		t.Error("Retryable should be true for expired token")
	}
}

func TestDeviceNotFound(t *testing.T) {
	t.Parallel()
	err := DeviceNotFound("bf3-node01")

	if err.Code != CodeDeviceNotFound {
		t.Errorf("Code = %q, want %q", err.Code, CodeDeviceNotFound)
	}
	if err.ExitCode != ExitNotFound {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitNotFound)
	}
	if !strings.Contains(err.Message, "bf3-node01") {
		t.Errorf("Message should contain device name, got %q", err.Message)
	}
	if err.Retryable {
		t.Error("Retryable should be false for not found errors")
	}
}

func TestCANotFound(t *testing.T) {
	t.Parallel()
	err := CANotFound("ops-ca")

	if err.Code != CodeCANotFound {
		t.Errorf("Code = %q, want %q", err.Code, CodeCANotFound)
	}
	if err.ExitCode != ExitNotFound {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitNotFound)
	}
	if !strings.Contains(err.Message, "ops-ca") {
		t.Errorf("Message should contain CA name, got %q", err.Message)
	}
	if err.Retryable {
		t.Error("Retryable should be false for not found errors")
	}
}

func TestOperatorNotFound(t *testing.T) {
	t.Parallel()
	err := OperatorNotFound("alice@example.com")

	if err.Code != CodeOperatorNotFound {
		t.Errorf("Code = %q, want %q", err.Code, CodeOperatorNotFound)
	}
	if err.ExitCode != ExitNotFound {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitNotFound)
	}
	if !strings.Contains(err.Message, "alice@example.com") {
		t.Errorf("Message should contain email, got %q", err.Message)
	}
	if err.Retryable {
		t.Error("Retryable should be false for not found errors")
	}
}

func TestAlreadyExists(t *testing.T) {
	t.Parallel()
	err := AlreadyExists("SSH CA", "ops-ca")

	if err.Code != CodeAlreadyExists {
		t.Errorf("Code = %q, want %q", err.Code, CodeAlreadyExists)
	}
	if err.ExitCode != ExitGeneral {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitGeneral)
	}
	if !strings.Contains(err.Message, "SSH CA") {
		t.Errorf("Message should contain resource type, got %q", err.Message)
	}
	if !strings.Contains(err.Message, "ops-ca") {
		t.Errorf("Message should contain name, got %q", err.Message)
	}
	if err.Retryable {
		t.Error("Retryable should be false for already exists errors")
	}
}

func TestRateLimited(t *testing.T) {
	t.Parallel()
	err := RateLimited()

	if err.Code != CodeRateLimited {
		t.Errorf("Code = %q, want %q", err.Code, CodeRateLimited)
	}
	if err.ExitCode != ExitRateLimited {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitRateLimited)
	}
	if err.Hint == "" {
		t.Error("Hint should not be empty")
	}
	if !err.Retryable {
		t.Error("Retryable should be true for rate limited errors")
	}
}

func TestConnectionFailed(t *testing.T) {
	t.Parallel()
	err := ConnectionFailed("192.168.1.204:50051")

	if err.Code != CodeConnectionFailed {
		t.Errorf("Code = %q, want %q", err.Code, CodeConnectionFailed)
	}
	if err.ExitCode != ExitGeneral {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitGeneral)
	}
	if !strings.Contains(err.Message, "192.168.1.204:50051") {
		t.Errorf("Message should contain target, got %q", err.Message)
	}
	if err.Hint == "" {
		t.Error("Hint should not be empty")
	}
	if !err.Retryable {
		t.Error("Retryable should be true for connection errors")
	}
}

func TestInternalError(t *testing.T) {
	t.Parallel()
	originalErr := strings.NewReader("test").Read // just need any error
	err := InternalError(nil)

	if err.Code != CodeInternalError {
		t.Errorf("Code = %q, want %q", err.Code, CodeInternalError)
	}
	if err.ExitCode != ExitGeneral {
		t.Errorf("ExitCode = %d, want %d", err.ExitCode, ExitGeneral)
	}
	if err.Retryable {
		t.Error("Retryable should be false for internal errors")
	}

	// Test with actual error
	_ = originalErr
	err2 := InternalError(&testError{msg: "database locked"})
	if !strings.Contains(err2.Message, "database locked") {
		t.Errorf("Message should contain original error, got %q", err2.Message)
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestCLIError_JSONSerialization(t *testing.T) {
	t.Parallel()
	err := &CLIError{
		Code:      CodeDeviceNotFound,
		Message:   "device 'test-dpu' not found",
		Hint:      "check device name with 'bluectl dpu list'",
		Retryable: false,
		ExitCode:  ExitNotFound,
	}

	data, jsonErr := json.Marshal(err)
	if jsonErr != nil {
		t.Fatalf("json.Marshal failed: %v", jsonErr)
	}

	// Verify JSON contains expected fields
	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal(data, &parsed); jsonErr != nil {
		t.Fatalf("json.Unmarshal failed: %v", jsonErr)
	}

	if parsed["code"] != CodeDeviceNotFound {
		t.Errorf("JSON code = %v, want %v", parsed["code"], CodeDeviceNotFound)
	}
	if parsed["message"] != "device 'test-dpu' not found" {
		t.Errorf("JSON message = %v, want %v", parsed["message"], "device 'test-dpu' not found")
	}
	if parsed["hint"] != "check device name with 'bluectl dpu list'" {
		t.Errorf("JSON hint = %v, want %v", parsed["hint"], "check device name with 'bluectl dpu list'")
	}
	if parsed["retryable"] != false {
		t.Errorf("JSON retryable = %v, want %v", parsed["retryable"], false)
	}

	// ExitCode should NOT be in JSON (json:"-" tag)
	if _, exists := parsed["ExitCode"]; exists {
		t.Error("ExitCode should not be serialized to JSON")
	}
}

func TestCLIError_JSONSerialization_OmitEmptyHint(t *testing.T) {
	t.Parallel()
	err := &CLIError{
		Code:      CodeInternalError,
		Message:   "unexpected error",
		Hint:      "", // empty hint
		Retryable: false,
		ExitCode:  ExitGeneral,
	}

	data, jsonErr := json.Marshal(err)
	if jsonErr != nil {
		t.Fatalf("json.Marshal failed: %v", jsonErr)
	}

	// Hint should be omitted when empty
	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal(data, &parsed); jsonErr != nil {
		t.Fatalf("json.Unmarshal failed: %v", jsonErr)
	}

	if _, exists := parsed["hint"]; exists {
		t.Error("Empty hint should be omitted from JSON")
	}
}

func TestFormatError_JSON(t *testing.T) {
	t.Parallel()
	err := DeviceNotFound("bf3-node01")

	output := FormatError(err, "json")

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(output), &parsed); jsonErr != nil {
		t.Fatalf("FormatError(json) produced invalid JSON: %v\nOutput: %s", jsonErr, output)
	}

	// Verify required fields
	if parsed["code"] != CodeDeviceNotFound {
		t.Errorf("JSON code = %v, want %v", parsed["code"], CodeDeviceNotFound)
	}
	if !strings.Contains(parsed["message"].(string), "bf3-node01") {
		t.Errorf("JSON message should contain device name, got %v", parsed["message"])
	}
}

func TestFormatError_Table(t *testing.T) {
	t.Parallel()
	err := DeviceNotFound("bf3-node01")

	output := FormatError(err, "table")

	// Should be human-readable, not JSON
	if strings.HasPrefix(output, "{") {
		t.Error("Table format should not produce JSON")
	}

	// Should contain error message
	if !strings.Contains(output, "bf3-node01") {
		t.Errorf("Output should contain device name, got %q", output)
	}

	// Should contain error code
	if !strings.Contains(output, CodeDeviceNotFound) {
		t.Errorf("Output should contain error code, got %q", output)
	}
}

func TestFormatError_TableWithHint(t *testing.T) {
	t.Parallel()
	err := TokenExpired()

	output := FormatError(err, "table")

	// Should contain hint
	if !strings.Contains(output, err.Hint) {
		t.Errorf("Output should contain hint, got %q", output)
	}
}

func TestFormatError_DefaultToTable(t *testing.T) {
	t.Parallel()
	err := DeviceNotFound("bf3-node01")

	// Unknown format should default to table
	tableOutput := FormatError(err, "table")
	unknownOutput := FormatError(err, "yaml") // yaml not supported for errors

	if unknownOutput != tableOutput {
		t.Error("Unknown format should default to table output")
	}
}
