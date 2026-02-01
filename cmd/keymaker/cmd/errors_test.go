package cmd

import (
	"encoding/json"
	"testing"

	"github.com/gobeyondidentity/secure-infra/pkg/clierror"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
)

func TestHandleError_CLIError(t *testing.T) {
	// Test that CLIError is properly recognized
	err := clierror.CANotFound("ops-ca")

	if err.Code != clierror.CodeCANotFound {
		t.Errorf("Expected code %s, got %s", clierror.CodeCANotFound, err.Code)
	}
	if err.ExitCode != clierror.ExitNotFound {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitNotFound, err.ExitCode)
	}
}

func TestHandleError_InternalError(t *testing.T) {
	// Test that generic errors are wrapped as InternalError
	err := clierror.InternalError(nil)

	if err.Code != clierror.CodeInternalError {
		t.Errorf("Expected code %s, got %s", clierror.CodeInternalError, err.Code)
	}
	if err.ExitCode != clierror.ExitGeneral {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitGeneral, err.ExitCode)
	}
}

func TestSSHCAList_EmptyReturnsEmptyArray(t *testing.T) {
	// Verify that empty list serializes to [] not null
	cas := []*store.SSHCA{}

	data, err := json.Marshal(cas)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if string(data) != "[]" {
		t.Errorf("Expected [], got %s", string(data))
	}
}

func TestSSHCAList_NilBecomesEmptyArray(t *testing.T) {
	// Verify that nil slice becomes empty array when explicitly set
	var cas []*store.SSHCA
	if cas == nil {
		cas = []*store.SSHCA{}
	}

	data, err := json.Marshal(cas)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if string(data) != "[]" {
		t.Errorf("Expected [], got %s", string(data))
	}
}

func TestAttestationStaleError(t *testing.T) {
	err := clierror.AttestationStale("1h30m")

	if err.Code != clierror.CodeAttestationStale {
		t.Errorf("Expected code %s, got %s", clierror.CodeAttestationStale, err.Code)
	}
	if err.ExitCode != clierror.ExitAttestation {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitAttestation, err.ExitCode)
	}
	if !err.Retryable {
		t.Error("Expected retryable to be true")
	}
}

func TestAttestationFailedError(t *testing.T) {
	err := clierror.AttestationFailed("device failed integrity verification")

	if err.Code != clierror.CodeAttestationFailed {
		t.Errorf("Expected code %s, got %s", clierror.CodeAttestationFailed, err.Code)
	}
	if err.ExitCode != clierror.ExitAttestation {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitAttestation, err.ExitCode)
	}
	if err.Retryable {
		t.Error("Expected retryable to be false for failed attestation")
	}
}

func TestAttestationUnavailableError(t *testing.T) {
	err := clierror.AttestationUnavailable()

	if err.Code != clierror.CodeAttestationUnavailable {
		t.Errorf("Expected code %s, got %s", clierror.CodeAttestationUnavailable, err.Code)
	}
	if err.ExitCode != clierror.ExitAttestation {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitAttestation, err.ExitCode)
	}
	if !err.Retryable {
		t.Error("Expected retryable to be true")
	}
}

func TestNotAuthorizedError(t *testing.T) {
	err := clierror.NotAuthorized("CA 'ops-ca'")

	if err.Code != clierror.CodeNotAuthorized {
		t.Errorf("Expected code %s, got %s", clierror.CodeNotAuthorized, err.Code)
	}
	if err.ExitCode != clierror.ExitAuth {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitAuth, err.ExitCode)
	}
}

func TestDeviceNotFoundError(t *testing.T) {
	err := clierror.DeviceNotFound("bf3-node01")

	if err.Code != clierror.CodeDeviceNotFound {
		t.Errorf("Expected code %s, got %s", clierror.CodeDeviceNotFound, err.Code)
	}
	if err.ExitCode != clierror.ExitNotFound {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitNotFound, err.ExitCode)
	}
}

func TestCANotFoundError(t *testing.T) {
	err := clierror.CANotFound("ops-ca")

	if err.Code != clierror.CodeCANotFound {
		t.Errorf("Expected code %s, got %s", clierror.CodeCANotFound, err.Code)
	}
	if err.ExitCode != clierror.ExitNotFound {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitNotFound, err.ExitCode)
	}
}

func TestAlreadyExistsError(t *testing.T) {
	err := clierror.AlreadyExists("SSH CA", "ops-ca")

	if err.Code != clierror.CodeAlreadyExists {
		t.Errorf("Expected code %s, got %s", clierror.CodeAlreadyExists, err.Code)
	}
	if err.ExitCode != clierror.ExitGeneral {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitGeneral, err.ExitCode)
	}
}

func TestConnectionFailedError(t *testing.T) {
	err := clierror.ConnectionFailed("192.168.1.204:50051")

	if err.Code != clierror.CodeConnectionFailed {
		t.Errorf("Expected code %s, got %s", clierror.CodeConnectionFailed, err.Code)
	}
	if err.ExitCode != clierror.ExitGeneral {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitGeneral, err.ExitCode)
	}
	if !err.Retryable {
		t.Error("Expected retryable to be true for connection errors")
	}
}

func TestTokenExpiredError(t *testing.T) {
	err := clierror.TokenExpired()

	if err.Code != clierror.CodeTokenExpired {
		t.Errorf("Expected code %s, got %s", clierror.CodeTokenExpired, err.Code)
	}
	if err.ExitCode != clierror.ExitAuth {
		t.Errorf("Expected exit code %d, got %d", clierror.ExitAuth, err.ExitCode)
	}
	if !err.Retryable {
		t.Error("Expected retryable to be true for expired token")
	}
}

func TestCLIError_JSONOutput(t *testing.T) {
	err := clierror.CANotFound("ops-ca")

	output := clierror.FormatError(err, "json")

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(output), &parsed); jsonErr != nil {
		t.Fatalf("FormatError(json) produced invalid JSON: %v\nOutput: %s", jsonErr, output)
	}

	// Verify required fields
	if parsed["code"] != clierror.CodeCANotFound {
		t.Errorf("JSON code = %v, want %v", parsed["code"], clierror.CodeCANotFound)
	}
}

func TestCLIError_TableOutput(t *testing.T) {
	err := clierror.CANotFound("ops-ca")

	output := clierror.FormatError(err, "table")

	// Should not start with { (not JSON)
	if len(output) > 0 && output[0] == '{' {
		t.Error("Table format should not produce JSON")
	}
}
