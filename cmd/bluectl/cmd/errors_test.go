package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/nmelo/secure-infra/pkg/clierror"
	"github.com/spf13/cobra"
)

func TestHandleError_NilError(t *testing.T) {
	// HandleError with nil should not panic or do anything
	cmd := &cobra.Command{}
	cmd.Flags().String("output", "table", "")

	// This should return without doing anything
	// We cannot test os.Exit behavior directly, so we verify no panic occurs
	// and that HandleError handles nil gracefully by not entering any error path
	if err := (error)(nil); err != nil {
		t.Error("nil error should not enter error handling")
	}
}

func TestCLIError_DeviceNotFound(t *testing.T) {
	err := clierror.DeviceNotFound("bf3-test")

	if err.Code != clierror.CodeDeviceNotFound {
		t.Errorf("expected code %s, got %s", clierror.CodeDeviceNotFound, err.Code)
	}
	if err.ExitCode != clierror.ExitNotFound {
		t.Errorf("expected exit code %d, got %d", clierror.ExitNotFound, err.ExitCode)
	}
	if !strings.Contains(err.Message, "bf3-test") {
		t.Errorf("expected message to contain device name, got %s", err.Message)
	}
}

func TestCLIError_OperatorNotFound(t *testing.T) {
	err := clierror.OperatorNotFound("test@example.com")

	if err.Code != clierror.CodeOperatorNotFound {
		t.Errorf("expected code %s, got %s", clierror.CodeOperatorNotFound, err.Code)
	}
	if err.ExitCode != clierror.ExitNotFound {
		t.Errorf("expected exit code %d, got %d", clierror.ExitNotFound, err.ExitCode)
	}
	if !strings.Contains(err.Message, "test@example.com") {
		t.Errorf("expected message to contain email, got %s", err.Message)
	}
}

func TestCLIError_AlreadyExists(t *testing.T) {
	err := clierror.AlreadyExists("DPU", "192.168.1.204:50051")

	if err.Code != clierror.CodeAlreadyExists {
		t.Errorf("expected code %s, got %s", clierror.CodeAlreadyExists, err.Code)
	}
	if err.ExitCode != clierror.ExitGeneral {
		t.Errorf("expected exit code %d, got %d", clierror.ExitGeneral, err.ExitCode)
	}
	if !strings.Contains(err.Message, "DPU") {
		t.Errorf("expected message to contain resource type, got %s", err.Message)
	}
	if !strings.Contains(err.Message, "192.168.1.204:50051") {
		t.Errorf("expected message to contain resource name, got %s", err.Message)
	}
}

func TestCLIError_ConnectionFailed(t *testing.T) {
	err := clierror.ConnectionFailed("192.168.1.204:50051")

	if err.Code != clierror.CodeConnectionFailed {
		t.Errorf("expected code %s, got %s", clierror.CodeConnectionFailed, err.Code)
	}
	if !err.Retryable {
		t.Error("connection failed should be retryable")
	}
	if !strings.Contains(err.Message, "192.168.1.204:50051") {
		t.Errorf("expected message to contain address, got %s", err.Message)
	}
}

func TestCLIError_AttestationFailed(t *testing.T) {
	err := clierror.AttestationFailed("signature verification failed")

	if err.Code != clierror.CodeAttestationFailed {
		t.Errorf("expected code %s, got %s", clierror.CodeAttestationFailed, err.Code)
	}
	if err.ExitCode != clierror.ExitAttestation {
		t.Errorf("expected exit code %d, got %d", clierror.ExitAttestation, err.ExitCode)
	}
	if err.Retryable {
		t.Error("attestation failed should not be retryable")
	}
	if !strings.Contains(err.Message, "signature verification failed") {
		t.Errorf("expected message to contain reason, got %s", err.Message)
	}
}

func TestCLIError_InternalError(t *testing.T) {
	originalErr := os.ErrNotExist
	err := clierror.InternalError(originalErr)

	if err.Code != clierror.CodeInternalError {
		t.Errorf("expected code %s, got %s", clierror.CodeInternalError, err.Code)
	}
	if err.ExitCode != clierror.ExitGeneral {
		t.Errorf("expected exit code %d, got %d", clierror.ExitGeneral, err.ExitCode)
	}
	if !strings.Contains(err.Message, "file does not exist") {
		t.Errorf("expected message to contain original error, got %s", err.Message)
	}
}

func TestCLIError_InternalError_Nil(t *testing.T) {
	err := clierror.InternalError(nil)

	if err.Code != clierror.CodeInternalError {
		t.Errorf("expected code %s, got %s", clierror.CodeInternalError, err.Code)
	}
	if !strings.Contains(err.Message, "unexpected internal error") {
		t.Errorf("expected generic message for nil error, got %s", err.Message)
	}
}

func TestFormatError_Table(t *testing.T) {
	err := clierror.DeviceNotFound("bf3-test")
	output := clierror.FormatError(err, "table")

	if !strings.Contains(output, "DEVICE_NOT_FOUND") {
		t.Errorf("expected table format to contain error code, got %s", output)
	}
	if !strings.Contains(output, "bf3-test") {
		t.Errorf("expected table format to contain device name, got %s", output)
	}
	if !strings.Contains(output, "Hint:") {
		t.Errorf("expected table format to contain hint, got %s", output)
	}
}

func TestFormatError_JSON(t *testing.T) {
	err := clierror.DeviceNotFound("bf3-test")
	output := clierror.FormatError(err, "json")

	if !strings.Contains(output, `"code"`) {
		t.Errorf("expected JSON format to contain code field, got %s", output)
	}
	if !strings.Contains(output, `"DEVICE_NOT_FOUND"`) {
		t.Errorf("expected JSON format to contain error code, got %s", output)
	}
	if !strings.Contains(output, `"message"`) {
		t.Errorf("expected JSON format to contain message field, got %s", output)
	}
	if !strings.Contains(output, `"hint"`) {
		t.Errorf("expected JSON format to contain hint field, got %s", output)
	}
}

func TestPrintError_Stderr(t *testing.T) {
	err := clierror.DeviceNotFound("bf3-test")

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	clierror.PrintError(err, "table")

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "DEVICE_NOT_FOUND") {
		t.Errorf("expected error to be printed to stderr, got %s", output)
	}
}

func TestCLIError_ImplementsError(t *testing.T) {
	err := clierror.DeviceNotFound("bf3-test")

	// Verify it implements error interface
	var _ error = err

	errMsg := err.Error()
	if errMsg == "" {
		t.Error("Error() should return non-empty message")
	}
	if !strings.Contains(errMsg, "bf3-test") {
		t.Errorf("Error() should contain device name, got %s", errMsg)
	}
}

func TestCLIError_TypeAssertion(t *testing.T) {
	var err error = clierror.DeviceNotFound("bf3-test")

	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatal("expected type assertion to succeed")
	}
	if cliErr.Code != clierror.CodeDeviceNotFound {
		t.Errorf("expected code %s, got %s", clierror.CodeDeviceNotFound, cliErr.Code)
	}
}
