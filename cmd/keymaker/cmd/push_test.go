package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gobeyondidentity/secure-infra/pkg/clierror"
)

// mockHTTPClient implements HTTPClient for testing.
type mockHTTPClient struct {
	response *http.Response
	err      error
	request  *http.Request // Captures the last request
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.request = req
	return m.response, m.err
}

func newMockResponse(statusCode int, body interface{}) *http.Response {
	var bodyBytes []byte
	switch v := body.(type) {
	case string:
		bodyBytes = []byte(v)
	default:
		bodyBytes, _ = json.Marshal(v)
	}

	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Header:     make(http.Header),
	}
}

func TestCallPushAPI_Success(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing successful push API call")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusOK, pushResponse{
			Success:           true,
			InstalledPath:     "/etc/ssh/trusted-user-ca-keys.d/ops-ca.pub",
			SSHDReloaded:      true,
			AttestationStatus: "verified",
			AttestationAge:    "5m",
		}),
	}

	// Save original and restore after test
	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API with caName=ops-ca, targetDPU=bf3-lab, force=false")
	resp, err := callPushAPI(config, "ops-ca", "bf3-lab", false)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	t.Log("Verifying response fields")
	if !resp.Success {
		t.Error("Expected success=true")
	}
	if resp.InstalledPath != "/etc/ssh/trusted-user-ca-keys.d/ops-ca.pub" {
		t.Errorf("Expected installed_path=/etc/ssh/trusted-user-ca-keys.d/ops-ca.pub, got %s", resp.InstalledPath)
	}
	if !resp.SSHDReloaded {
		t.Error("Expected sshd_reloaded=true")
	}
	if resp.AttestationStatus != "verified" {
		t.Errorf("Expected attestation_status=verified, got %s", resp.AttestationStatus)
	}
	if resp.AttestationAge != "5m" {
		t.Errorf("Expected attestation_age=5m, got %s", resp.AttestationAge)
	}

	t.Log("Verifying request body was sent correctly")
	// Verify request was sent correctly
	if mockClient.request == nil {
		t.Fatal("No request was made")
	}
	if mockClient.request.URL.Path != "/api/v1/push" {
		t.Errorf("Expected path /api/v1/push, got %s", mockClient.request.URL.Path)
	}

	var sentReq pushRequest
	body, _ := io.ReadAll(mockClient.request.Body)
	if err := json.Unmarshal(body, &sentReq); err != nil {
		t.Fatalf("Failed to parse request body: %v", err)
	}
	if sentReq.CAName != "ops-ca" {
		t.Errorf("Expected ca_name=ops-ca, got %s", sentReq.CAName)
	}
	if sentReq.TargetDPU != "bf3-lab" {
		t.Errorf("Expected target_dpu=bf3-lab, got %s", sentReq.TargetDPU)
	}
	if sentReq.OperatorID != "op_123" {
		t.Errorf("Expected operator_id=op_123, got %s", sentReq.OperatorID)
	}
	if sentReq.Force {
		t.Error("Expected force=false")
	}
}

func TestCallPushAPI_SuccessWithForce(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API call with force flag")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusOK, pushResponse{
			Success:           true,
			InstalledPath:     "/etc/ssh/trusted-user-ca-keys.d/ops-ca.pub",
			SSHDReloaded:      true,
			AttestationStatus: "stale",
			AttestationAge:    "2h",
		}),
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API with force=true")
	resp, err := callPushAPI(config, "ops-ca", "bf3-lab", true)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success=true")
	}

	t.Log("Verifying force flag was sent in request")
	var sentReq pushRequest
	body, _ := io.ReadAll(mockClient.request.Body)
	json.Unmarshal(body, &sentReq)
	if !sentReq.Force {
		t.Error("Expected force=true in request")
	}
}

func TestCallPushAPI_CANotFound(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API when CA is not found (404)")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusNotFound, map[string]string{
			"error": "CA not found",
		}),
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API expecting CA not found error")
	_, err := callPushAPI(config, "nonexistent-ca", "bf3-lab", false)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	t.Log("Verifying error type is CANotFound")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if cliErr.Code != clierror.CodeCANotFound {
		t.Errorf("Expected code %s, got %s", clierror.CodeCANotFound, cliErr.Code)
	}
}

func TestCallPushAPI_DeviceNotFound(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API when DPU is not found (404)")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusNotFound, map[string]string{
			"error": "DPU not found",
		}),
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API expecting device not found error")
	_, err := callPushAPI(config, "ops-ca", "nonexistent-dpu", false)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	t.Log("Verifying error type is DeviceNotFound")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if cliErr.Code != clierror.CodeDeviceNotFound {
		t.Errorf("Expected code %s, got %s", clierror.CodeDeviceNotFound, cliErr.Code)
	}
}

func TestCallPushAPI_NotAuthorized(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API when not authorized (403)")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusForbidden, map[string]string{
			"error": "not authorized for this CA and device",
		}),
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API expecting not authorized error")
	_, err := callPushAPI(config, "ops-ca", "bf3-lab", false)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	t.Log("Verifying error type is NotAuthorized")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if cliErr.Code != clierror.CodeNotAuthorized {
		t.Errorf("Expected code %s, got %s", clierror.CodeNotAuthorized, cliErr.Code)
	}
}

func TestCallPushAPI_AttestationStale(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API when attestation is stale (412)")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusPreconditionFailed, pushResponse{
			Success:           false,
			AttestationStatus: "stale",
			AttestationAge:    "2h",
			Message:           "attestation blocked: stale:2h",
		}),
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API expecting attestation stale error")
	resp, err := callPushAPI(config, "ops-ca", "bf3-lab", false)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	t.Log("Verifying response contains attestation details")
	if resp == nil {
		t.Fatal("Expected response with attestation details, got nil")
	}
	if resp.AttestationAge != "2h" {
		t.Errorf("Expected attestation_age=2h, got %s", resp.AttestationAge)
	}

	t.Log("Verifying error type is AttestationStale")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if cliErr.Code != clierror.CodeAttestationStale {
		t.Errorf("Expected code %s, got %s", clierror.CodeAttestationStale, cliErr.Code)
	}
}

func TestCallPushAPI_AttestationFailed(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API when attestation failed (412)")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusPreconditionFailed, pushResponse{
			Success:           false,
			AttestationStatus: "failed",
			Message:           "attestation failed: device failed integrity verification",
		}),
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API expecting attestation failed error")
	resp, err := callPushAPI(config, "ops-ca", "bf3-lab", false)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if resp == nil {
		t.Fatal("Expected response with attestation details, got nil")
	}

	t.Log("Verifying error type is AttestationFailed")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if cliErr.Code != clierror.CodeAttestationFailed {
		t.Errorf("Expected code %s, got %s", clierror.CodeAttestationFailed, cliErr.Code)
	}
}

func TestCallPushAPI_ConnectionError(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API when server connection fails")

	mockClient := &mockHTTPClient{
		err: &mockNetError{message: "connection refused"},
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API expecting connection failed error")
	_, err := callPushAPI(config, "ops-ca", "bf3-lab", false)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	t.Log("Verifying error type is ConnectionFailed")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if cliErr.Code != clierror.CodeConnectionFailed {
		t.Errorf("Expected code %s, got %s", clierror.CodeConnectionFailed, cliErr.Code)
	}
}

func TestCallPushAPI_ServerError(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API when server returns 500")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusInternalServerError, map[string]string{
			"error": "internal server error",
		}),
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API expecting internal error")
	_, err := callPushAPI(config, "ops-ca", "bf3-lab", false)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	t.Log("Verifying error type is InternalError")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if cliErr.Code != clierror.CodeInternalError {
		t.Errorf("Expected code %s, got %s", clierror.CodeInternalError, cliErr.Code)
	}
}

func TestCallPushAPI_ServiceUnavailable(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API when DPU connection fails (503)")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusServiceUnavailable, map[string]string{
			"error": "failed to connect to DPU",
		}),
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API expecting connection failed error")
	_, err := callPushAPI(config, "ops-ca", "bf3-lab", false)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	t.Log("Verifying error type is ConnectionFailed for DPU")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if cliErr.Code != clierror.CodeConnectionFailed {
		t.Errorf("Expected code %s, got %s", clierror.CodeConnectionFailed, cliErr.Code)
	}
	// Should reference the target DPU, not the server
	if !strings.Contains(cliErr.Message, "bf3-lab") {
		t.Errorf("Expected error message to contain 'bf3-lab', got: %s", cliErr.Message)
	}
}

func TestCallPushAPI_BadRequest(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing push API with bad request (400)")

	mockClient := &mockHTTPClient{
		response: newMockResponse(http.StatusBadRequest, map[string]string{
			"error": "ca_name is required",
		}),
	}

	originalClient := pushHTTPClient
	pushHTTPClient = mockClient
	defer func() { pushHTTPClient = originalClient }()

	config := &KMConfig{
		ServerURL: "http://localhost:8080",
		OperatorID:      "op_123",
	}

	t.Log("Calling push API expecting internal error for bad request")
	_, err := callPushAPI(config, "", "bf3-lab", false)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	t.Log("Verifying error type is InternalError")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if cliErr.Code != clierror.CodeInternalError {
		t.Errorf("Expected code %s, got %s", clierror.CodeInternalError, cliErr.Code)
	}
}

func TestHandlePushError_DeviceAuthorization(t *testing.T) {
	// Cannot run in parallel - callPushAPI uses global DPoP state
	t.Log("Testing error handling for device authorization failure")

	body := []byte(`{"error": "not authorized for device"}`)
	resp, err := handlePushError(http.StatusForbidden, body, "ops-ca", "bf3-lab")

	if resp != nil {
		t.Error("Expected nil response for auth error")
	}

	t.Log("Verifying error references the device")
	cliErr, ok := err.(*clierror.CLIError)
	if !ok {
		t.Fatalf("Expected *clierror.CLIError, got %T", err)
	}
	if !strings.Contains(cliErr.Message, "bf3-lab") {
		t.Errorf("Expected error to mention device 'bf3-lab', got: %s", cliErr.Message)
	}
}

// mockNetError implements net.Error for testing connection failures.
type mockNetError struct {
	message string
}

func (e *mockNetError) Error() string   { return e.message }
func (e *mockNetError) Timeout() bool   { return false }
func (e *mockNetError) Temporary() bool { return false }
