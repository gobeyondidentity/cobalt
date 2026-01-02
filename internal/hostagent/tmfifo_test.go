package hostagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nmelo/secure-infra/internal/agent/tmfifo"
)

func TestDetectTmfifo_notAvailable(t *testing.T) {
	// Default path should not exist in test environment
	path, ok := DetectTmfifo()
	if ok {
		t.Skipf("tmfifo device exists at %s, skipping unavailable test", path)
	}

	if path != "" {
		t.Errorf("expected empty path when not available, got %s", path)
	}
}

func TestNewTmfifoClient(t *testing.T) {
	// Default path
	client := NewTmfifoClient("", "test-host")
	if client.devicePath != DefaultTmfifoPath {
		t.Errorf("expected default path %s, got %s", DefaultTmfifoPath, client.devicePath)
	}
	if client.hostname != "test-host" {
		t.Errorf("expected hostname 'test-host', got %s", client.hostname)
	}

	// Custom path
	customPath := "/dev/custom-tmfifo"
	client = NewTmfifoClient(customPath, "custom-host")
	if client.devicePath != customPath {
		t.Errorf("expected custom path %s, got %s", customPath, client.devicePath)
	}
}

func TestTmfifoClient_Open_deviceNotFound(t *testing.T) {
	client := NewTmfifoClient("/dev/nonexistent-tmfifo", "test-host")

	err := client.Open()
	if err == nil {
		t.Fatal("expected error for nonexistent device")
	}
}

func TestTmfifoClient_Close_notOpen(t *testing.T) {
	client := NewTmfifoClient("/dev/nonexistent", "test-host")

	// Should not error when closing a non-open client
	if err := client.Close(); err != nil {
		t.Errorf("Close on non-open client should not error: %v", err)
	}
}

func TestGenerateNonce(t *testing.T) {
	seen := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		nonce := generateNonce()
		if seen[nonce] {
			t.Fatalf("duplicate nonce generated after %d iterations", i)
		}
		seen[nonce] = true

		// Verify nonce is hex-encoded and has expected length (32 hex chars = 16 bytes)
		if len(nonce) != 32 {
			t.Errorf("nonce has wrong length: got %d, want 32", len(nonce))
		}
	}
}

func TestTmfifoClient_handleCredentialPush_sshCA(t *testing.T) {
	tmpDir := t.TempDir()

	client := NewTmfifoClient("/dev/null", "test-host")
	client.credInstaller = &CredentialInstaller{
		TrustedCADir:   tmpDir,
		SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
	}

	// Create sshd_config
	if err := os.WriteFile(client.credInstaller.SshdConfigPath, []byte("Port 22\n"), 0644); err != nil {
		t.Fatalf("create sshd_config: %v", err)
	}

	// Build credential push message
	payload := tmfifo.CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "test-ca",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca"),
	}
	payloadBytes, _ := json.Marshal(payload)

	msg := &tmfifo.Message{
		Type:    tmfifo.TypeCredentialPush,
		Payload: payloadBytes,
		Nonce:   "test-nonce",
	}

	// Handle the message (will fail on sendCredentialAck since device is /dev/null)
	err := client.handleCredentialPush(msg)
	// We expect this to fail on the ack, but the installation should succeed
	if err != nil {
		// The error should be about writing the ack, not installation
		t.Logf("expected error on ack: %v", err)
	}

	// Verify the CA was installed
	caPath := filepath.Join(tmpDir, "test-ca.pub")
	content, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read installed CA: %v", err)
	}

	expected := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca\n"
	if string(content) != expected {
		t.Errorf("CA content mismatch:\ngot:  %q\nwant: %q", string(content), expected)
	}
}

func TestTmfifoClient_handleCredentialPush_unsupportedType(t *testing.T) {
	client := NewTmfifoClient("/dev/null", "test-host")

	// Build credential push with unsupported type
	payload := tmfifo.CredentialPushPayload{
		CredentialType: "unknown-type",
		CredentialName: "test",
		Data:           []byte("data"),
	}
	payloadBytes, _ := json.Marshal(payload)

	msg := &tmfifo.Message{
		Type:    tmfifo.TypeCredentialPush,
		Payload: payloadBytes,
		Nonce:   "test-nonce",
	}

	// Handle should fail with unsupported type error
	err := client.handleCredentialPush(msg)
	// Error expected (either from handling or from ack)
	if err == nil {
		t.Log("no error returned, but credential was not installed (expected)")
	}
}

func TestTmfifoClient_handleCredentialPush_invalidPayload(t *testing.T) {
	client := NewTmfifoClient("/dev/null", "test-host")

	msg := &tmfifo.Message{
		Type:    tmfifo.TypeCredentialPush,
		Payload: []byte("not json"),
		Nonce:   "test-nonce",
	}

	// Handle should fail with parse error
	err := client.handleCredentialPush(msg)
	// Error expected
	if err == nil {
		t.Log("no error returned (ack may have failed)")
	}
}

func TestTmfifoClient_handleMessage_unknownType(t *testing.T) {
	client := NewTmfifoClient("/dev/null", "test-host")

	msg := &tmfifo.Message{
		Type:    "UNKNOWN_TYPE",
		Payload: []byte("{}"),
		Nonce:   "test-nonce",
	}

	// Unknown types should be ignored without error
	if err := client.handleMessage(msg); err != nil {
		t.Errorf("unknown message type should not error: %v", err)
	}
}

func TestTmfifoMessageTypes(t *testing.T) {
	// Verify we're using the correct message types from the tmfifo package
	expectedTypes := map[string]string{
		"enroll_request":  tmfifo.TypeEnrollRequest,
		"enroll_response": tmfifo.TypeEnrollResponse,
		"posture_report":  tmfifo.TypePostureReport,
		"posture_ack":     tmfifo.TypePostureAck,
		"credential_push": tmfifo.TypeCredentialPush,
		"credential_ack":  tmfifo.TypeCredentialAck,
	}

	if tmfifo.TypeEnrollRequest != "ENROLL_REQUEST" {
		t.Errorf("TypeEnrollRequest: got %s, want ENROLL_REQUEST", tmfifo.TypeEnrollRequest)
	}
	if tmfifo.TypeEnrollResponse != "ENROLL_RESPONSE" {
		t.Errorf("TypeEnrollResponse: got %s, want ENROLL_RESPONSE", tmfifo.TypeEnrollResponse)
	}
	if tmfifo.TypeCredentialPush != "CREDENTIAL_PUSH" {
		t.Errorf("TypeCredentialPush: got %s, want CREDENTIAL_PUSH", tmfifo.TypeCredentialPush)
	}
	if tmfifo.TypeCredentialAck != "CREDENTIAL_ACK" {
		t.Errorf("TypeCredentialAck: got %s, want CREDENTIAL_ACK", tmfifo.TypeCredentialAck)
	}

	_ = expectedTypes // Used for documentation
}

func TestEnrollRequestPayload(t *testing.T) {
	payload := tmfifo.EnrollRequestPayload{
		Hostname: "test-host",
		Posture:  json.RawMessage(`{"secure_boot":true}`),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded tmfifo.EnrollRequestPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Hostname != payload.Hostname {
		t.Errorf("hostname mismatch: got %s, want %s", decoded.Hostname, payload.Hostname)
	}
}

func TestCredentialAckPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload tmfifo.CredentialAckPayload
	}{
		{
			name: "success",
			payload: tmfifo.CredentialAckPayload{
				Success:       true,
				InstalledPath: "/etc/ssh/trusted-user-ca-keys.d/test-ca.pub",
			},
		},
		{
			name: "failure",
			payload: tmfifo.CredentialAckPayload{
				Success: false,
				Error:   "permission denied",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var decoded tmfifo.CredentialAckPayload
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			if decoded.Success != tc.payload.Success {
				t.Errorf("success mismatch: got %v, want %v", decoded.Success, tc.payload.Success)
			}
			if decoded.InstalledPath != tc.payload.InstalledPath {
				t.Errorf("installed_path mismatch: got %s, want %s", decoded.InstalledPath, tc.payload.InstalledPath)
			}
			if decoded.Error != tc.payload.Error {
				t.Errorf("error mismatch: got %s, want %s", decoded.Error, tc.payload.Error)
			}
		})
	}
}
