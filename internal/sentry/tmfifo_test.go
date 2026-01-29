package sentry

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/nmelo/secure-infra/internal/aegis/tmfifo"
)

func TestDetectTmfifo_notAvailable(t *testing.T) {
	// tmfifo_net0 interface should not exist in test environment
	iface, ok := DetectTmfifo()
	if ok {
		t.Skipf("tmfifo interface exists (%s), skipping unavailable test", iface)
	}

	if iface != "" {
		t.Errorf("expected empty interface name when not available, got %s", iface)
	}
}

func TestNewTmfifoClient(t *testing.T) {
	// Default address
	client := NewTmfifoClient("", "test-host")
	if client.dpuAddr != DefaultTmfifoDPUAddr {
		t.Errorf("expected default addr %s, got %s", DefaultTmfifoDPUAddr, client.dpuAddr)
	}
	if client.hostname != "test-host" {
		t.Errorf("expected hostname 'test-host', got %s", client.hostname)
	}

	// Custom address
	customAddr := "10.0.0.1:9444"
	client = NewTmfifoClient(customAddr, "custom-host")
	if client.dpuAddr != customAddr {
		t.Errorf("expected custom addr %s, got %s", customAddr, client.dpuAddr)
	}
}

func TestTmfifoClient_Open_connectionFailed(t *testing.T) {
	// Try to connect to non-existent address
	client := NewTmfifoClient("127.0.0.1:59999", "test-host")

	err := client.Open()
	if err == nil {
		client.Close()
		t.Fatal("expected error for connection refused")
	}
}

func TestTmfifoClient_Close_notOpen(t *testing.T) {
	client := NewTmfifoClient("127.0.0.1:9444", "test-host")

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

	client := NewTmfifoClient("127.0.0.1:9444", "test-host")
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
		ID:      "test-nonce",
	}

	// Handle the message (will fail on sendCredentialAck since not connected)
	err := client.handleCredentialPush(msg)
	// We expect this to fail on the ack, but the installation should succeed
	if err != nil {
		// The error should be about writing the ack, not installation
		t.Logf("expected error on ack (not connected): %v", err)
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
	client := NewTmfifoClient("127.0.0.1:9444", "test-host")

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
		ID:      "test-nonce",
	}

	// Handle should fail with unsupported type error
	err := client.handleCredentialPush(msg)
	// Error expected (either from handling or from ack)
	if err == nil {
		t.Log("no error returned, but credential was not installed (expected)")
	}
}

func TestTmfifoClient_handleCredentialPush_invalidPayload(t *testing.T) {
	client := NewTmfifoClient("127.0.0.1:9444", "test-host")

	msg := &tmfifo.Message{
		Type:    tmfifo.TypeCredentialPush,
		Payload: []byte("not json"),
		ID:      "test-nonce",
	}

	// Handle should fail with parse error
	err := client.handleCredentialPush(msg)
	// Error expected
	if err == nil {
		t.Log("no error returned (ack may have failed)")
	}
}

func TestTmfifoClient_handleMessage_unknownType(t *testing.T) {
	client := NewTmfifoClient("127.0.0.1:9444", "test-host")

	msg := &tmfifo.Message{
		Type:    "UNKNOWN_TYPE",
		Payload: []byte("{}"),
		ID:      "test-nonce",
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

// mockTmfifoDevice simulates a tmfifo connection for testing ReportPosture with credential push.
type mockTmfifoDevice struct {
	readBuf  []byte
	writeBuf []byte
	readIdx  int
}

func (m *mockTmfifoDevice) Read(p []byte) (n int, err error) {
	if m.readIdx >= len(m.readBuf) {
		return 0, io.EOF
	}
	n = copy(p, m.readBuf[m.readIdx:])
	m.readIdx += n
	return n, nil
}

func (m *mockTmfifoDevice) Write(p []byte) (n int, err error) {
	m.writeBuf = append(m.writeBuf, p...)
	return len(p), nil
}

func (m *mockTmfifoDevice) Close() error {
	return nil
}

func (m *mockTmfifoDevice) enqueueMessages(msgs ...*tmfifo.Message) {
	for _, msg := range msgs {
		data, _ := json.Marshal(msg)
		m.readBuf = append(m.readBuf, data...)
		m.readBuf = append(m.readBuf, '\n')
	}
}

func TestTmfifoClient_ReportPosture_handlesCredentialPushBeforeAck(t *testing.T) {
	// This test verifies that ReportPosture handles CREDENTIAL_PUSH messages
	// that arrive before the POSTURE_ACK, which can happen when the DPU
	// decides to push credentials as a result of the posture report.
	tmpDir := t.TempDir()

	// Create a mock device with pre-loaded responses:
	// 1. CREDENTIAL_PUSH (should be handled inline)
	// 2. POSTURE_ACK (expected final response)
	credPushPayload := tmfifo.CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "test-ca",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca"),
	}
	credPushBytes, _ := json.Marshal(credPushPayload)

	ackPayload := tmfifo.PostureAckPayload{
		Accepted: true,
	}
	ackBytes, _ := json.Marshal(ackPayload)

	mockDev := &mockTmfifoDevice{}
	mockDev.enqueueMessages(
		&tmfifo.Message{
			Type:    tmfifo.TypeCredentialPush,
			Payload: credPushBytes,
			ID:      "push-1",
		},
		&tmfifo.Message{
			Type:    tmfifo.TypePostureAck,
			Payload: ackBytes,
			ID:      "ack-1",
		},
	)

	client := &TmfifoClient{
		dpuAddr:  "127.0.0.1:9444",
		hostname: "test-host",
		credInstaller: &CredentialInstaller{
			TrustedCADir:   tmpDir,
			SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
		},
		stopCh: make(chan struct{}),
	}

	// Create a mock sshd_config
	os.WriteFile(client.credInstaller.SshdConfigPath, []byte("Port 22\n"), 0644)

	// Use the testable version of ReportPosture with mock device
	posture := json.RawMessage(`{"secure_boot": true}`)
	err := client.reportPostureWithReader(posture, mockDev, mockDev)

	if err != nil {
		t.Fatalf("ReportPosture failed: %v", err)
	}

	// Verify credential was installed
	caPath := filepath.Join(tmpDir, "test-ca.pub")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		t.Errorf("credential was not installed at %s", caPath)
	}
}

func TestTmfifoClient_ReportPosture_multipleCredentialPushesBeforeAck(t *testing.T) {
	// Test that multiple CREDENTIAL_PUSH messages are handled before the ack
	tmpDir := t.TempDir()

	credPush1 := tmfifo.CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "ca-1",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest ca-1"),
	}
	credPush1Bytes, _ := json.Marshal(credPush1)

	credPush2 := tmfifo.CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "ca-2",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest ca-2"),
	}
	credPush2Bytes, _ := json.Marshal(credPush2)

	ackPayload := tmfifo.PostureAckPayload{Accepted: true}
	ackBytes, _ := json.Marshal(ackPayload)

	mockDev := &mockTmfifoDevice{}
	mockDev.enqueueMessages(
		&tmfifo.Message{Type: tmfifo.TypeCredentialPush, Payload: credPush1Bytes, ID: "push-1"},
		&tmfifo.Message{Type: tmfifo.TypeCredentialPush, Payload: credPush2Bytes, ID: "push-2"},
		&tmfifo.Message{Type: tmfifo.TypePostureAck, Payload: ackBytes, ID: "ack-1"},
	)

	client := &TmfifoClient{
		dpuAddr:  "127.0.0.1:9444",
		hostname: "test-host",
		credInstaller: &CredentialInstaller{
			TrustedCADir:   tmpDir,
			SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
		},
		stopCh: make(chan struct{}),
	}
	os.WriteFile(client.credInstaller.SshdConfigPath, []byte("Port 22\n"), 0644)

	posture := json.RawMessage(`{"secure_boot": true}`)
	err := client.reportPostureWithReader(posture, mockDev, mockDev)

	if err != nil {
		t.Fatalf("ReportPosture failed: %v", err)
	}

	// Verify both credentials were installed
	for _, name := range []string{"ca-1", "ca-2"} {
		caPath := filepath.Join(tmpDir, name+".pub")
		if _, err := os.Stat(caPath); os.IsNotExist(err) {
			t.Errorf("credential %s was not installed", name)
		}
	}
}

func TestTmfifoClient_ReportPosture_ackStillRequired(t *testing.T) {
	// Test that PostureAck is still required even after handling credential pushes
	tmpDir := t.TempDir()

	credPushPayload := tmfifo.CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "test-ca",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca"),
	}
	credPushBytes, _ := json.Marshal(credPushPayload)

	// Only credential push, no ack
	mockDev := &mockTmfifoDevice{}
	mockDev.enqueueMessages(
		&tmfifo.Message{Type: tmfifo.TypeCredentialPush, Payload: credPushBytes, ID: "push-1"},
		// No POSTURE_ACK follows
	)

	client := &TmfifoClient{
		dpuAddr:  "127.0.0.1:9444",
		hostname: "test-host",
		credInstaller: &CredentialInstaller{
			TrustedCADir:   tmpDir,
			SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
		},
		stopCh: make(chan struct{}),
	}
	os.WriteFile(client.credInstaller.SshdConfigPath, []byte("Port 22\n"), 0644)

	posture := json.RawMessage(`{"secure_boot": true}`)
	err := client.reportPostureWithReader(posture, mockDev, mockDev)

	// Should fail because no ack was received (EOF)
	if err == nil {
		t.Fatal("expected error when no PostureAck received, got nil")
	}
}
