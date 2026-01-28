package tmfifo

import (
	"context"
	"encoding/json"
	"testing"
)

// TestMessageMarshalUnmarshal verifies JSON serialization of protocol messages.
func TestMessageMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		msgType string
		payload interface{}
	}{
		{
			name:    "enroll request",
			msgType: TypeEnrollRequest,
			payload: EnrollRequestPayload{
				Hostname: "test-host",
				Posture:  json.RawMessage(`{"secure_boot":true}`),
			},
		},
		{
			name:    "enroll response success",
			msgType: TypeEnrollResponse,
			payload: EnrollResponsePayload{
				Success: true,
				HostID:  "host_12345678",
				DPUName: "dpu-test",
			},
		},
		{
			name:    "enroll response error",
			msgType: TypeEnrollResponse,
			payload: EnrollResponsePayload{
				Success: false,
				Error:   "hostname not allowed",
			},
		},
		{
			name:    "posture report",
			msgType: TypePostureReport,
			payload: PostureReportPayload{
				Hostname: "test-host",
				Posture:  json.RawMessage(`{"disk_encryption":"luks"}`),
			},
		},
		{
			name:    "posture ack",
			msgType: TypePostureAck,
			payload: PostureAckPayload{
				Accepted: true,
			},
		},
		{
			name:    "credential push",
			msgType: TypeCredentialPush,
			payload: CredentialPushPayload{
				CredentialType: "ssh-ca",
				CredentialName: "prod-ca",
				Data:           []byte("ssh-ed25519 AAAAC3NzaC1..."),
			},
		},
		{
			name:    "credential ack success",
			msgType: TypeCredentialAck,
			payload: CredentialAckPayload{
				Success:       true,
				InstalledPath: "/etc/ssh/trusted-user-ca-keys.d/prod-ca.pub",
			},
		},
		{
			name:    "credential ack failure",
			msgType: TypeCredentialAck,
			payload: CredentialAckPayload{
				Success: false,
				Error:   "permission denied",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Marshal payload
			payloadBytes, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("failed to marshal payload: %v", err)
			}

			// Create message
			msg := Message{
				Type:    tc.msgType,
				Payload: payloadBytes,
				ID:   "test-nonce-12345",
			}

			// Marshal message
			msgBytes, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal message: %v", err)
			}

			// Unmarshal message
			var decoded Message
			if err := json.Unmarshal(msgBytes, &decoded); err != nil {
				t.Fatalf("failed to unmarshal message: %v", err)
			}

			// Verify fields
			if decoded.Type != tc.msgType {
				t.Errorf("type mismatch: got %s, want %s", decoded.Type, tc.msgType)
			}
			if decoded.ID != msg.ID {
				t.Errorf("nonce mismatch: got %s, want %s", decoded.ID, msg.ID)
			}
			if len(decoded.Payload) == 0 {
				t.Error("payload is empty")
			}
		})
	}
}

// TestNonceTracking verifies replay protection via nonce tracking.
func TestNonceTracking(t *testing.T) {
	listener := NewListener("/dev/null", nil)

	// First nonce should be accepted
	nonce1 := "unique-nonce-1"
	if !listener.recordNonce(nonce1) {
		t.Error("first nonce should be accepted")
	}

	// Same nonce should be rejected (replay)
	if listener.recordNonce(nonce1) {
		t.Error("duplicate nonce should be rejected")
	}

	// Different nonce should be accepted
	nonce2 := "unique-nonce-2"
	if !listener.recordNonce(nonce2) {
		t.Error("second unique nonce should be accepted")
	}
}

// TestGenerateNonce verifies nonce generation produces unique values.
func TestGenerateNonce(t *testing.T) {
	seen := make(map[string]bool)
	iterations := 1000

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

// TestIsAvailable verifies device availability check.
func TestIsAvailable(t *testing.T) {
	// Default path should not exist in test environment
	if IsAvailable() {
		t.Skip("tmfifo device exists, skipping unavailable test")
	}

	// Non-existent path should return false
	if IsAvailableAt("/dev/nonexistent-device") {
		t.Error("non-existent device should not be available")
	}

	// /dev/null should exist on all Unix systems
	if !IsAvailableAt("/dev/null") {
		t.Error("/dev/null should be available")
	}
}

// TestListenerStartStop verifies basic listener lifecycle.
func TestListenerStartStop(t *testing.T) {
	// Try to create listener with non-existent device
	listener := NewListener("/dev/nonexistent-tmfifo", nil)

	ctx := context.Background()
	err := listener.Start(ctx)
	if err != ErrDeviceNotFound {
		t.Errorf("expected ErrDeviceNotFound, got: %v", err)
	}

	// Stop should be safe even if not started
	if err := listener.Stop(); err != nil {
		t.Errorf("stop on non-started listener should not error: %v", err)
	}
}

// TestDevicePath verifies device path configuration.
func TestDevicePath(t *testing.T) {
	// Default path
	listener := NewListener("", nil)
	if listener.DevicePath() != DefaultDevicePath {
		t.Errorf("expected default path %s, got %s", DefaultDevicePath, listener.DevicePath())
	}

	// Custom path
	customPath := "/dev/custom-tmfifo"
	listener = NewListener(customPath, nil)
	if listener.DevicePath() != customPath {
		t.Errorf("expected custom path %s, got %s", customPath, listener.DevicePath())
	}
}

// mockHandler implements MessageHandler for testing.
type mockHandler struct {
	enrollCalled  bool
	postureCalled bool
	enrollResp    *EnrollResponsePayload
	postureResp   *PostureAckPayload
	enrollErr     error
	postureErr    error
}

func (m *mockHandler) HandleEnroll(ctx context.Context, hostname string, posture json.RawMessage) (*EnrollResponsePayload, error) {
	m.enrollCalled = true
	if m.enrollErr != nil {
		return nil, m.enrollErr
	}
	if m.enrollResp != nil {
		return m.enrollResp, nil
	}
	return &EnrollResponsePayload{Success: true, HostID: "host_test"}, nil
}

func (m *mockHandler) HandlePosture(ctx context.Context, hostname string, posture json.RawMessage) (*PostureAckPayload, error) {
	m.postureCalled = true
	if m.postureErr != nil {
		return nil, m.postureErr
	}
	if m.postureResp != nil {
		return m.postureResp, nil
	}
	return &PostureAckPayload{Accepted: true}, nil
}

// TestCredentialPushPayload verifies credential push message structure.
func TestCredentialPushPayload(t *testing.T) {
	payload := CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "prod-ca",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest... ca@example.com"),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded CredentialPushPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.CredentialType != payload.CredentialType {
		t.Errorf("credential_type mismatch: got %s, want %s", decoded.CredentialType, payload.CredentialType)
	}
	if decoded.CredentialName != payload.CredentialName {
		t.Errorf("credential_name mismatch: got %s, want %s", decoded.CredentialName, payload.CredentialName)
	}
	if string(decoded.Data) != string(payload.Data) {
		t.Errorf("data mismatch: got %s, want %s", string(decoded.Data), string(payload.Data))
	}
}

// TestMessageConstants verifies message type constants are defined correctly.
func TestMessageConstants(t *testing.T) {
	expectedTypes := map[string]string{
		"TypeEnrollRequest":  "ENROLL_REQUEST",
		"TypeEnrollResponse": "ENROLL_RESPONSE",
		"TypePostureReport":  "POSTURE_REPORT",
		"TypePostureAck":     "POSTURE_ACK",
		"TypeCredentialPush": "CREDENTIAL_PUSH",
		"TypeCredentialAck":  "CREDENTIAL_ACK",
	}

	actuals := map[string]string{
		"TypeEnrollRequest":  TypeEnrollRequest,
		"TypeEnrollResponse": TypeEnrollResponse,
		"TypePostureReport":  TypePostureReport,
		"TypePostureAck":     TypePostureAck,
		"TypeCredentialPush": TypeCredentialPush,
		"TypeCredentialAck":  TypeCredentialAck,
	}

	for name, expected := range expectedTypes {
		if actuals[name] != expected {
			t.Errorf("%s: got %s, want %s", name, actuals[name], expected)
		}
	}
}
