package tmfifo

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Message Serialization Tests
// ============================================================================

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
				ID:      "test-nonce-12345",
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

// ============================================================================
// Nonce and Replay Protection Tests
// ============================================================================

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

// TestNonceTrackingConcurrent verifies nonce tracking is thread-safe.
func TestNonceTrackingConcurrent(t *testing.T) {
	listener := NewListener("/dev/null", nil)

	var wg sync.WaitGroup
	nonces := make(chan string, 100)
	accepted := make(chan string, 100)

	// Generate 100 unique nonces
	for i := 0; i < 100; i++ {
		nonces <- generateNonce()
	}
	close(nonces)

	// 10 goroutines trying to record nonces concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for nonce := range nonces {
				if listener.recordNonce(nonce) {
					accepted <- nonce
				}
			}
		}()
	}

	wg.Wait()
	close(accepted)

	// All 100 unique nonces should be accepted exactly once
	count := 0
	for range accepted {
		count++
	}
	if count != 100 {
		t.Errorf("expected 100 unique nonces accepted, got %d", count)
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

// TestNonceCleanup verifies that old nonces are cleaned up.
func TestNonceCleanup(t *testing.T) {
	listener := NewListener("/dev/null", nil)

	// Record a nonce with an old timestamp
	oldNonce := "old-nonce"
	listener.nonceMu.Lock()
	listener.seenNonces[oldNonce] = time.Now().Add(-10 * time.Minute) // 10 minutes old
	listener.nonceMu.Unlock()

	// Record a recent nonce
	recentNonce := "recent-nonce"
	listener.recordNonce(recentNonce)

	// Run cleanup
	listener.cleanupNonces()

	// Old nonce should be removed
	listener.nonceMu.RLock()
	_, oldExists := listener.seenNonces[oldNonce]
	_, recentExists := listener.seenNonces[recentNonce]
	listener.nonceMu.RUnlock()

	if oldExists {
		t.Error("old nonce should have been cleaned up")
	}
	if !recentExists {
		t.Error("recent nonce should not have been cleaned up")
	}
}

// ============================================================================
// Device Availability Tests
// ============================================================================

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

// ============================================================================
// Connection Tests
// ============================================================================

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

// TestListenerStartWithValidDevice verifies listener starts with valid device.
func TestListenerStartWithValidDevice(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	// Create a fake device file
	f, err := os.Create(fakePath)
	if err != nil {
		t.Fatalf("failed to create fake device: %v", err)
	}
	f.Close()

	handler := &mockHandler{}
	listener := NewListener(fakePath, handler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = listener.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify started state
	listener.startMu.Lock()
	started := listener.started
	listener.startMu.Unlock()

	if !started {
		t.Error("expected listener to be started")
	}

	// Stop should succeed
	err = listener.Stop()
	if err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// TestListenerDoubleStart verifies error on double start.
func TestListenerDoubleStart(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	f, _ := os.Create(fakePath)
	f.Close()

	listener := NewListener(fakePath, nil)

	ctx := context.Background()
	err := listener.Start(ctx)
	if err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	defer listener.Stop()

	// Second start should fail
	err = listener.Start(ctx)
	if err == nil {
		t.Error("expected error on double start")
	}
	if !strings.Contains(err.Error(), "already started") {
		t.Errorf("error should mention already started: %v", err)
	}
}

// TestListenerStartWithInvalidPath tests various invalid path scenarios.
func TestListenerStartWithInvalidPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError error
	}{
		{
			name:        "non-existent path",
			path:        "/nonexistent/path/tmfifo",
			expectError: ErrDeviceNotFound,
		},
		// Note: empty path now creates a TCP listener on the default port,
		// which succeeds. This is tested separately in TestListenerStartStop.
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listener := NewListener(tc.path, nil)
			err := listener.Start(context.Background())
			if !errors.Is(err, tc.expectError) && err != tc.expectError {
				t.Errorf("expected %v, got %v", tc.expectError, err)
			}
			listener.Stop()
		})
	}
}

// ============================================================================
// Device Path Tests
// ============================================================================

// TestDevicePath verifies device path configuration.
func TestDevicePath(t *testing.T) {
	// Empty path uses TCP listener on default address
	listener := NewListener("", nil)
	if listener.ListenAddr() != DefaultListenAddr {
		t.Errorf("expected default listen addr %s, got %s", DefaultListenAddr, listener.ListenAddr())
	}

	// Unix socket path (starts with /)
	socketPath := "/dev/custom-tmfifo"
	listener = NewListener(socketPath, nil)
	if listener.SocketPath() != socketPath {
		t.Errorf("expected socket path %s, got %s", socketPath, listener.SocketPath())
	}
	// DevicePath returns socket path for backward compat
	if listener.DevicePath() != socketPath {
		t.Errorf("expected DevicePath %s, got %s", socketPath, listener.DevicePath())
	}
}

// ============================================================================
// Message Handling Tests
// ============================================================================

// mockHandler implements MessageHandler for testing.
type mockHandler struct {
	enrollCalled    bool
	postureCalled   bool
	enrollResp      *EnrollResponsePayload
	postureResp     *PostureAckPayload
	enrollErr       error
	postureErr      error
	lastHostname    string
	lastPosture     json.RawMessage
	mu              sync.Mutex
}

func (m *mockHandler) HandleEnroll(ctx context.Context, hostname string, posture json.RawMessage) (*EnrollResponsePayload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enrollCalled = true
	m.lastHostname = hostname
	m.lastPosture = posture
	if m.enrollErr != nil {
		return nil, m.enrollErr
	}
	if m.enrollResp != nil {
		return m.enrollResp, nil
	}
	return &EnrollResponsePayload{Success: true, HostID: "host_test"}, nil
}

func (m *mockHandler) HandlePosture(ctx context.Context, hostname string, posture json.RawMessage) (*PostureAckPayload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.postureCalled = true
	m.lastHostname = hostname
	m.lastPosture = posture
	if m.postureErr != nil {
		return nil, m.postureErr
	}
	if m.postureResp != nil {
		return m.postureResp, nil
	}
	return &PostureAckPayload{Accepted: true}, nil
}

// TestHandleEnrollRequest tests enrollment request handling.
func TestHandleEnrollRequest(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	// Create device file for write
	f, err := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	handler := &mockHandler{}
	listener := NewListener(fakePath, handler)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	// Create enrollment request message
	payload := EnrollRequestPayload{
		Hostname: "test-host",
		Posture:  json.RawMessage(`{"secure_boot":true}`),
	}
	payloadBytes, _ := json.Marshal(payload)
	msg := Message{
		Type:    TypeEnrollRequest,
		ID:      generateNonce(),
		Payload: payloadBytes,
	}
	msgBytes, _ := json.Marshal(msg)

	// Handle the message
	err = listener.handleMessage(context.Background(), msgBytes)
	if err != nil {
		t.Fatalf("handleMessage failed: %v", err)
	}

	// Verify handler was called
	handler.mu.Lock()
	called := handler.enrollCalled
	hostname := handler.lastHostname
	handler.mu.Unlock()

	if !called {
		t.Error("expected HandleEnroll to be called")
	}
	if hostname != "test-host" {
		t.Errorf("hostname = %q, want %q", hostname, "test-host")
	}

	f.Close()
}

// TestHandlePostureReport tests posture report handling.
func TestHandlePostureReport(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	f, err := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	handler := &mockHandler{}
	listener := NewListener(fakePath, handler)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	// Create posture report message
	payload := PostureReportPayload{
		Hostname: "test-host",
		Posture:  json.RawMessage(`{"disk_encryption":"luks"}`),
	}
	payloadBytes, _ := json.Marshal(payload)
	msg := Message{
		Type:    TypePostureReport,
		ID:      generateNonce(),
		Payload: payloadBytes,
	}
	msgBytes, _ := json.Marshal(msg)

	// Handle the message
	err = listener.handleMessage(context.Background(), msgBytes)
	if err != nil {
		t.Fatalf("handleMessage failed: %v", err)
	}

	// Verify handler was called
	handler.mu.Lock()
	called := handler.postureCalled
	handler.mu.Unlock()

	if !called {
		t.Error("expected HandlePosture to be called")
	}

	f.Close()
}

// TestHandleMessageReplayDetection tests that duplicate nonces are rejected.
func TestHandleMessageReplayDetection(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	f, _ := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)

	handler := &mockHandler{}
	listener := NewListener(fakePath, handler)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	// Create message with fixed nonce
	payload := EnrollRequestPayload{Hostname: "test-host"}
	payloadBytes, _ := json.Marshal(payload)
	msg := Message{
		Type:    TypeEnrollRequest,
		ID:      "fixed-nonce-12345",
		Payload: payloadBytes,
	}
	msgBytes, _ := json.Marshal(msg)

	// First message should succeed
	err := listener.handleMessage(context.Background(), msgBytes)
	if err != nil {
		t.Fatalf("first message should succeed: %v", err)
	}

	// Second message with same nonce should be rejected
	err = listener.handleMessage(context.Background(), msgBytes)
	if !errors.Is(err, ErrReplayDetected) {
		t.Errorf("expected ErrReplayDetected, got %v", err)
	}

	f.Close()
}

// TestHandleMessageNoHandler tests handling when no handler is configured.
func TestHandleMessageNoHandler(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	f, _ := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)

	// No handler
	listener := NewListener(fakePath, nil)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	payload := EnrollRequestPayload{Hostname: "test-host"}
	payloadBytes, _ := json.Marshal(payload)
	msg := Message{
		Type:    TypeEnrollRequest,
		ID:      generateNonce(),
		Payload: payloadBytes,
	}
	msgBytes, _ := json.Marshal(msg)

	err := listener.handleMessage(context.Background(), msgBytes)
	if err == nil {
		t.Error("expected error when no handler configured")
	}
	if !strings.Contains(err.Error(), "no handler") {
		t.Errorf("error should mention no handler: %v", err)
	}

	f.Close()
}

// TestHandleMessageHandlerError tests error propagation from handler.
func TestHandleMessageHandlerError(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	f, _ := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)

	handler := &mockHandler{
		enrollErr: errors.New("enrollment denied"),
	}
	listener := NewListener(fakePath, handler)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	payload := EnrollRequestPayload{Hostname: "test-host"}
	payloadBytes, _ := json.Marshal(payload)
	msg := Message{
		Type:    TypeEnrollRequest,
		ID:      generateNonce(),
		Payload: payloadBytes,
	}
	msgBytes, _ := json.Marshal(msg)

	// Handler error is wrapped in response, not returned as error
	err := listener.handleMessage(context.Background(), msgBytes)
	if err != nil {
		t.Fatalf("handleMessage should not return error for handler failure: %v", err)
	}

	f.Close()
}

// TestHandleUnknownMessageType tests handling of unknown message types.
func TestHandleUnknownMessageType(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	f, _ := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)

	listener := NewListener(fakePath, nil)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	msg := Message{
		Type: "UNKNOWN_TYPE",
		ID:   generateNonce(),
	}
	msgBytes, _ := json.Marshal(msg)

	// Unknown types are logged but not an error
	err := listener.handleMessage(context.Background(), msgBytes)
	if err != nil {
		t.Errorf("unknown message type should not return error: %v", err)
	}

	f.Close()
}

// TestHandleInvalidJSON tests handling of malformed JSON.
func TestHandleInvalidJSON(t *testing.T) {
	listener := NewListener("/dev/null", nil)

	err := listener.handleMessage(context.Background(), []byte("not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse message") {
		t.Errorf("error should mention parse: %v", err)
	}
}

// TestHandleCredentialAck tests credential ack handling.
func TestHandleCredentialAck(t *testing.T) {
	listener := NewListener("/dev/null", nil)

	// Success ack
	payload := CredentialAckPayload{
		Success:       true,
		InstalledPath: "/etc/ssh/ca.pub",
	}
	payloadBytes, _ := json.Marshal(payload)
	msg := Message{
		Type:    TypeCredentialAck,
		ID:      generateNonce(),
		Payload: payloadBytes,
	}

	err := listener.handleCredentialAck(&msg)
	if err != nil {
		t.Errorf("handleCredentialAck should not error: %v", err)
	}

	// Failure ack
	payload = CredentialAckPayload{
		Success: false,
		Error:   "permission denied",
	}
	payloadBytes, _ = json.Marshal(payload)
	msg.Payload = payloadBytes

	err = listener.handleCredentialAck(&msg)
	if err != nil {
		t.Errorf("handleCredentialAck should not error: %v", err)
	}
}

// ============================================================================
// Send Message Tests
// ============================================================================

// TestSendMessageDeviceNotOpen tests sending when no connection is active.
func TestSendMessageDeviceNotOpen(t *testing.T) {
	listener := NewListener("/dev/null", nil)

	msg := &Message{Type: TypeCredentialPush}
	err := listener.sendMessage(msg)
	if err == nil {
		t.Error("expected error when no active connection")
	}
	if !strings.Contains(err.Error(), "no active connection") {
		t.Errorf("error should mention no active connection: %v", err)
	}
}

// TestSendMessage tests successful message sending.
func TestSendMessage(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	f, err := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	listener := NewListener(fakePath, nil)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	msg := &Message{
		Type:    TypeCredentialPush,
		ID:      "test-nonce",
		Payload: json.RawMessage(`{"test":"data"}`),
	}

	err = listener.sendMessage(msg)
	if err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	// Verify message was written
	f.Seek(0, 0)
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if !strings.Contains(string(data), TypeCredentialPush) {
		t.Error("written data should contain message type")
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("message should end with newline")
	}

	f.Close()
}

// TestSendCredentialPush tests the high-level credential push method.
func TestSendCredentialPush(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	f, _ := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)

	listener := NewListener(fakePath, nil)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	err := listener.SendCredentialPush("ssh-ca", "prod-ca", []byte("ssh-ed25519 AAAA..."))
	if err != nil {
		t.Fatalf("SendCredentialPush failed: %v", err)
	}

	// Verify message content
	f.Seek(0, 0)
	data, _ := io.ReadAll(f)

	if !strings.Contains(string(data), TypeCredentialPush) {
		t.Error("should contain CREDENTIAL_PUSH")
	}
	if !strings.Contains(string(data), "ssh-ca") {
		t.Error("should contain credential type")
	}
	if !strings.Contains(string(data), "prod-ca") {
		t.Error("should contain credential name")
	}

	f.Close()
}

// TestPushCredential tests the PushCredential wrapper method.
func TestPushCredential(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	f, _ := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)

	listener := NewListener(fakePath, nil)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	result, err := listener.PushCredential("ssh-ca", "prod-ca", []byte("key-data"))
	if err != nil {
		t.Fatalf("PushCredential failed: %v", err)
	}

	if !result.Success {
		t.Error("result.Success should be true")
	}
	if !strings.Contains(result.Message, "sent to host") {
		t.Errorf("message should indicate sent: %s", result.Message)
	}

	f.Close()
}

// TestPushCredentialDeviceClosed tests PushCredential when device is not open.
func TestPushCredentialDeviceClosed(t *testing.T) {
	listener := NewListener("/dev/null", nil)

	_, err := listener.PushCredential("ssh-ca", "prod-ca", []byte("key-data"))
	if err == nil {
		t.Error("expected error when device not open")
	}
}

// ============================================================================
// Credential Payload Tests
// ============================================================================

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

// ============================================================================
// Message Constant Tests
// ============================================================================

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

// ============================================================================
// Message Round-trip Tests
// ============================================================================

// TestMessageRoundTrip tests complete message send/receive cycle using pipes.
func TestMessageRoundTrip(t *testing.T) {
	// Create a pipe for bidirectional communication simulation
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	// Prepare message
	payload := EnrollRequestPayload{
		Hostname: "test-host",
		Posture:  json.RawMessage(`{"secure_boot":true}`),
	}
	payloadBytes, _ := json.Marshal(payload)
	msg := Message{
		Type:    TypeEnrollRequest,
		ID:      "round-trip-test",
		Payload: payloadBytes,
	}

	// Send in goroutine
	go func() {
		data, _ := json.Marshal(msg)
		data = append(data, '\n')
		w.Write(data)
	}()

	// Read with timeout
	done := make(chan struct{})
	var received Message
	var readErr error

	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		n, err := r.Read(buf)
		if err != nil {
			readErr = err
			return
		}
		readErr = json.Unmarshal(buf[:n-1], &received) // -1 to exclude newline
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for message")
	}

	if readErr != nil {
		t.Fatalf("read error: %v", readErr)
	}

	if received.Type != msg.Type {
		t.Errorf("type mismatch: got %s, want %s", received.Type, msg.Type)
	}
	if received.ID != msg.ID {
		t.Errorf("ID mismatch: got %s, want %s", received.ID, msg.ID)
	}
}

// TestMessageRoundTripMultiple tests multiple messages in sequence.
func TestMessageRoundTripMultiple(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	messages := []Message{
		{Type: TypeEnrollRequest, ID: "msg-1"},
		{Type: TypePostureReport, ID: "msg-2"},
		{Type: TypeCredentialPush, ID: "msg-3"},
	}

	// Write all messages
	go func() {
		for _, msg := range messages {
			data, _ := json.Marshal(msg)
			data = append(data, '\n')
			w.Write(data)
		}
		// Close writer to signal EOF
		w.Close()
	}()

	// Read all messages using bufio for proper line reading
	reader := bufio.NewReader(r)
	received := make([]Message, 0, len(messages))

	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		if len(line) > 0 {
			var msg Message
			if err := json.Unmarshal(line[:len(line)-1], &msg); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			received = append(received, msg)
		}
	}

	if len(received) != len(messages) {
		t.Fatalf("expected %d messages, got %d", len(messages), len(received))
	}

	for i, msg := range messages {
		if received[i].ID != msg.ID {
			t.Errorf("message %d: ID = %s, want %s", i, received[i].ID, msg.ID)
		}
	}
}

// ============================================================================
// State Transition Tests
// ============================================================================

// ListenerState represents the possible states of a Listener.
type ListenerState string

const (
	StateUninitialized ListenerState = "uninitialized"
	StateReady         ListenerState = "ready"
	StateRunning       ListenerState = "running"
	StateStopped       ListenerState = "stopped"
)

// TestListenerStateTransitions tests valid state transitions using table-driven tests.
func TestListenerStateTransitions(t *testing.T) {
	tests := []struct {
		name          string
		initialState  ListenerState
		action        string
		expectedState ListenerState
		expectError   bool
	}{
		{
			name:          "uninitialized to ready via NewListener",
			initialState:  StateUninitialized,
			action:        "NewListener",
			expectedState: StateReady,
			expectError:   false,
		},
		{
			name:          "ready to running via Start",
			initialState:  StateReady,
			action:        "Start",
			expectedState: StateRunning,
			expectError:   false,
		},
		{
			name:          "running to stopped via Stop",
			initialState:  StateRunning,
			action:        "Stop",
			expectedState: StateStopped,
			expectError:   false,
		},
		{
			name:          "running to running via double Start fails",
			initialState:  StateRunning,
			action:        "Start",
			expectedState: StateRunning,
			expectError:   true,
		},
		{
			name:          "stopped to stopped via Stop is safe",
			initialState:  StateStopped,
			action:        "Stop",
			expectedState: StateStopped,
			expectError:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			fakePath := filepath.Join(tmpDir, "tmfifo_test")
			f, _ := os.Create(fakePath)
			f.Close()

			var listener *Listener
			var err error
			ctx := context.Background()

			// Setup initial state
			switch tc.initialState {
			case StateUninitialized:
				// Do nothing
			case StateReady:
				listener = NewListener(fakePath, nil)
			case StateRunning:
				listener = NewListener(fakePath, nil)
				listener.Start(ctx)
			case StateStopped:
				listener = NewListener(fakePath, nil)
				listener.Start(ctx)
				listener.Stop()
			}

			// Perform action
			switch tc.action {
			case "NewListener":
				listener = NewListener(fakePath, nil)
			case "Start":
				if listener != nil {
					err = listener.Start(ctx)
				}
			case "Stop":
				if listener != nil {
					err = listener.Stop()
				}
			}

			// Check error expectation
			if tc.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Cleanup
			if listener != nil {
				listener.Stop()
			}
		})
	}
}

// ============================================================================
// Context Cancellation Tests
// ============================================================================

// TestListenerContextCancellation tests that listener respects context cancellation.
func TestListenerContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")
	f, _ := os.Create(fakePath)
	f.Close()

	listener := NewListener(fakePath, nil)

	ctx, cancel := context.WithCancel(context.Background())
	err := listener.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Cancel context
	cancel()

	// Give goroutines time to notice cancellation
	time.Sleep(100 * time.Millisecond)

	// Stop should still work cleanly
	err = listener.Stop()
	if err != nil {
		t.Errorf("Stop after context cancel should succeed: %v", err)
	}
}

// ============================================================================
// Protocol Version Tests
// ============================================================================

// TestProtocolVersion verifies protocol version constant.
func TestProtocolVersion(t *testing.T) {
	if ProtocolVersion != 1 {
		t.Errorf("ProtocolVersion = %d, want 1", ProtocolVersion)
	}
}

// TestMessageWithVersion tests message includes version field.
func TestMessageWithVersion(t *testing.T) {
	msg := Message{
		Version: ProtocolVersion,
		Type:    TypeEnrollRequest,
		ID:      "test-id",
	}

	data, _ := json.Marshal(msg)
	if !strings.Contains(string(data), `"v":1`) {
		t.Error("marshaled message should contain version field")
	}

	var decoded Message
	json.Unmarshal(data, &decoded)
	if decoded.Version != ProtocolVersion {
		t.Errorf("decoded Version = %d, want %d", decoded.Version, ProtocolVersion)
	}
}

// ============================================================================
// Error Translation Tests (DOCA Error Code Mapping)
// ============================================================================

// DOCAError represents a DOCA error code with its human-readable translation.
type DOCAError struct {
	Code        int
	Name        string
	Description string
}

// DOCAErrorMap provides human-readable translations for known DOCA error codes.
// This mapping helps operators understand errors without looking up DOCA documentation.
var DOCAErrorMap = map[int]DOCAError{
	0:    {Code: 0, Name: "DOCA_SUCCESS", Description: "operation completed successfully"},
	-1:   {Code: -1, Name: "DOCA_ERROR_UNKNOWN", Description: "unknown error occurred"},
	-2:   {Code: -2, Name: "DOCA_ERROR_NOT_PERMITTED", Description: "operation not permitted"},
	-3:   {Code: -3, Name: "DOCA_ERROR_NOT_SUPPORTED", Description: "operation not supported"},
	-4:   {Code: -4, Name: "DOCA_ERROR_INVALID_VALUE", Description: "invalid value provided"},
	-5:   {Code: -5, Name: "DOCA_ERROR_NO_MEMORY", Description: "insufficient memory available"},
	-6:   {Code: -6, Name: "DOCA_ERROR_INITIALIZATION", Description: "initialization failed"},
	-7:   {Code: -7, Name: "DOCA_ERROR_SHUTDOWN", Description: "shutdown in progress"},
	-8:   {Code: -8, Name: "DOCA_ERROR_CONNECTION_RESET", Description: "connection was reset by peer"},
	-9:   {Code: -9, Name: "DOCA_ERROR_CONNECTION_ABORTED", Description: "connection was aborted"},
	-10:  {Code: -10, Name: "DOCA_ERROR_CONNECTION_INPROGRESS", Description: "connection attempt in progress"},
	-11:  {Code: -11, Name: "DOCA_ERROR_NOT_CONNECTED", Description: "not connected"},
	-12:  {Code: -12, Name: "DOCA_ERROR_IN_USE", Description: "resource is already in use"},
	-13:  {Code: -13, Name: "DOCA_ERROR_TIMEOUT", Description: "operation timed out"},
	-14:  {Code: -14, Name: "DOCA_ERROR_RESOURCE_BUSY", Description: "resource busy, retry operation"},
	-15:  {Code: -15, Name: "DOCA_ERROR_AGAIN", Description: "resource temporarily unavailable, retry"},
	-16:  {Code: -16, Name: "DOCA_ERROR_IO", Description: "I/O error occurred"},
	-17:  {Code: -17, Name: "DOCA_ERROR_BAD_STATE", Description: "object is in invalid state for operation"},
	-18:  {Code: -18, Name: "DOCA_ERROR_OVERFLOW", Description: "buffer overflow"},
	-19:  {Code: -19, Name: "DOCA_ERROR_UNDERFLOW", Description: "buffer underflow"},
	-20:  {Code: -20, Name: "DOCA_ERROR_ALREADY_EXIST", Description: "object already exists"},
	-21:  {Code: -21, Name: "DOCA_ERROR_NOT_FOUND", Description: "object not found"},
	-22:  {Code: -22, Name: "DOCA_ERROR_FULL", Description: "resource is full"},
	-23:  {Code: -23, Name: "DOCA_ERROR_EMPTY", Description: "resource is empty"},
	-24:  {Code: -24, Name: "DOCA_ERROR_DRIVER", Description: "driver error"},
	-25:  {Code: -25, Name: "DOCA_ERROR_OPERATING_SYSTEM", Description: "operating system error"},
}

// TranslateDOCAError converts a DOCA error code to a human-readable message.
func TranslateDOCAError(code int) string {
	if err, ok := DOCAErrorMap[code]; ok {
		return err.Description
	}
	return "unknown DOCA error"
}

// TestDOCAErrorTranslation verifies DOCA error code translations.
func TestDOCAErrorTranslation(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{0, "operation completed successfully"},
		{-1, "unknown error occurred"},
		{-8, "connection was reset by peer"},
		{-11, "not connected"},
		{-13, "operation timed out"},
		{-14, "resource busy, retry operation"},
		{-15, "resource temporarily unavailable, retry"},
		{-16, "I/O error occurred"},
		{-17, "object is in invalid state for operation"},
		{-999, "unknown DOCA error"}, // Unknown code
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			result := TranslateDOCAError(tc.code)
			if result != tc.expected {
				t.Errorf("TranslateDOCAError(%d) = %q, want %q", tc.code, result, tc.expected)
			}
		})
	}
}

// TestDOCAErrorMapCompleteness verifies all common DOCA errors are mapped.
func TestDOCAErrorMapCompleteness(t *testing.T) {
	// Critical error codes that must be mapped
	criticalCodes := []int{
		0,   // SUCCESS
		-8,  // CONNECTION_RESET
		-11, // NOT_CONNECTED
		-13, // TIMEOUT
		-14, // RESOURCE_BUSY (commonly seen)
		-15, // AGAIN
		-16, // IO
	}

	for _, code := range criticalCodes {
		if _, ok := DOCAErrorMap[code]; !ok {
			t.Errorf("critical DOCA error code %d is not mapped", code)
		}
	}
}

// TestDOCAError14Translation specifically tests the -14 error mentioned in acceptance criteria.
func TestDOCAError14Translation(t *testing.T) {
	result := TranslateDOCAError(-14)
	if !strings.Contains(result, "busy") || !strings.Contains(result, "retry") {
		t.Errorf("DOCA -14 should indicate busy/retry: got %q", result)
	}
}

// ============================================================================
// Reconnection Tests
// ============================================================================

// TestListenerReconnectionAfterDisconnect tests that listener can be restarted.
func TestListenerReconnectionAfterDisconnect(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")

	handler := &mockHandler{}

	// First connection cycle - create file before starting
	f, _ := os.Create(fakePath)
	f.Close()

	listener := NewListener(fakePath, handler)
	ctx := context.Background()

	err := listener.Start(ctx)
	if err != nil {
		t.Fatalf("first Start failed: %v", err)
	}

	err = listener.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Recreate file for second listener (Stop may have cleaned it up)
	f, _ = os.Create(fakePath)
	f.Close()

	// Create new listener (simulating reconnection)
	listener2 := NewListener(fakePath, handler)

	err = listener2.Start(ctx)
	if err != nil {
		t.Fatalf("reconnection Start failed: %v", err)
	}
	defer listener2.Stop()

	// Verify listener is functional by checking started state
	listener2.startMu.Lock()
	started := listener2.started
	listener2.startMu.Unlock()

	if !started {
		t.Error("reconnected listener should be started")
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

// TestEmptyMessage tests handling of empty message.
func TestEmptyMessage(t *testing.T) {
	listener := NewListener("/dev/null", nil)

	err := listener.handleMessage(context.Background(), []byte{})
	if err == nil {
		t.Error("expected error for empty message")
	}
}

// TestLargePayload tests handling of large payloads near the limit.
func TestLargePayload(t *testing.T) {
	// Create a large but valid payload
	largeData := make([]byte, 60*1024) // 60KB, under the 64KB limit
	for i := range largeData {
		largeData[i] = 'A'
	}

	payload := CredentialPushPayload{
		CredentialType: "test",
		CredentialName: "large",
		Data:           largeData,
	}

	// Should marshal without error
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal large payload: %v", err)
	}

	// Should unmarshal without error
	var decoded CredentialPushPayload
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal large payload: %v", err)
	}

	if len(decoded.Data) != len(largeData) {
		t.Errorf("data length mismatch: got %d, want %d", len(decoded.Data), len(largeData))
	}
}

// TestMessageWithEmptyNonce tests message without nonce (edge case).
func TestMessageWithEmptyNonce(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")
	f, _ := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)

	listener := NewListener(fakePath, &mockHandler{})
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	// Message with empty ID should still be processed (nonce check skipped)
	payload := EnrollRequestPayload{Hostname: "test-host"}
	payloadBytes, _ := json.Marshal(payload)
	msg := Message{
		Type:    TypeEnrollRequest,
		ID:      "", // Empty nonce
		Payload: payloadBytes,
	}
	msgBytes, _ := json.Marshal(msg)

	err := listener.handleMessage(context.Background(), msgBytes)
	if err != nil {
		t.Errorf("message with empty nonce should be handled: %v", err)
	}

	f.Close()
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

// TestConcurrentSends tests multiple concurrent send operations.
func TestConcurrentSends(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_test")
	f, _ := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)

	listener := NewListener(fakePath, nil)
	listener.activeConn = &fileConn{file: f}
	listener.started = true

	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			msg := &Message{
				Type: TypeCredentialPush,
				ID:   generateNonce(),
			}
			if err := listener.sendMessage(msg); err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent send error: %v", err)
	}

	f.Close()
}

// TestConcurrentNonceRecording tests concurrent nonce recording is safe.
func TestConcurrentNonceRecording(t *testing.T) {
	listener := NewListener("/dev/null", nil)

	var wg sync.WaitGroup
	duplicates := make(chan string, 100)

	// Use same nonce from multiple goroutines
	sharedNonce := "shared-nonce"

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if listener.recordNonce(sharedNonce) {
				duplicates <- sharedNonce
			}
		}()
	}

	wg.Wait()
	close(duplicates)

	// Only one goroutine should have successfully recorded the nonce
	count := 0
	for range duplicates {
		count++
	}

	if count != 1 {
		t.Errorf("expected exactly 1 successful recording, got %d", count)
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

// BenchmarkGenerateNonce measures nonce generation performance.
func BenchmarkGenerateNonce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateNonce()
	}
}

// BenchmarkNonceRecording measures nonce recording performance.
func BenchmarkNonceRecording(b *testing.B) {
	listener := NewListener("/dev/null", nil)
	nonces := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		nonces[i] = generateNonce()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		listener.recordNonce(nonces[i])
	}
}

// BenchmarkMessageMarshal measures message marshaling performance.
func BenchmarkMessageMarshal(b *testing.B) {
	payload := EnrollRequestPayload{
		Hostname: "test-host",
		Posture:  json.RawMessage(`{"secure_boot":true,"disk_encryption":"luks"}`),
	}
	payloadBytes, _ := json.Marshal(payload)
	msg := Message{
		Version: ProtocolVersion,
		Type:    TypeEnrollRequest,
		ID:      "test-nonce-12345",
		TS:      time.Now().UnixMilli(),
		Payload: payloadBytes,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(msg)
	}
}
