package sentry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nmelo/secure-infra/pkg/transport"
)

func TestClient_ReportPosture_handlesCredentialPushBeforeAck(t *testing.T) {
	// This test verifies that ReportPosture handles CREDENTIAL_PUSH messages
	// that arrive before the POSTURE_ACK.
	tmpDir := t.TempDir()

	mockTransport := transport.NewMockTransport()
	if err := mockTransport.Connect(context.TODO()); err != nil {
		t.Fatalf("connect mock transport: %v", err)
	}

	client := &Client{
		transport: mockTransport,
		hostname:  "test-host",
		credInstaller: &CredentialInstaller{
			TrustedCADir:   tmpDir,
			SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
		},
		stopCh: make(chan struct{}),
	}

	// Create a mock sshd_config
	os.WriteFile(client.credInstaller.SshdConfigPath, []byte("Port 22\n"), 0644)

	// Enqueue responses: CREDENTIAL_PUSH then POSTURE_ACK
	credPushPayload := CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "test-ca",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca"),
	}
	credPushBytes, _ := json.Marshal(credPushPayload)

	ackPayload := PostureAckPayload{Accepted: true}
	ackBytes, _ := json.Marshal(ackPayload)

	mockTransport.Enqueue(&transport.Message{
		Type:    transport.MessageCredentialPush,
		Payload: credPushBytes,
		ID:      "push-1",
	})
	mockTransport.Enqueue(&transport.Message{
		Type:    transport.MessagePostureAck,
		Payload: ackBytes,
		ID:      "ack-1",
	})

	posture := json.RawMessage(`{"secure_boot": true}`)
	err := client.ReportPosture(posture)

	if err != nil {
		t.Fatalf("ReportPosture failed: %v", err)
	}

	// Verify credential was installed
	caPath := filepath.Join(tmpDir, "test-ca.pub")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		t.Errorf("credential was not installed at %s", caPath)
	}

	// Verify posture report was sent
	sent := mockTransport.SentMessages()
	if len(sent) < 1 {
		t.Fatal("no messages sent")
	}
	if sent[0].Type != transport.MessagePostureReport {
		t.Errorf("first sent message type: got %s, want %s", sent[0].Type, transport.MessagePostureReport)
	}
}

func TestClient_ReportPosture_multipleCredentialPushesBeforeAck(t *testing.T) {
	// Test that multiple CREDENTIAL_PUSH messages are handled before the ack
	tmpDir := t.TempDir()

	mockTransport := transport.NewMockTransport()
	if err := mockTransport.Connect(context.TODO()); err != nil {
		t.Fatalf("connect mock transport: %v", err)
	}

	client := &Client{
		transport: mockTransport,
		hostname:  "test-host",
		credInstaller: &CredentialInstaller{
			TrustedCADir:   tmpDir,
			SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
		},
		stopCh: make(chan struct{}),
	}
	os.WriteFile(client.credInstaller.SshdConfigPath, []byte("Port 22\n"), 0644)

	// Enqueue: 2x CREDENTIAL_PUSH then POSTURE_ACK
	credPush1 := CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "ca-1",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest ca-1"),
	}
	credPush1Bytes, _ := json.Marshal(credPush1)

	credPush2 := CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "ca-2",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest ca-2"),
	}
	credPush2Bytes, _ := json.Marshal(credPush2)

	ackPayload := PostureAckPayload{Accepted: true}
	ackBytes, _ := json.Marshal(ackPayload)

	mockTransport.Enqueue(&transport.Message{Type: transport.MessageCredentialPush, Payload: credPush1Bytes, ID: "push-1"})
	mockTransport.Enqueue(&transport.Message{Type: transport.MessageCredentialPush, Payload: credPush2Bytes, ID: "push-2"})
	mockTransport.Enqueue(&transport.Message{Type: transport.MessagePostureAck, Payload: ackBytes, ID: "ack-1"})

	posture := json.RawMessage(`{"secure_boot": true}`)
	err := client.ReportPosture(posture)

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

func TestClient_ReportPosture_ackStillRequired(t *testing.T) {
	// Test that PostureAck is still required even after handling credential pushes
	tmpDir := t.TempDir()

	mockTransport := transport.NewMockTransport()
	if err := mockTransport.Connect(context.TODO()); err != nil {
		t.Fatalf("connect mock transport: %v", err)
	}

	client := &Client{
		transport: mockTransport,
		hostname:  "test-host",
		credInstaller: &CredentialInstaller{
			TrustedCADir:   tmpDir,
			SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
		},
		stopCh: make(chan struct{}),
	}
	os.WriteFile(client.credInstaller.SshdConfigPath, []byte("Port 22\n"), 0644)

	// Only enqueue credential push, no ack
	credPushPayload := CredentialPushPayload{
		CredentialType: "ssh-ca",
		CredentialName: "test-ca",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca"),
	}
	credPushBytes, _ := json.Marshal(credPushPayload)

	mockTransport.Enqueue(&transport.Message{Type: transport.MessageCredentialPush, Payload: credPushBytes, ID: "push-1"})

	// Close the transport to simulate EOF after credential push
	go func() {
		// Wait for the client to send posture report
		mockTransport.Dequeue()
		// Wait for client to receive credential push, then close
		mockTransport.Close()
	}()

	posture := json.RawMessage(`{"secure_boot": true}`)
	err := client.ReportPosture(posture)

	// Should fail because no ack was received
	if err == nil {
		t.Fatal("expected error when no PostureAck received, got nil")
	}
}

func TestClient_ReportPosture_unexpectedMessageType(t *testing.T) {
	// Test that unexpected message types (not CREDENTIAL_PUSH or POSTURE_ACK) cause an error
	mockTransport := transport.NewMockTransport()
	if err := mockTransport.Connect(context.TODO()); err != nil {
		t.Fatalf("connect mock transport: %v", err)
	}

	client := &Client{
		transport:     mockTransport,
		hostname:      "test-host",
		credInstaller: NewCredentialInstaller(),
		stopCh:        make(chan struct{}),
	}

	// Enqueue an unexpected message type
	mockTransport.Enqueue(&transport.Message{
		Type:    transport.MessageEnrollResponse, // Wrong type
		Payload: json.RawMessage(`{}`),
		ID:      "wrong-1",
	})

	posture := json.RawMessage(`{"secure_boot": true}`)
	err := client.ReportPosture(posture)

	if err == nil {
		t.Fatal("expected error for unexpected message type, got nil")
	}

	// Error message should mention the unexpected type
	if err.Error() != "unexpected response type: ENROLL_RESPONSE" {
		t.Errorf("unexpected error message: %v", err)
	}
}
