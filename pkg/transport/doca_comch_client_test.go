//go:build !doca

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Tests for DOCAComchClient that don't require DOCA hardware.
// These test the stub behavior and type compatibility.

func TestDOCAComchClientConfig_Fields(t *testing.T) {
	t.Log("Testing DOCAComchClientConfig struct has all expected fields")
	cfg := DOCAComchClientConfig{
		PCIAddr:        "01:00.0",
		ServerName:     "secureinfra",
		MaxMsgSize:     4096,
		RecvBufferSize: 32,
	}

	if cfg.PCIAddr != "01:00.0" {
		t.Errorf("PCIAddr: got %s, want 01:00.0", cfg.PCIAddr)
	}
	if cfg.ServerName != "secureinfra" {
		t.Errorf("ServerName: got %s, want secureinfra", cfg.ServerName)
	}
	if cfg.MaxMsgSize != 4096 {
		t.Errorf("MaxMsgSize: got %d, want 4096", cfg.MaxMsgSize)
	}
	if cfg.RecvBufferSize != 32 {
		t.Errorf("RecvBufferSize: got %d, want 32", cfg.RecvBufferSize)
	}
}

func TestNewDOCAComchClient_Stub(t *testing.T) {
	t.Log("Testing NewDOCAComchClient returns ErrDOCANotAvailable without DOCA SDK")
	cfg := DOCAComchClientConfig{
		PCIAddr:    "01:00.0",
		ServerName: "test",
	}

	client, err := NewDOCAComchClient(cfg)
	if err == nil {
		t.Fatal("expected error without DOCA SDK")
	}
	if client != nil {
		t.Fatal("expected nil client without DOCA SDK")
	}
	if err != ErrDOCANotAvailable {
		t.Errorf("expected ErrDOCANotAvailable, got %v", err)
	}
}

func TestDOCAComchClient_StubMethods(t *testing.T) {
	t.Log("Testing DOCAComchClient stub methods return ErrDOCANotAvailable")
	var client DOCAComchClient

	ctx := context.Background()
	if err := client.Connect(ctx); err != ErrDOCANotAvailable {
		t.Errorf("Connect: expected ErrDOCANotAvailable, got %v", err)
	}

	msg := &Message{Type: MessageEnrollRequest}
	if err := client.Send(msg); err != ErrDOCANotAvailable {
		t.Errorf("Send: expected ErrDOCANotAvailable, got %v", err)
	}

	_, err := client.Recv()
	if err != ErrDOCANotAvailable {
		t.Errorf("Recv: expected ErrDOCANotAvailable, got %v", err)
	}

	// Close should succeed (no-op)
	if err := client.Close(); err != nil {
		t.Errorf("Close: expected nil, got %v", err)
	}
}

func TestDOCAComchClient_StubType(t *testing.T) {
	t.Log("Testing DOCAComchClient.Type() returns TransportDOCAComch")
	var client DOCAComchClient
	if client.Type() != TransportDOCAComch {
		t.Errorf("Type: got %v, want %v", client.Type(), TransportDOCAComch)
	}
}

func TestDOCAComchClient_StubState(t *testing.T) {
	t.Log("Testing DOCAComchClient.State() returns 'unavailable' for stub")
	var client DOCAComchClient
	if client.State() != "unavailable" {
		t.Errorf("State: got %s, want unavailable", client.State())
	}
}

func TestDOCAComchClient_StubMaxMessageSize(t *testing.T) {
	t.Log("Testing DOCAComchClient.MaxMessageSize() returns 0 for stub")
	var client DOCAComchClient
	if client.MaxMessageSize() != 0 {
		t.Errorf("MaxMessageSize: got %d, want 0", client.MaxMessageSize())
	}
}

func TestDocaComchAvailable_Stub(t *testing.T) {
	t.Log("Testing docaComchAvailable() returns false without DOCA SDK")
	if docaComchAvailable() {
		t.Error("docaComchAvailable should return false without DOCA SDK")
	}
}

func TestDOCAComchClient_TransportInterface(t *testing.T) {
	t.Log("Testing DOCAComchClient implements Transport interface")
	var _ Transport = (*DOCAComchClient)(nil)
}

// Tests for message serialization that would be used by DOCAComchClient

func TestDOCAComchClient_MessageSerialization(t *testing.T) {
	t.Log("Testing client-side message serialization round-trip")
	tests := []struct {
		name string
		msg  *Message
	}{
		{
			name: "enroll request",
			msg: &Message{
				Type:    MessageEnrollRequest,
				Payload: json.RawMessage(`{"hostname":"test-host"}`),
				ID:   "nonce-123",
			},
		},
		{
			name: "posture report",
			msg: &Message{
				Type:    MessagePostureReport,
				Payload: json.RawMessage(`{"score":95}`),
				ID:   "posture-456",
			},
		},
		{
			name: "credential push",
			msg: &Message{
				Type:    MessageCredentialPush,
				Payload: json.RawMessage(`{"type":"ssh-ca","data":"base64..."}`),
				ID:   "cred-789",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data, err := json.Marshal(tt.msg)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			// Deserialize
			var decoded Message
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			// Verify round-trip
			if decoded.Type != tt.msg.Type {
				t.Errorf("type mismatch: got %s, want %s", decoded.Type, tt.msg.Type)
			}
			if decoded.ID != tt.msg.ID {
				t.Errorf("nonce mismatch: got %s, want %s", decoded.ID, tt.msg.ID)
			}
			if string(decoded.Payload) != string(tt.msg.Payload) {
				t.Errorf("payload mismatch: got %s, want %s", decoded.Payload, tt.msg.Payload)
			}
		})
	}
}

func TestDOCAComchClient_MessageSizeValidation(t *testing.T) {
	t.Log("Testing message size validation against 4KB limit")
	maxSize := uint32(4096)

	// Message under limit
	smallPayload := make([]byte, 1000)
	smallMsg := &Message{
		Type:    MessageEnrollRequest,
		Payload: json.RawMessage(smallPayload),
		ID:   "test",
	}
	smallData, _ := json.Marshal(smallMsg)
	if uint32(len(smallData)) > maxSize {
		t.Errorf("small message should fit: %d > %d", len(smallData), maxSize)
	}

	// Message over limit - need valid JSON and larger size
	// Create a large JSON payload (5000 bytes of a single character would create
	// an invalid JSON, so we create a valid JSON string instead)
	largeContent := make([]byte, 5000)
	for i := range largeContent {
		largeContent[i] = 'x'
	}
	// Wrap in a valid JSON object with a string field
	largePayloadJSON := fmt.Sprintf(`{"data":"%s"}`, string(largeContent))
	largeMsg := &Message{
		Type:    MessagePostureReport,
		Payload: json.RawMessage(largePayloadJSON),
		ID:   "large-test",
	}
	largeData, _ := json.Marshal(largeMsg)
	if uint32(len(largeData)) <= maxSize {
		t.Errorf("large message should exceed limit: %d <= %d", len(largeData), maxSize)
	}
}

func TestDOCAComchClient_ContextCancellation(t *testing.T) {
	t.Log("Testing client handles context cancellation correctly")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	var client DOCAComchClient

	// Connect with cancelled context should eventually return
	// (stub returns immediately with ErrDOCANotAvailable, but pattern is important)
	err := client.Connect(ctx)
	if err != ErrDOCANotAvailable {
		t.Errorf("expected ErrDOCANotAvailable, got %v", err)
	}
}

// Benchmark message serialization
func BenchmarkMessageMarshal(b *testing.B) {
	msg := &Message{
		Type:    MessagePostureReport,
		Payload: json.RawMessage(`{"score":95,"checks":["firewall","disk","software"],"timestamp":"2026-01-20T12:00:00Z"}`),
		ID:   "benchmark-nonce-12345",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageUnmarshal(b *testing.B) {
	data := []byte(`{"type":"POSTURE_REPORT","payload":{"score":95,"checks":["firewall","disk","software"],"timestamp":"2026-01-20T12:00:00Z"},"nonce":"benchmark-nonce-12345"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			b.Fatal(err)
		}
	}
}

// ============================================================================
// Additional Stub Tests for Coverage
// ============================================================================

func TestNewDOCAComchTransport_Stub(t *testing.T) {
	t.Log("Testing NewDOCAComchTransport returns ErrDOCANotAvailable without DOCA SDK")
	transport, err := NewDOCAComchTransport()
	if transport != nil {
		t.Error("expected nil transport without DOCA SDK")
	}
	if err != ErrDOCANotAvailable {
		t.Errorf("expected ErrDOCANotAvailable, got %v", err)
	}
}

func TestCheckComchClientCapability_Stub(t *testing.T) {
	t.Log("Testing CheckComchClientCapability returns ErrDOCANotAvailable without DOCA SDK")
	capable, err := CheckComchClientCapability("01:00.0")
	if capable {
		t.Error("expected false capability without DOCA SDK")
	}
	if err != ErrDOCANotAvailable {
		t.Errorf("expected ErrDOCANotAvailable, got %v", err)
	}
}

func TestCheckComchServerCapability_Stub(t *testing.T) {
	t.Log("Testing CheckComchServerCapability returns ErrDOCANotAvailable without DOCA SDK")
	capable, err := CheckComchServerCapability("03:00.0")
	if capable {
		t.Error("expected false capability without DOCA SDK")
	}
	if err != ErrDOCANotAvailable {
		t.Errorf("expected ErrDOCANotAvailable, got %v", err)
	}
}
