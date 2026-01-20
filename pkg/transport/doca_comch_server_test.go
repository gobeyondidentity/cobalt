//go:build !doca

package transport

import (
	"encoding/json"
	"testing"
)

// Tests for DOCAComchServer that don't require DOCA hardware.
// These test the stub behavior and type compatibility.

func TestDOCAComchServerConfig_Fields(t *testing.T) {
	// Test that the config struct has all expected fields
	cfg := DOCAComchServerConfig{
		PCIAddr:        "03:00.0",
		RepPCIAddr:     "01:00.0",
		ServerName:     "secureinfra",
		MaxMsgSize:     4096,
		RecvBufferSize: 32,
		MaxClients:     16,
	}

	if cfg.PCIAddr != "03:00.0" {
		t.Errorf("PCIAddr: got %s, want 03:00.0", cfg.PCIAddr)
	}
	if cfg.RepPCIAddr != "01:00.0" {
		t.Errorf("RepPCIAddr: got %s, want 01:00.0", cfg.RepPCIAddr)
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
	if cfg.MaxClients != 16 {
		t.Errorf("MaxClients: got %d, want 16", cfg.MaxClients)
	}
}

func TestNewDOCAComchServer_Stub(t *testing.T) {
	// Without DOCA SDK, NewDOCAComchServer should return an error
	cfg := DOCAComchServerConfig{
		PCIAddr:    "03:00.0",
		RepPCIAddr: "01:00.0",
		ServerName: "test",
	}

	server, err := NewDOCAComchServer(cfg)
	if err == nil {
		t.Fatal("expected error without DOCA SDK")
	}
	if server != nil {
		t.Fatal("expected nil server without DOCA SDK")
	}
	if err != ErrDOCANotAvailable {
		t.Errorf("expected ErrDOCANotAvailable, got %v", err)
	}
}

func TestDOCAComchServer_ConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     DOCAComchServerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: DOCAComchServerConfig{
				PCIAddr:    "03:00.0",
				RepPCIAddr: "01:00.0",
				ServerName: "test",
			},
			wantErr: false, // Will fail with ErrDOCANotAvailable, not validation
		},
		{
			name: "missing PCI address",
			cfg: DOCAComchServerConfig{
				RepPCIAddr: "01:00.0",
				ServerName: "test",
			},
			wantErr: true,
		},
		{
			name: "missing rep PCI address",
			cfg: DOCAComchServerConfig{
				PCIAddr:    "03:00.0",
				ServerName: "test",
			},
			wantErr: true,
		},
		{
			name: "missing server name",
			cfg: DOCAComchServerConfig{
				PCIAddr:    "03:00.0",
				RepPCIAddr: "01:00.0",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the validation function directly
			err := validateServerConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateServerConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDOCAComchServer_StubMethods(t *testing.T) {
	// Test that stub methods return expected errors
	var server DOCAComchServer

	_, err := server.Accept()
	if err != ErrDOCANotAvailable {
		t.Errorf("Accept: expected ErrDOCANotAvailable, got %v", err)
	}

	// Close should succeed (no-op)
	if err := server.Close(); err != nil {
		t.Errorf("Close: expected nil, got %v", err)
	}
}

func TestDOCAComchServer_StubType(t *testing.T) {
	var server DOCAComchServer
	if server.Type() != TransportDOCAComch {
		t.Errorf("Type: got %v, want %v", server.Type(), TransportDOCAComch)
	}
}

func TestDOCAComchServer_TransportListenerInterface(t *testing.T) {
	// Verify that DOCAComchServer implements TransportListener interface
	var _ TransportListener = (*DOCAComchServer)(nil)
}

// Tests for DOCAComchServerConn

func TestDOCAComchServerConn_StubMethods(t *testing.T) {
	var conn DOCAComchServerConn

	// All methods should return ErrDOCANotAvailable
	if err := conn.Connect(nil); err != ErrDOCANotAvailable {
		t.Errorf("Connect: expected ErrDOCANotAvailable, got %v", err)
	}

	msg := &Message{Type: MessageEnrollRequest}
	if err := conn.Send(msg); err != ErrDOCANotAvailable {
		t.Errorf("Send: expected ErrDOCANotAvailable, got %v", err)
	}

	_, err := conn.Recv()
	if err != ErrDOCANotAvailable {
		t.Errorf("Recv: expected ErrDOCANotAvailable, got %v", err)
	}

	// Close should succeed (no-op)
	if err := conn.Close(); err != nil {
		t.Errorf("Close: expected nil, got %v", err)
	}
}

func TestDOCAComchServerConn_StubType(t *testing.T) {
	var conn DOCAComchServerConn
	if conn.Type() != TransportDOCAComch {
		t.Errorf("Type: got %v, want %v", conn.Type(), TransportDOCAComch)
	}
}

func TestDOCAComchServerConn_TransportInterface(t *testing.T) {
	// Verify that DOCAComchServerConn implements Transport interface
	var _ Transport = (*DOCAComchServerConn)(nil)
}

// Test message handling patterns that would be used by server

func TestDOCAComchServer_MessageSerialization(t *testing.T) {
	// Test server-side message types
	tests := []struct {
		name string
		msg  *Message
	}{
		{
			name: "enroll response",
			msg: &Message{
				Type:    MessageEnrollResponse,
				Payload: json.RawMessage(`{"host_id":"h-123","status":"enrolled"}`),
				Nonce:   "nonce-123",
			},
		},
		{
			name: "posture ack",
			msg: &Message{
				Type:    MessagePostureAck,
				Payload: json.RawMessage(`{"accepted":true}`),
				Nonce:   "posture-456",
			},
		},
		{
			name: "credential push",
			msg: &Message{
				Type:    MessageCredentialPush,
				Payload: json.RawMessage(`{"type":"ssh-ca","data":"base64..."}`),
				Nonce:   "cred-789",
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
			if decoded.Nonce != tt.msg.Nonce {
				t.Errorf("nonce mismatch: got %s, want %s", decoded.Nonce, tt.msg.Nonce)
			}
			if string(decoded.Payload) != string(tt.msg.Payload) {
				t.Errorf("payload mismatch: got %s, want %s", decoded.Payload, tt.msg.Payload)
			}
		})
	}
}

func TestDOCAComchServerConn_State(t *testing.T) {
	var conn DOCAComchServerConn
	// Stub should return "unavailable"
	if conn.State() != "unavailable" {
		t.Errorf("State: got %s, want unavailable", conn.State())
	}
}

func TestDOCAComchServerConn_MaxMessageSize(t *testing.T) {
	var conn DOCAComchServerConn
	// Stub should return 0
	if conn.MaxMessageSize() != 0 {
		t.Errorf("MaxMessageSize: got %d, want 0", conn.MaxMessageSize())
	}
}

// Benchmark server message handling
func BenchmarkServerMessageMarshal(b *testing.B) {
	msg := &Message{
		Type:    MessageEnrollResponse,
		Payload: json.RawMessage(`{"host_id":"h-12345","status":"enrolled","assigned_policies":["base","high-security"]}`),
		Nonce:   "benchmark-nonce-server",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}
