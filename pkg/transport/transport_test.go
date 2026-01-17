package transport

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMessage_Serialization(t *testing.T) {
	tests := []struct {
		name    string
		message *Message
	}{
		{
			name: "enroll request",
			message: &Message{
				Type:    MessageEnrollRequest,
				Payload: json.RawMessage(`{"hostname":"test-host","os":"linux"}`),
				Nonce:   "nonce-12345",
			},
		},
		{
			name: "enroll response",
			message: &Message{
				Type:    MessageEnrollResponse,
				Payload: json.RawMessage(`{"host_id":"host-001","status":"enrolled"}`),
				Nonce:   "nonce-67890",
			},
		},
		{
			name: "posture report",
			message: &Message{
				Type:    MessagePostureReport,
				Payload: json.RawMessage(`{"posture_score":85,"checks":["firewall","antivirus"]}`),
				Nonce:   "posture-nonce",
			},
		},
		{
			name: "empty payload",
			message: &Message{
				Type:    MessagePostureAck,
				Payload: json.RawMessage(`{}`),
				Nonce:   "ack-nonce",
			},
		},
		{
			name: "null payload",
			message: &Message{
				Type:    MessageCredentialAck,
				Payload: json.RawMessage(`null`),
				Nonce:   "cred-ack-nonce",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data, err := json.Marshal(tt.message)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			// Deserialize
			var decoded Message
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			// Verify fields
			if decoded.Type != tt.message.Type {
				t.Errorf("type mismatch: got %s, want %s", decoded.Type, tt.message.Type)
			}
			if decoded.Nonce != tt.message.Nonce {
				t.Errorf("nonce mismatch: got %s, want %s", decoded.Nonce, tt.message.Nonce)
			}

			// Verify payload (compare as strings for RawMessage)
			if string(decoded.Payload) != string(tt.message.Payload) {
				t.Errorf("payload mismatch: got %s, want %s", decoded.Payload, tt.message.Payload)
			}
		})
	}
}

func TestMessage_JSONFields(t *testing.T) {
	msg := &Message{
		Type:    MessageEnrollRequest,
		Payload: json.RawMessage(`{"key":"value"}`),
		Nonce:   "test-nonce",
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Verify JSON field names match expected wire format
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	expectedFields := []string{"type", "payload", "nonce"}
	for _, field := range expectedFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("expected JSON field %q not found", field)
		}
	}

	if len(raw) != len(expectedFields) {
		t.Errorf("unexpected number of fields: got %d, want %d", len(raw), len(expectedFields))
	}
}

func TestTransportType_Values(t *testing.T) {
	tests := []struct {
		transportType TransportType
		expected      string
	}{
		{TransportDOCAComch, "doca_comch"},
		{TransportTmfifoNet, "tmfifo_net"},
		{TransportNetwork, "network"},
		{TransportMock, "mock"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.transportType) != tt.expected {
				t.Errorf("got %s, want %s", tt.transportType, tt.expected)
			}
		})
	}
}

func TestMessageType_Values(t *testing.T) {
	tests := []struct {
		messageType MessageType
		expected    string
	}{
		{MessageEnrollRequest, "ENROLL_REQUEST"},
		{MessageEnrollResponse, "ENROLL_RESPONSE"},
		{MessagePostureReport, "POSTURE_REPORT"},
		{MessagePostureAck, "POSTURE_ACK"},
		{MessageCredentialPush, "CREDENTIAL_PUSH"},
		{MessageCredentialAck, "CREDENTIAL_ACK"},
		{MessageCertRequest, "CERT_REQUEST"},
		{MessageCertResponse, "CERT_RESPONSE"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.messageType) != tt.expected {
				t.Errorf("got %s, want %s", tt.messageType, tt.expected)
			}
		})
	}
}

func TestMessage_PayloadExtraction(t *testing.T) {
	// Test extracting structured data from payload
	type enrollPayload struct {
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
	}

	original := enrollPayload{
		Hostname: "test-host",
		OS:       "linux",
	}

	payloadBytes, _ := json.Marshal(original)
	msg := &Message{
		Type:    MessageEnrollRequest,
		Payload: payloadBytes,
		Nonce:   "extraction-test",
	}

	// Serialize full message
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal message failed: %v", err)
	}

	// Deserialize
	var decoded Message
	if err := json.Unmarshal(msgBytes, &decoded); err != nil {
		t.Fatalf("unmarshal message failed: %v", err)
	}

	// Extract payload
	var extracted enrollPayload
	if err := json.Unmarshal(decoded.Payload, &extracted); err != nil {
		t.Fatalf("unmarshal payload failed: %v", err)
	}

	if extracted.Hostname != original.Hostname {
		t.Errorf("hostname mismatch: got %s, want %s", extracted.Hostname, original.Hostname)
	}
	if extracted.OS != original.OS {
		t.Errorf("os mismatch: got %s, want %s", extracted.OS, original.OS)
	}
}

func TestMessage_RoundTrip(t *testing.T) {
	// Test full round-trip through MockTransport
	mt := NewMockTransport()
	if err := mt.Connect(context.Background()); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer mt.Close()

	original := &Message{
		Type:    MessagePostureReport,
		Payload: json.RawMessage(`{"score":95,"timestamp":"2026-01-17T12:00:00Z"}`),
		Nonce:   "round-trip-nonce",
	}

	// Send the message
	if err := mt.Send(original); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// Retrieve from send channel
	received, err := mt.Dequeue()
	if err != nil {
		t.Fatalf("dequeue failed: %v", err)
	}

	// Verify round-trip preservation
	if received.Type != original.Type {
		t.Errorf("type mismatch: got %s, want %s", received.Type, original.Type)
	}
	if received.Nonce != original.Nonce {
		t.Errorf("nonce mismatch: got %s, want %s", received.Nonce, original.Nonce)
	}
	if string(received.Payload) != string(original.Payload) {
		t.Errorf("payload mismatch: got %s, want %s", received.Payload, original.Payload)
	}
}
