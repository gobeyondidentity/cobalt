package transport

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestProtocolMessageEnvelope tests Message serialization/deserialization.
func TestProtocolMessageEnvelope(t *testing.T) {
	t.Log("Testing Message envelope serialization and deserialization")

	t.Run("round-trip all fields", func(t *testing.T) {
		t.Log("Verifying all Message fields survive JSON round-trip")
		original := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthChallenge,
			ID:      "550e8400-e29b-41d4-a716-446655440000",
			TS:      1737244800000,
			Payload: json.RawMessage(`{"nonce":"abc123"}`),
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Version != original.Version {
			t.Errorf("Version: got %d, want %d", decoded.Version, original.Version)
		}
		if decoded.Type != original.Type {
			t.Errorf("Type: got %s, want %s", decoded.Type, original.Type)
		}
		if decoded.ID != original.ID {
			t.Errorf("ID: got %s, want %s", decoded.ID, original.ID)
		}
		if decoded.TS != original.TS {
			t.Errorf("TS: got %d, want %d", decoded.TS, original.TS)
		}
		if string(decoded.Payload) != string(original.Payload) {
			t.Errorf("Payload: got %s, want %s", decoded.Payload, original.Payload)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		t.Log("Verifying empty payload {} is preserved")
		original := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthOK,
			ID:      "test-id",
			TS:      1737244800000,
			Payload: json.RawMessage(`{}`),
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if string(decoded.Payload) != "{}" {
			t.Errorf("empty payload not preserved: got %s", decoded.Payload)
		}
	})

	t.Run("null payload", func(t *testing.T) {
		t.Log("Verifying null payload is preserved")
		original := &Message{
			Version: ProtocolVersion,
			Type:    MessagePostureAck,
			ID:      "test-id",
			TS:      1737244800000,
			Payload: json.RawMessage(`null`),
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if string(decoded.Payload) != "null" {
			t.Errorf("null payload not preserved: got %s", decoded.Payload)
		}
	})

	t.Run("large payload near 4KB limit", func(t *testing.T) {
		t.Log("Verifying large payload (~3.8KB) is preserved")
		// Generate payload just under 4KB
		largeData := strings.Repeat("x", 3800)
		payloadJSON, _ := json.Marshal(map[string]string{"data": largeData})

		original := &Message{
			Version: ProtocolVersion,
			Type:    MessagePostureReport,
			ID:      "large-payload-test",
			TS:      1737244800000,
			Payload: payloadJSON,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if string(decoded.Payload) != string(original.Payload) {
			t.Error("large payload not preserved correctly")
		}
	})

	t.Run("wire format field names", func(t *testing.T) {
		t.Log("Verifying JSON field names match wire format: v, type, id, ts, payload")
		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageEnrollRequest,
			ID:      "test-id",
			TS:      1737244800000,
			Payload: json.RawMessage(`{}`),
		}

		data, _ := json.Marshal(msg)
		var raw map[string]any
		json.Unmarshal(data, &raw)

		// Verify JSON tags produce expected wire format
		expectedFields := map[string]bool{
			"v":       true,
			"type":    true,
			"id":      true,
			"ts":      true,
			"payload": true,
		}

		for field := range expectedFields {
			if _, ok := raw[field]; !ok {
				t.Errorf("expected wire format field %q not found", field)
			}
		}

		for field := range raw {
			if !expectedFields[field] {
				t.Errorf("unexpected wire format field %q", field)
			}
		}
	})
}

// TestProtocolAuthPayloads tests authentication message payload serialization.
func TestProtocolAuthPayloads(t *testing.T) {
	t.Log("Testing authentication message payload serialization")

	t.Run("AUTH_CHALLENGE payload", func(t *testing.T) {
		t.Log("Verifying AUTH_CHALLENGE nonce field round-trips correctly")
		original := AuthChallengePayload{
			Nonce: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded AuthChallengePayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Nonce != original.Nonce {
			t.Errorf("Nonce: got %s, want %s", decoded.Nonce, original.Nonce)
		}

		// Verify wire format field name
		var raw map[string]any
		json.Unmarshal(data, &raw)
		if _, ok := raw["nonce"]; !ok {
			t.Error("expected wire field 'nonce'")
		}
	})

	t.Run("AUTH_RESPONSE payload", func(t *testing.T) {
		t.Log("Verifying AUTH_RESPONSE with nonce, signature, and public_key fields")
		original := AuthResponsePayload{
			Nonce:     "a1b2c3d4e5f6",
			Signature: "c2lnbmF0dXJlZGF0YWhlcmU=", // base64
			PublicKey: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAtest\n-----END PUBLIC KEY-----",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded AuthResponsePayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Nonce != original.Nonce {
			t.Errorf("Nonce: got %s, want %s", decoded.Nonce, original.Nonce)
		}
		if decoded.Signature != original.Signature {
			t.Errorf("Signature: got %s, want %s", decoded.Signature, original.Signature)
		}
		if decoded.PublicKey != original.PublicKey {
			t.Errorf("PublicKey: got %s, want %s", decoded.PublicKey, original.PublicKey)
		}

		// Verify wire format field names
		var raw map[string]any
		json.Unmarshal(data, &raw)
		for _, field := range []string{"nonce", "signature", "public_key"} {
			if _, ok := raw[field]; !ok {
				t.Errorf("expected wire field %q", field)
			}
		}
	})

	t.Run("AUTH_RESPONSE with empty public_key (reconnect)", func(t *testing.T) {
		t.Log("Verifying AUTH_RESPONSE allows empty public_key for reconnect case")
		// On reconnect, public_key can be empty
		original := AuthResponsePayload{
			Nonce:     "abc123",
			Signature: "c2ln",
			PublicKey: "",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded AuthResponsePayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.PublicKey != "" {
			t.Errorf("PublicKey should be empty, got %s", decoded.PublicKey)
		}
	})

	t.Run("AUTH_OK payload (empty)", func(t *testing.T) {
		t.Log("Verifying AUTH_OK serializes to empty object {}")
		original := AuthOKPayload{}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded AuthOKPayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		// AUTH_OK has no fields, just verify it serializes to {}
		if string(data) != "{}" {
			t.Errorf("AUTH_OK should serialize to {}, got %s", data)
		}
	})

	t.Run("AUTH_FAIL payload", func(t *testing.T) {
		t.Log("Verifying AUTH_FAIL reason field for all failure codes")
		reasons := []string{
			"invalid_signature",
			"unknown_key",
			"expired_nonce",
		}

		for _, reason := range reasons {
			original := AuthFailPayload{Reason: reason}

			data, err := json.Marshal(original)
			if err != nil {
				t.Fatalf("marshal failed for reason %s: %v", reason, err)
			}

			var decoded AuthFailPayload
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal failed for reason %s: %v", reason, err)
			}

			if decoded.Reason != reason {
				t.Errorf("Reason: got %s, want %s", decoded.Reason, reason)
			}
		}
	})
}

// TestProtocolEnrollPayloads tests enrollment message payload serialization.
func TestProtocolEnrollPayloads(t *testing.T) {
	t.Log("Testing enrollment message payload serialization")
	// Define inline payload types matching expected wire format
	type EnrollRequestPayload struct {
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
		Arch     string `json:"arch,omitempty"`
	}

	type EnrollResponsePayload struct {
		HostID string `json:"host_id"`
		Status string `json:"status"`
	}

	t.Run("ENROLL_REQUEST payload", func(t *testing.T) {
		t.Log("Verifying ENROLL_REQUEST with hostname, os, and arch fields")
		original := EnrollRequestPayload{
			Hostname: "worker-node-01",
			OS:       "linux",
			Arch:     "amd64",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded EnrollRequestPayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Hostname != original.Hostname {
			t.Errorf("Hostname: got %s, want %s", decoded.Hostname, original.Hostname)
		}
		if decoded.OS != original.OS {
			t.Errorf("OS: got %s, want %s", decoded.OS, original.OS)
		}
		if decoded.Arch != original.Arch {
			t.Errorf("Arch: got %s, want %s", decoded.Arch, original.Arch)
		}
	})

	t.Run("ENROLL_RESPONSE payload", func(t *testing.T) {
		t.Log("Verifying ENROLL_RESPONSE with host_id and status fields")
		original := EnrollResponsePayload{
			HostID: "host-550e8400-e29b-41d4",
			Status: "enrolled",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded EnrollResponsePayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.HostID != original.HostID {
			t.Errorf("HostID: got %s, want %s", decoded.HostID, original.HostID)
		}
		if decoded.Status != original.Status {
			t.Errorf("Status: got %s, want %s", decoded.Status, original.Status)
		}
	})

	t.Run("full message with ENROLL_REQUEST", func(t *testing.T) {
		t.Log("Verifying full Message envelope with embedded ENROLL_REQUEST payload")
		payload := EnrollRequestPayload{
			Hostname: "test-host",
			OS:       "linux",
		}
		payloadJSON, _ := json.Marshal(payload)

		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageEnrollRequest,
			ID:      "enroll-123",
			TS:      1737244800000,
			Payload: payloadJSON,
		}

		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		var extractedPayload EnrollRequestPayload
		if err := json.Unmarshal(decoded.Payload, &extractedPayload); err != nil {
			t.Fatalf("payload unmarshal failed: %v", err)
		}

		if extractedPayload.Hostname != payload.Hostname {
			t.Errorf("extracted Hostname: got %s, want %s", extractedPayload.Hostname, payload.Hostname)
		}
	})
}

// TestProtocolPosturePayloads tests posture message payload serialization.
func TestProtocolPosturePayloads(t *testing.T) {
	t.Log("Testing posture message payload serialization")
	type PostureCheck struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Value  any    `json:"value,omitempty"`
	}

	type PostureReportPayload struct {
		Score     int            `json:"posture_score"`
		Timestamp string         `json:"timestamp"`
		Checks    []PostureCheck `json:"checks"`
	}

	type PostureAckPayload struct {
		Received bool   `json:"received"`
		NextPoll int    `json:"next_poll_seconds,omitempty"`
		Message  string `json:"message,omitempty"`
	}

	t.Run("POSTURE_REPORT payload", func(t *testing.T) {
		t.Log("Verifying POSTURE_REPORT with score, timestamp, and checks array")
		original := PostureReportPayload{
			Score:     85,
			Timestamp: "2026-01-17T12:00:00Z",
			Checks: []PostureCheck{
				{Name: "firewall", Status: "pass", Value: true},
				{Name: "antivirus", Status: "pass", Value: "CrowdStrike"},
				{Name: "disk_encryption", Status: "fail", Value: nil},
			},
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded PostureReportPayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Score != original.Score {
			t.Errorf("Score: got %d, want %d", decoded.Score, original.Score)
		}
		if len(decoded.Checks) != len(original.Checks) {
			t.Errorf("Checks count: got %d, want %d", len(decoded.Checks), len(original.Checks))
		}
	})

	t.Run("POSTURE_ACK payload", func(t *testing.T) {
		t.Log("Verifying POSTURE_ACK with received, next_poll_seconds, and message fields")
		original := PostureAckPayload{
			Received: true,
			NextPoll: 300,
			Message:  "posture accepted",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded PostureAckPayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Received != original.Received {
			t.Errorf("Received: got %v, want %v", decoded.Received, original.Received)
		}
		if decoded.NextPoll != original.NextPoll {
			t.Errorf("NextPoll: got %d, want %d", decoded.NextPoll, original.NextPoll)
		}
	})
}

// TestProtocolCredentialPayloads tests credential message payload serialization.
func TestProtocolCredentialPayloads(t *testing.T) {
	t.Log("Testing credential message payload serialization")
	type CredentialPushPayload struct {
		CredentialID   string `json:"credential_id"`
		CredentialType string `json:"credential_type"`
		Data           string `json:"data"` // Base64 encoded
		ExpiresAt      string `json:"expires_at,omitempty"`
	}

	type CredentialAckPayload struct {
		CredentialID string `json:"credential_id"`
		Status       string `json:"status"` // "accepted", "rejected", "error"
		Error        string `json:"error,omitempty"`
	}

	t.Run("CREDENTIAL_PUSH payload", func(t *testing.T) {
		t.Log("Verifying CREDENTIAL_PUSH with credential_id, type, data, and expires_at")
		original := CredentialPushPayload{
			CredentialID:   "cred-123456",
			CredentialType: "x509_cert",
			Data:           "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t", // base64
			ExpiresAt:      "2026-12-31T23:59:59Z",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded CredentialPushPayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.CredentialID != original.CredentialID {
			t.Errorf("CredentialID: got %s, want %s", decoded.CredentialID, original.CredentialID)
		}
		if decoded.Data != original.Data {
			t.Errorf("Data: got %s, want %s", decoded.Data, original.Data)
		}
	})

	t.Run("CREDENTIAL_ACK payload", func(t *testing.T) {
		t.Log("Verifying CREDENTIAL_ACK with credential_id and status fields")
		original := CredentialAckPayload{
			CredentialID: "cred-123456",
			Status:       "accepted",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded CredentialAckPayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.CredentialID != original.CredentialID {
			t.Errorf("CredentialID: got %s, want %s", decoded.CredentialID, original.CredentialID)
		}
		if decoded.Status != original.Status {
			t.Errorf("Status: got %s, want %s", decoded.Status, original.Status)
		}
	})

	t.Run("CREDENTIAL_ACK with error", func(t *testing.T) {
		t.Log("Verifying CREDENTIAL_ACK error field for rejection case")
		original := CredentialAckPayload{
			CredentialID: "cred-789",
			Status:       "error",
			Error:        "storage full",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded CredentialAckPayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Error != original.Error {
			t.Errorf("Error: got %s, want %s", decoded.Error, original.Error)
		}
	})
}

// TestProtocolCertPayloads tests certificate request/response payload serialization.
func TestProtocolCertPayloads(t *testing.T) {
	t.Log("Testing certificate request/response payload serialization")
	type CertRequestPayload struct {
		CSR          string `json:"csr"`           // PEM-encoded CSR
		KeyType      string `json:"key_type"`      // "rsa", "ecdsa", "ed25519"
		ValidityDays int    `json:"validity_days"` // requested validity
	}

	type CertResponsePayload struct {
		Certificate string `json:"certificate"` // PEM-encoded certificate
		Chain       string `json:"chain"`       // PEM-encoded CA chain
		ExpiresAt   string `json:"expires_at"`
	}

	t.Run("CERT_REQUEST payload", func(t *testing.T) {
		t.Log("Verifying CERT_REQUEST with CSR, key_type, and validity_days")
		original := CertRequestPayload{
			CSR:          "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----",
			KeyType:      "ed25519",
			ValidityDays: 365,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded CertRequestPayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.CSR != original.CSR {
			t.Errorf("CSR mismatch")
		}
		if decoded.KeyType != original.KeyType {
			t.Errorf("KeyType: got %s, want %s", decoded.KeyType, original.KeyType)
		}
	})

	t.Run("CERT_RESPONSE payload", func(t *testing.T) {
		t.Log("Verifying CERT_RESPONSE with certificate, chain, and expires_at")
		original := CertResponsePayload{
			Certificate: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
			Chain:       "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
			ExpiresAt:   "2027-01-17T12:00:00Z",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded CertResponsePayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Certificate != original.Certificate {
			t.Errorf("Certificate mismatch")
		}
		if decoded.Chain != original.Chain {
			t.Errorf("Chain mismatch")
		}
	})
}

// TestProtocolEdgeCases tests edge cases and error handling.
func TestProtocolEdgeCases(t *testing.T) {
	t.Log("Testing protocol edge cases and error handling")

	t.Run("malformed JSON in payload", func(t *testing.T) {
		t.Log("Verifying malformed JSON payload causes unmarshal error")
		// Create message with invalid JSON payload
		msgJSON := `{"v":1,"type":"AUTH_CHALLENGE","id":"test","ts":123,"payload":{invalid}}`

		var msg Message
		err := json.Unmarshal([]byte(msgJSON), &msg)
		if err == nil {
			t.Error("expected error for malformed JSON payload")
		}
	})

	t.Run("missing required envelope fields", func(t *testing.T) {
		t.Log("Verifying missing envelope fields result in zero values, not errors")
		// Missing fields should result in zero values, not errors
		// JSON unmarshal doesn't enforce required fields
		msgJSON := `{"type":"AUTH_CHALLENGE"}`

		var msg Message
		if err := json.Unmarshal([]byte(msgJSON), &msg); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if msg.Version != 0 {
			t.Errorf("expected Version zero value, got %d", msg.Version)
		}
		if msg.ID != "" {
			t.Errorf("expected ID zero value, got %s", msg.ID)
		}
		if msg.TS != 0 {
			t.Errorf("expected TS zero value, got %d", msg.TS)
		}
	})

	t.Run("extra unknown fields ignored", func(t *testing.T) {
		t.Log("Verifying extra unknown fields are silently ignored")
		// Extra fields should be silently ignored
		msgJSON := `{
			"v": 1,
			"type": "AUTH_OK",
			"id": "test-id",
			"ts": 1737244800000,
			"payload": {},
			"unknown_field": "should be ignored",
			"another_unknown": 42
		}`

		var msg Message
		if err := json.Unmarshal([]byte(msgJSON), &msg); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if msg.Type != MessageAuthOK {
			t.Errorf("Type: got %s, want %s", msg.Type, MessageAuthOK)
		}
	})

	t.Run("extra fields in payload ignored", func(t *testing.T) {
		t.Log("Verifying extra fields in payload are silently ignored")
		payloadJSON := `{
			"nonce": "abc123",
			"extra_field": "ignored",
			"nested": {"also": "ignored"}
		}`

		var payload AuthChallengePayload
		if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if payload.Nonce != "abc123" {
			t.Errorf("Nonce: got %s, want abc123", payload.Nonce)
		}
	})

	t.Run("unicode in string fields", func(t *testing.T) {
		t.Log("Verifying unicode characters in string fields are preserved")
		type TestPayload struct {
			Name    string `json:"name"`
			Message string `json:"message"`
		}

		original := TestPayload{
			Name:    "test-host-jp",
			Message: "Status: OK",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded TestPayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Name != original.Name {
			t.Errorf("Name: got %s, want %s", decoded.Name, original.Name)
		}
		if decoded.Message != original.Message {
			t.Errorf("Message: got %s, want %s", decoded.Message, original.Message)
		}
	})

	t.Run("special characters in nonce", func(t *testing.T) {
		t.Log("Verifying hex nonce with mixed case is preserved")
		// Nonce is hex, but test that encoding handles any string
		payload := AuthChallengePayload{
			Nonce: "abcdef0123456789ABCDEF",
		}

		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded AuthChallengePayload
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.Nonce != payload.Nonce {
			t.Errorf("Nonce: got %s, want %s", decoded.Nonce, payload.Nonce)
		}
	})

	t.Run("zero timestamp", func(t *testing.T) {
		t.Log("Verifying zero timestamp value is preserved")
		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthChallenge,
			ID:      "test",
			TS:      0,
			Payload: json.RawMessage(`{}`),
		}

		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.TS != 0 {
			t.Errorf("TS: got %d, want 0", decoded.TS)
		}
	})

	t.Run("negative timestamp", func(t *testing.T) {
		t.Log("Verifying negative timestamp (pre-epoch) serializes correctly")
		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthChallenge,
			ID:      "test",
			TS:      -1000,
			Payload: json.RawMessage(`{}`),
		}

		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.TS != -1000 {
			t.Errorf("TS: got %d, want -1000", decoded.TS)
		}
	})

	t.Run("empty string ID", func(t *testing.T) {
		t.Log("Verifying empty string ID is preserved")
		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthChallenge,
			ID:      "",
			TS:      1737244800000,
			Payload: json.RawMessage(`{}`),
		}

		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.ID != "" {
			t.Errorf("ID: got %s, want empty", decoded.ID)
		}
	})

	t.Run("max int64 timestamp", func(t *testing.T) {
		t.Log("Verifying max int64 timestamp serializes without overflow")
		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthChallenge,
			ID:      "test",
			TS:      9223372036854775807, // max int64
			Payload: json.RawMessage(`{}`),
		}

		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.TS != 9223372036854775807 {
			t.Errorf("TS: got %d, want max int64", decoded.TS)
		}
	})
}

// TestProtocolAllMessageTypes verifies all defined message types serialize correctly.
func TestProtocolAllMessageTypes(t *testing.T) {
	t.Log("Testing that all defined message types serialize correctly")
	messageTypes := []MessageType{
		MessageAuthChallenge,
		MessageAuthResponse,
		MessageAuthOK,
		MessageAuthFail,
		MessageEnrollRequest,
		MessageEnrollResponse,
		MessagePostureReport,
		MessagePostureAck,
		MessageCredentialPush,
		MessageCredentialAck,
		MessageCertRequest,
		MessageCertResponse,
	}

	for _, msgType := range messageTypes {
		t.Run(string(msgType), func(t *testing.T) {
			t.Logf("Verifying %s message type round-trips correctly", msgType)
			msg := &Message{
				Version: ProtocolVersion,
				Type:    msgType,
				ID:      "test-" + string(msgType),
				TS:      1737244800000,
				Payload: json.RawMessage(`{"test": "data"}`),
			}

			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("marshal failed for %s: %v", msgType, err)
			}

			var decoded Message
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal failed for %s: %v", msgType, err)
			}

			if decoded.Type != msgType {
				t.Errorf("Type: got %s, want %s", decoded.Type, msgType)
			}
		})
	}
}

// TestProtocolNewAuthMessageIntegration tests NewAuthMessage creates valid serializable messages.
func TestProtocolNewAuthMessageIntegration(t *testing.T) {
	t.Log("Testing NewAuthMessage creates valid serializable messages")
	testCases := []struct {
		name     string
		msgType  MessageType
		payload  any
		verifyFn func(t *testing.T, msg *Message)
	}{
		{
			name:    "AUTH_CHALLENGE",
			msgType: MessageAuthChallenge,
			payload: AuthChallengePayload{Nonce: GenerateNonce()},
			verifyFn: func(t *testing.T, msg *Message) {
				var p AuthChallengePayload
				if err := json.Unmarshal(msg.Payload, &p); err != nil {
					t.Errorf("payload unmarshal failed: %v", err)
				}
				if len(p.Nonce) != 64 {
					t.Errorf("nonce length: got %d, want 64", len(p.Nonce))
				}
			},
		},
		{
			name:    "AUTH_RESPONSE",
			msgType: MessageAuthResponse,
			payload: AuthResponsePayload{
				Nonce:     "abc123",
				Signature: "sig==",
				PublicKey: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
			},
			verifyFn: func(t *testing.T, msg *Message) {
				var p AuthResponsePayload
				if err := json.Unmarshal(msg.Payload, &p); err != nil {
					t.Errorf("payload unmarshal failed: %v", err)
				}
				if p.Nonce != "abc123" {
					t.Errorf("nonce: got %s, want abc123", p.Nonce)
				}
			},
		},
		{
			name:    "AUTH_OK",
			msgType: MessageAuthOK,
			payload: AuthOKPayload{},
			verifyFn: func(t *testing.T, msg *Message) {
				if string(msg.Payload) != "{}" {
					t.Errorf("AUTH_OK payload: got %s, want {}", msg.Payload)
				}
			},
		},
		{
			name:    "AUTH_FAIL",
			msgType: MessageAuthFail,
			payload: AuthFailPayload{Reason: "invalid_signature"},
			verifyFn: func(t *testing.T, msg *Message) {
				var p AuthFailPayload
				if err := json.Unmarshal(msg.Payload, &p); err != nil {
					t.Errorf("payload unmarshal failed: %v", err)
				}
				if p.Reason != "invalid_signature" {
					t.Errorf("reason: got %s, want invalid_signature", p.Reason)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Verifying NewAuthMessage creates valid %s with correct envelope and payload", tc.name)
			msg, err := NewAuthMessage(tc.msgType, tc.payload)
			if err != nil {
				t.Fatalf("NewAuthMessage failed: %v", err)
			}

			// Verify basic envelope
			if msg.Version != ProtocolVersion {
				t.Errorf("Version: got %d, want %d", msg.Version, ProtocolVersion)
			}
			if msg.Type != tc.msgType {
				t.Errorf("Type: got %s, want %s", msg.Type, tc.msgType)
			}
			if msg.ID == "" {
				t.Error("ID should not be empty")
			}
			if msg.TS == 0 {
				t.Error("TS should not be zero")
			}

			// Verify serialization round-trip
			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var decoded Message
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			// Run type-specific verification
			tc.verifyFn(t, &decoded)
		})
	}
}

// TestProtocolParseAuthPayloadIntegration tests ParseAuthPayload with various inputs.
func TestProtocolParseAuthPayloadIntegration(t *testing.T) {
	t.Log("Testing ParseAuthPayload with various inputs")

	t.Run("parses all auth payload types", func(t *testing.T) {
		t.Log("Verifying ParseAuthPayload correctly extracts all auth payload types")
		// AUTH_CHALLENGE
		challengeMsg, _ := NewAuthMessage(MessageAuthChallenge, AuthChallengePayload{Nonce: "test123"})
		challenge, err := ParseAuthPayload[AuthChallengePayload](challengeMsg)
		if err != nil {
			t.Errorf("parse challenge failed: %v", err)
		}
		if challenge.Nonce != "test123" {
			t.Errorf("challenge nonce: got %s, want test123", challenge.Nonce)
		}

		// AUTH_RESPONSE
		responseMsg, _ := NewAuthMessage(MessageAuthResponse, AuthResponsePayload{
			Nonce:     "test123",
			Signature: "sig",
			PublicKey: "key",
		})
		response, err := ParseAuthPayload[AuthResponsePayload](responseMsg)
		if err != nil {
			t.Errorf("parse response failed: %v", err)
		}
		if response.Nonce != "test123" {
			t.Errorf("response nonce: got %s, want test123", response.Nonce)
		}

		// AUTH_OK
		okMsg, _ := NewAuthMessage(MessageAuthOK, AuthOKPayload{})
		_, err = ParseAuthPayload[AuthOKPayload](okMsg)
		if err != nil {
			t.Errorf("parse ok failed: %v", err)
		}

		// AUTH_FAIL
		failMsg, _ := NewAuthMessage(MessageAuthFail, AuthFailPayload{Reason: "test"})
		fail, err := ParseAuthPayload[AuthFailPayload](failMsg)
		if err != nil {
			t.Errorf("parse fail failed: %v", err)
		}
		if fail.Reason != "test" {
			t.Errorf("fail reason: got %s, want test", fail.Reason)
		}
	})

	t.Run("returns error for nil message", func(t *testing.T) {
		t.Log("Verifying ParseAuthPayload returns error for nil message")
		_, err := ParseAuthPayload[AuthChallengePayload](nil)
		if err == nil {
			t.Error("expected error for nil message")
		}
	})

	t.Run("returns error for invalid payload JSON", func(t *testing.T) {
		t.Log("Verifying ParseAuthPayload returns error for invalid JSON payload")
		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthChallenge,
			ID:      "test",
			TS:      1737244800000,
			Payload: json.RawMessage(`{not valid json`),
		}

		_, err := ParseAuthPayload[AuthChallengePayload](msg)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("handles type mismatch gracefully", func(t *testing.T) {
		t.Log("Verifying ParseAuthPayload handles type mismatch gracefully (lenient JSON)")
		// Create AUTH_FAIL message but try to parse as AUTH_CHALLENGE
		// This should work since JSON unmarshaling is lenient
		failMsg, _ := NewAuthMessage(MessageAuthFail, AuthFailPayload{Reason: "test"})

		challenge, err := ParseAuthPayload[AuthChallengePayload](failMsg)
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}

		// Nonce will be empty since it wasn't in the payload
		if challenge.Nonce != "" {
			t.Errorf("expected empty nonce, got %s", challenge.Nonce)
		}
	})
}

// TestProtocolVersionValidation tests protocol version handling.
func TestProtocolVersionValidation(t *testing.T) {
	t.Log("Testing protocol version handling")

	t.Run("current protocol version is 1", func(t *testing.T) {
		t.Log("Verifying current ProtocolVersion constant is 1")
		if ProtocolVersion != 1 {
			t.Errorf("ProtocolVersion: got %d, want 1", ProtocolVersion)
		}
	})

	t.Run("version 0 serializes correctly", func(t *testing.T) {
		t.Log("Verifying version 0 serializes correctly")
		msg := &Message{
			Version: 0,
			Type:    MessageAuthChallenge,
			ID:      "test",
			TS:      1737244800000,
			Payload: json.RawMessage(`{}`),
		}

		data, _ := json.Marshal(msg)
		var decoded Message
		json.Unmarshal(data, &decoded)

		if decoded.Version != 0 {
			t.Errorf("Version: got %d, want 0", decoded.Version)
		}
	})

	t.Run("version 255 (max uint8) serializes correctly", func(t *testing.T) {
		t.Log("Verifying version 255 (max uint8) serializes correctly")
		msg := &Message{
			Version: 255,
			Type:    MessageAuthChallenge,
			ID:      "test",
			TS:      1737244800000,
			Payload: json.RawMessage(`{}`),
		}

		data, _ := json.Marshal(msg)
		var decoded Message
		json.Unmarshal(data, &decoded)

		if decoded.Version != 255 {
			t.Errorf("Version: got %d, want 255", decoded.Version)
		}
	})
}
