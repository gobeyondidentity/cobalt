package transport

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestGenerateNonce(t *testing.T) {
	t.Log("Testing GenerateNonce produces cryptographically secure random values")

	t.Run("produces valid hex string", func(t *testing.T) {
		t.Log("Verifying nonce is valid 64-character hex string (32 bytes)")
		nonce := GenerateNonce()

		// Should be valid hex
		decoded, err := hex.DecodeString(nonce)
		if err != nil {
			t.Errorf("GenerateNonce() produced invalid hex: %v", err)
		}

		// Should be 32 bytes (64 hex chars)
		if len(decoded) != 32 {
			t.Errorf("GenerateNonce() produced %d bytes, want 32", len(decoded))
		}
		if len(nonce) != 64 {
			t.Errorf("GenerateNonce() produced %d hex chars, want 64", len(nonce))
		}
	})

	t.Run("produces different values each call", func(t *testing.T) {
		t.Log("Verifying 100 consecutive nonces are all unique")
		seen := make(map[string]bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			nonce := GenerateNonce()
			if seen[nonce] {
				t.Errorf("GenerateNonce() produced duplicate nonce on iteration %d", i)
			}
			seen[nonce] = true
		}
	})
}

func TestParseAuthPayload(t *testing.T) {
	t.Log("Testing ParseAuthPayload extracts typed payloads from Messages")

	t.Run("parses AuthChallengePayload", func(t *testing.T) {
		t.Log("Verifying AuthChallengePayload extraction preserves nonce")
		payload := AuthChallengePayload{Nonce: "abc123def456"}
		payloadJSON, _ := json.Marshal(payload)

		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthChallenge,
			ID:      "test-id",
			TS:      1234567890,
			Payload: payloadJSON,
		}

		result, err := ParseAuthPayload[AuthChallengePayload](msg)
		if err != nil {
			t.Errorf("ParseAuthPayload() error = %v", err)
			return
		}

		if result.Nonce != payload.Nonce {
			t.Errorf("ParseAuthPayload() nonce = %v, want %v", result.Nonce, payload.Nonce)
		}
	})

	t.Run("parses AuthResponsePayload", func(t *testing.T) {
		t.Log("Verifying AuthResponsePayload extraction preserves nonce, signature, and public_key")
		payload := AuthResponsePayload{
			Nonce:     "abc123def456",
			Signature: "c2lnbmF0dXJl",
			PublicKey: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
		}
		payloadJSON, _ := json.Marshal(payload)

		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthResponse,
			ID:      "test-id",
			TS:      1234567890,
			Payload: payloadJSON,
		}

		result, err := ParseAuthPayload[AuthResponsePayload](msg)
		if err != nil {
			t.Errorf("ParseAuthPayload() error = %v", err)
			return
		}

		if result.Nonce != payload.Nonce {
			t.Errorf("ParseAuthPayload() nonce = %v, want %v", result.Nonce, payload.Nonce)
		}
		if result.Signature != payload.Signature {
			t.Errorf("ParseAuthPayload() signature = %v, want %v", result.Signature, payload.Signature)
		}
		if result.PublicKey != payload.PublicKey {
			t.Errorf("ParseAuthPayload() public_key = %v, want %v", result.PublicKey, payload.PublicKey)
		}
	})

	t.Run("parses AuthOKPayload", func(t *testing.T) {
		t.Log("Verifying AuthOKPayload extraction succeeds for empty payload")
		payload := AuthOKPayload{}
		payloadJSON, _ := json.Marshal(payload)

		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthOK,
			ID:      "test-id",
			TS:      1234567890,
			Payload: payloadJSON,
		}

		_, err := ParseAuthPayload[AuthOKPayload](msg)
		if err != nil {
			t.Errorf("ParseAuthPayload() error = %v", err)
		}
	})

	t.Run("parses AuthFailPayload", func(t *testing.T) {
		t.Log("Verifying AuthFailPayload extraction preserves failure reason")
		payload := AuthFailPayload{Reason: "invalid_signature"}
		payloadJSON, _ := json.Marshal(payload)

		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthFail,
			ID:      "test-id",
			TS:      1234567890,
			Payload: payloadJSON,
		}

		result, err := ParseAuthPayload[AuthFailPayload](msg)
		if err != nil {
			t.Errorf("ParseAuthPayload() error = %v", err)
			return
		}

		if result.Reason != payload.Reason {
			t.Errorf("ParseAuthPayload() reason = %v, want %v", result.Reason, payload.Reason)
		}
	})

	t.Run("returns error for nil message", func(t *testing.T) {
		t.Log("Verifying ParseAuthPayload returns error for nil message")
		_, err := ParseAuthPayload[AuthChallengePayload](nil)
		if err == nil {
			t.Error("ParseAuthPayload() expected error for nil message")
		}
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		t.Log("Verifying ParseAuthPayload returns error for malformed JSON payload")
		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessageAuthChallenge,
			ID:      "test-id",
			TS:      1234567890,
			Payload: json.RawMessage(`{invalid json`),
		}

		_, err := ParseAuthPayload[AuthChallengePayload](msg)
		if err == nil {
			t.Error("ParseAuthPayload() expected error for invalid JSON")
		}
	})
}

func TestNewAuthMessage(t *testing.T) {
	t.Log("Testing NewAuthMessage creates properly formatted auth protocol messages")

	t.Run("creates AUTH_CHALLENGE message", func(t *testing.T) {
		t.Log("Verifying AUTH_CHALLENGE has correct envelope fields and serialized payload")
		payload := AuthChallengePayload{Nonce: "abc123"}

		msg, err := NewAuthMessage(MessageAuthChallenge, payload)
		if err != nil {
			t.Errorf("NewAuthMessage() error = %v", err)
			return
		}

		if msg.Version != ProtocolVersion {
			t.Errorf("NewAuthMessage() version = %v, want %v", msg.Version, ProtocolVersion)
		}
		if msg.Type != MessageAuthChallenge {
			t.Errorf("NewAuthMessage() type = %v, want %v", msg.Type, MessageAuthChallenge)
		}
		if msg.ID == "" {
			t.Error("NewAuthMessage() should generate correlation ID")
		}
		if msg.TS == 0 {
			t.Error("NewAuthMessage() should set timestamp")
		}

		// Verify payload is correctly serialized
		var parsed AuthChallengePayload
		if err := json.Unmarshal(msg.Payload, &parsed); err != nil {
			t.Errorf("NewAuthMessage() payload not valid JSON: %v", err)
		}
		if parsed.Nonce != payload.Nonce {
			t.Errorf("NewAuthMessage() payload nonce = %v, want %v", parsed.Nonce, payload.Nonce)
		}
	})

	t.Run("creates AUTH_RESPONSE message", func(t *testing.T) {
		t.Log("Verifying AUTH_RESPONSE message creation with nonce, signature, and public_key")
		payload := AuthResponsePayload{
			Nonce:     "abc123",
			Signature: "sig",
			PublicKey: "pubkey",
		}

		msg, err := NewAuthMessage(MessageAuthResponse, payload)
		if err != nil {
			t.Errorf("NewAuthMessage() error = %v", err)
			return
		}

		if msg.Type != MessageAuthResponse {
			t.Errorf("NewAuthMessage() type = %v, want %v", msg.Type, MessageAuthResponse)
		}
	})

	t.Run("creates AUTH_OK message", func(t *testing.T) {
		t.Log("Verifying AUTH_OK message creation with empty payload")
		payload := AuthOKPayload{}

		msg, err := NewAuthMessage(MessageAuthOK, payload)
		if err != nil {
			t.Errorf("NewAuthMessage() error = %v", err)
			return
		}

		if msg.Type != MessageAuthOK {
			t.Errorf("NewAuthMessage() type = %v, want %v", msg.Type, MessageAuthOK)
		}
	})

	t.Run("creates AUTH_FAIL message", func(t *testing.T) {
		t.Log("Verifying AUTH_FAIL message creation with failure reason")
		payload := AuthFailPayload{Reason: "expired_nonce"}

		msg, err := NewAuthMessage(MessageAuthFail, payload)
		if err != nil {
			t.Errorf("NewAuthMessage() error = %v", err)
			return
		}

		if msg.Type != MessageAuthFail {
			t.Errorf("NewAuthMessage() type = %v, want %v", msg.Type, MessageAuthFail)
		}
	})

	t.Run("generates unique correlation IDs", func(t *testing.T) {
		t.Log("Verifying 100 consecutive messages have unique correlation IDs")
		payload := AuthChallengePayload{Nonce: "test"}
		seen := make(map[string]bool)

		for i := 0; i < 100; i++ {
			msg, err := NewAuthMessage(MessageAuthChallenge, payload)
			if err != nil {
				t.Errorf("NewAuthMessage() error = %v", err)
				continue
			}

			if seen[msg.ID] {
				t.Errorf("NewAuthMessage() produced duplicate ID on iteration %d", i)
			}
			seen[msg.ID] = true
		}
	})
}

func TestNewAuthMessage_MarshalError(t *testing.T) {
	t.Log("Testing NewAuthMessage returns error for un-marshalable payload")
	// channels cannot be marshaled to JSON
	badPayload := make(chan int)
	_, err := NewAuthMessage(MessageAuthChallenge, badPayload)
	if err == nil {
		t.Error("NewAuthMessage() expected error for un-marshalable payload")
	}
}

func TestConnectionState(t *testing.T) {
	t.Log("Testing ConnectionState enum values and string representations")

	t.Run("states have correct values", func(t *testing.T) {
		t.Log("Verifying ConnectionState constants have expected integer values")
		if StateConnected != 0 {
			t.Errorf("StateConnected = %d, want 0", StateConnected)
		}
		if StateAuthenticated != 1 {
			t.Errorf("StateAuthenticated = %d, want 1", StateAuthenticated)
		}
		if StateEnrolled != 2 {
			t.Errorf("StateEnrolled = %d, want 2", StateEnrolled)
		}
	})

	t.Run("String() returns readable names", func(t *testing.T) {
		t.Log("Verifying ConnectionState.String() returns human-readable names")
		tests := []struct {
			state ConnectionState
			want  string
		}{
			{StateConnected, "Connected"},
			{StateAuthenticated, "Authenticated"},
			{StateEnrolled, "Enrolled"},
			{ConnectionState(99), "Unknown(99)"},
		}

		for _, tt := range tests {
			got := tt.state.String()
			if got != tt.want {
				t.Errorf("ConnectionState(%d).String() = %v, want %v", tt.state, got, tt.want)
			}
		}
	})
}
