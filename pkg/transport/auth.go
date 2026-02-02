package transport

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ConnectionState represents the authentication state of a transport connection.
type ConnectionState int

const (
	// StateConnected indicates transport is connected but not yet authenticated.
	StateConnected ConnectionState = iota

	// StateAuthenticated indicates authentication is complete.
	StateAuthenticated

	// StateEnrolled indicates the host is enrolled with the DPU.
	StateEnrolled
)

// String returns a human-readable representation of the connection state.
func (s ConnectionState) String() string {
	switch s {
	case StateConnected:
		return "Connected"
	case StateAuthenticated:
		return "Authenticated"
	case StateEnrolled:
		return "Enrolled"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// AuthChallengePayload is sent by DPU immediately on connection.
type AuthChallengePayload struct {
	Nonce string `json:"nonce"` // Random 32-byte hex string
}

// AuthResponsePayload is sent by host to prove identity.
type AuthResponsePayload struct {
	Nonce     string `json:"nonce"`      // Echo of challenge nonce
	Signature string `json:"signature"`  // Base64 Ed25519 signature of nonce
	PublicKey string `json:"public_key"` // PEM-encoded public key (first connection only, empty on reconnect)
}

// AuthOKPayload indicates successful authentication.
type AuthOKPayload struct{}

// AuthFailPayload indicates authentication failure.
type AuthFailPayload struct {
	Reason string `json:"reason"` // "invalid_signature", "unknown_key", "expired_nonce"
}

// GenerateNonce generates a cryptographically secure 32-byte random value as a hex string.
func GenerateNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// ParseAuthPayload parses the payload from a Message into the specified type.
func ParseAuthPayload[T any](msg *Message) (*T, error) {
	if msg == nil {
		return nil, errors.New("message is nil")
	}

	var payload T
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse auth payload: %w", err)
	}
	return &payload, nil
}

// NewAuthMessage creates a new authentication message with the given type and payload.
// It generates a unique correlation ID and sets the current timestamp.
func NewAuthMessage(msgType MessageType, payload interface{}) (*Message, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth payload: %w", err)
	}

	return &Message{
		Version: ProtocolVersion,
		Type:    msgType,
		ID:      uuid.New().String(),
		TS:      time.Now().UnixMilli(),
		Payload: payloadJSON,
	}, nil
}
