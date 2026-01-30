package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewAuthClient(t *testing.T) {
	transport := NewMockTransport()
	keyPath := "/tmp/test-key.pem"

	client := NewAuthClient(transport, keyPath)

	if client == nil {
		t.Fatal("NewAuthClient returned nil")
	}
	if client.transport != transport {
		t.Error("transport not set correctly")
	}
	if client.keyPath != keyPath {
		t.Errorf("keyPath = %q, want %q", client.keyPath, keyPath)
	}
}

func TestAuthClient_LoadOrGenerateKey_GeneratesNewKey(t *testing.T) {
	// Use temp directory for test
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "subdir", "test-key.pem")

	transport := NewMockTransport()
	client := NewAuthClient(transport, keyPath)

	// Key should not exist yet
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("key file should not exist before LoadOrGenerateKey")
	}

	// Generate key
	err := client.LoadOrGenerateKey()
	if err != nil {
		t.Fatalf("LoadOrGenerateKey() error = %v", err)
	}

	// Verify key was generated
	if client.privateKey == nil {
		t.Error("privateKey should be set after generation")
	}
	if client.publicKey == nil {
		t.Error("publicKey should be set after generation")
	}

	// Verify key file was created with correct permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	// Windows Mode().Perm() returns 0666 regardless of ACLs
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Errorf("key file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Verify the file contains valid PEM
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("key file does not contain valid PEM")
	}
}

func TestAuthClient_LoadOrGenerateKey_LoadsExistingKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "existing-key.pem")

	// Generate a keypair first
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Save keypair to file
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priv.Seed(),
	})
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	// Load the key
	transport := NewMockTransport()
	client := NewAuthClient(transport, keyPath)

	err = client.LoadOrGenerateKey()
	if err != nil {
		t.Fatalf("LoadOrGenerateKey() error = %v", err)
	}

	// Verify loaded key matches original
	if !client.privateKey.Equal(priv) {
		t.Error("loaded privateKey does not match original")
	}
	if !client.publicKey.Equal(pub) {
		t.Error("loaded publicKey does not match original")
	}
}

func TestAuthClient_PublicKeyPEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")

	transport := NewMockTransport()
	client := NewAuthClient(transport, keyPath)

	if err := client.LoadOrGenerateKey(); err != nil {
		t.Fatalf("LoadOrGenerateKey() error = %v", err)
	}

	pemStr := client.PublicKeyPEM()
	if pemStr == "" {
		t.Fatal("PublicKeyPEM() returned empty string")
	}

	// Verify it's valid PEM
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("PublicKeyPEM() did not return valid PEM")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want %q", block.Type, "PUBLIC KEY")
	}
}

func TestAuthClient_Authenticate_Success(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")

	transport := NewMockTransport()
	client := NewAuthClient(transport, keyPath)

	if err := client.LoadOrGenerateKey(); err != nil {
		t.Fatalf("LoadOrGenerateKey() error = %v", err)
	}

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	// Generate a nonce for the challenge
	nonce := GenerateNonce()

	// Simulate DPU sending AUTH_CHALLENGE
	challengePayload, _ := json.Marshal(AuthChallengePayload{Nonce: nonce})
	challengeMsg := &Message{
		Version: ProtocolVersion,
		Type:    MessageAuthChallenge,
		ID:      "challenge-id",
		TS:      1234567890,
		Payload: challengePayload,
	}
	if err := transport.Enqueue(challengeMsg); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	// Simulate DPU sending AUTH_OK after receiving response
	authOKPayload, _ := json.Marshal(AuthOKPayload{})
	authOKMsg := &Message{
		Version: ProtocolVersion,
		Type:    MessageAuthOK,
		ID:      "ok-id",
		TS:      1234567891,
		Payload: authOKPayload,
	}
	if err := transport.Enqueue(authOKMsg); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	// Run authentication
	err := client.Authenticate(ctx)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	// Verify AUTH_RESPONSE was sent
	sent := transport.SentMessages()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}

	if sent[0].Type != MessageAuthResponse {
		t.Errorf("sent message type = %s, want %s", sent[0].Type, MessageAuthResponse)
	}

	// Verify the response payload
	var responsePayload AuthResponsePayload
	if err := json.Unmarshal(sent[0].Payload, &responsePayload); err != nil {
		t.Fatalf("failed to parse response payload: %v", err)
	}

	if responsePayload.Nonce != nonce {
		t.Errorf("response nonce = %q, want %q", responsePayload.Nonce, nonce)
	}

	if responsePayload.PublicKey == "" {
		t.Error("response should include public key")
	}

	// Verify signature is valid
	sigBytes, err := base64.StdEncoding.DecodeString(responsePayload.Signature)
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil {
		t.Fatalf("failed to decode nonce: %v", err)
	}

	if !ed25519.Verify(client.publicKey, nonceBytes, sigBytes) {
		t.Error("signature verification failed")
	}
}

func TestAuthClient_Authenticate_AuthFail(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")

	transport := NewMockTransport()
	client := NewAuthClient(transport, keyPath)

	if err := client.LoadOrGenerateKey(); err != nil {
		t.Fatalf("LoadOrGenerateKey() error = %v", err)
	}

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	// Simulate DPU sending AUTH_CHALLENGE
	nonce := GenerateNonce()
	challengePayload, _ := json.Marshal(AuthChallengePayload{Nonce: nonce})
	challengeMsg := &Message{
		Version: ProtocolVersion,
		Type:    MessageAuthChallenge,
		ID:      "challenge-id",
		TS:      1234567890,
		Payload: challengePayload,
	}
	if err := transport.Enqueue(challengeMsg); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	// Simulate DPU sending AUTH_FAIL
	authFailPayload, _ := json.Marshal(AuthFailPayload{Reason: "unknown_key"})
	authFailMsg := &Message{
		Version: ProtocolVersion,
		Type:    MessageAuthFail,
		ID:      "fail-id",
		TS:      1234567891,
		Payload: authFailPayload,
	}
	if err := transport.Enqueue(authFailMsg); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	// Run authentication
	err := client.Authenticate(ctx)
	if err == nil {
		t.Fatal("Authenticate() should have returned error for AUTH_FAIL")
	}

	// Verify error contains the reason
	if err.Error() != "authentication failed: unknown_key" {
		t.Errorf("error = %q, want %q", err.Error(), "authentication failed: unknown_key")
	}
}

func TestAuthClient_Authenticate_UnexpectedMessage(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")

	transport := NewMockTransport()
	client := NewAuthClient(transport, keyPath)

	if err := client.LoadOrGenerateKey(); err != nil {
		t.Fatalf("LoadOrGenerateKey() error = %v", err)
	}

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	// Simulate DPU sending unexpected message instead of AUTH_CHALLENGE
	unexpectedPayload, _ := json.Marshal(map[string]string{"foo": "bar"})
	unexpectedMsg := &Message{
		Version: ProtocolVersion,
		Type:    MessageEnrollResponse,
		ID:      "unexpected-id",
		TS:      1234567890,
		Payload: unexpectedPayload,
	}
	if err := transport.Enqueue(unexpectedMsg); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	// Run authentication
	err := client.Authenticate(ctx)
	if err == nil {
		t.Fatal("Authenticate() should have returned error for unexpected message")
	}
}

func TestAuthClient_Authenticate_WithoutKey(t *testing.T) {
	transport := NewMockTransport()
	client := NewAuthClient(transport, "/nonexistent/path")

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	// Simulate DPU sending AUTH_CHALLENGE
	nonce := GenerateNonce()
	challengePayload, _ := json.Marshal(AuthChallengePayload{Nonce: nonce})
	challengeMsg := &Message{
		Version: ProtocolVersion,
		Type:    MessageAuthChallenge,
		ID:      "challenge-id",
		TS:      1234567890,
		Payload: challengePayload,
	}
	if err := transport.Enqueue(challengeMsg); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	// Run authentication without loading key first
	err := client.Authenticate(ctx)
	if err == nil {
		t.Fatal("Authenticate() should have returned error when key not loaded")
	}
}

func TestAuthClient_DirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a deeply nested path
	keyPath := filepath.Join(tmpDir, "a", "b", "c", "key.pem")

	transport := NewMockTransport()
	client := NewAuthClient(transport, keyPath)

	err := client.LoadOrGenerateKey()
	if err != nil {
		t.Fatalf("LoadOrGenerateKey() error = %v", err)
	}

	// Verify directory was created
	dirPath := filepath.Dir(keyPath)
	info, err := os.Stat(dirPath)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
	// Check directory permissions (0755) - Windows Mode().Perm() returns 0777
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0755 {
		t.Errorf("directory permissions = %o, want 0755", info.Mode().Perm())
	}
}
