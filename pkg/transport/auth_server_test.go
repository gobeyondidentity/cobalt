package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewAuthServer(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	server := NewAuthServer(ks, 10)
	if server == nil {
		t.Fatal("NewAuthServer() returned nil")
	}
	if server.keyStore != ks {
		t.Error("keyStore not set correctly")
	}
	if server.maxConns != 10 {
		t.Errorf("maxConns = %d, want 10", server.maxConns)
	}
}

func TestAuthServer_Authenticate_TOFU(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	server := NewAuthServer(ks, 10)
	transport := NewMockTransport()

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	// Generate a client keypair
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Run server auth in goroutine
	var authErr error
	var returnedPub ed25519.PublicKey
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		returnedPub, authErr = server.Authenticate(ctx, transport)
	}()

	// Receive the AUTH_CHALLENGE
	challengeMsg, err := transport.Dequeue()
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}
	if challengeMsg.Type != MessageAuthChallenge {
		t.Fatalf("expected AUTH_CHALLENGE, got %s", challengeMsg.Type)
	}

	var challenge AuthChallengePayload
	if err := json.Unmarshal(challengeMsg.Payload, &challenge); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Sign the nonce
	nonceBytes, _ := hex.DecodeString(challenge.Nonce)
	signature := ed25519.Sign(clientPriv, nonceBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Build AUTH_RESPONSE with public key (TOFU case)
	pubKeyPEM := publicKeyToPEM(clientPub)
	responsePayload := AuthResponsePayload{
		Nonce:     challenge.Nonce,
		Signature: signatureB64,
		PublicKey: pubKeyPEM,
	}
	responseMsg, _ := NewAuthMessage(MessageAuthResponse, responsePayload)
	if err := transport.Enqueue(responseMsg); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	// Wait for AUTH_OK
	resultMsg, err := transport.Dequeue()
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}
	if resultMsg.Type != MessageAuthOK {
		t.Errorf("expected AUTH_OK, got %s", resultMsg.Type)
	}

	wg.Wait()

	if authErr != nil {
		t.Fatalf("Authenticate() error = %v", authErr)
	}

	// Verify returned public key matches
	if !returnedPub.Equal(clientPub) {
		t.Error("returned public key does not match client key")
	}

	// Verify key was registered (TOFU)
	if !ks.IsKnown(clientPub) {
		t.Error("client key should be registered after TOFU")
	}
}

func TestAuthServer_Authenticate_KnownKey(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	// Pre-register a client key
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := ks.Register(clientPub); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	server := NewAuthServer(ks, 10)
	transport := NewMockTransport()

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	var authErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, authErr = server.Authenticate(ctx, transport)
	}()

	// Receive the AUTH_CHALLENGE
	challengeMsg, _ := transport.Dequeue()
	var challenge AuthChallengePayload
	json.Unmarshal(challengeMsg.Payload, &challenge)

	// Sign the nonce
	nonceBytes, _ := hex.DecodeString(challenge.Nonce)
	signature := ed25519.Sign(clientPriv, nonceBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Build AUTH_RESPONSE with public key (known key case)
	pubKeyPEM := publicKeyToPEM(clientPub)
	responsePayload := AuthResponsePayload{
		Nonce:     challenge.Nonce,
		Signature: signatureB64,
		PublicKey: pubKeyPEM,
	}
	responseMsg, _ := NewAuthMessage(MessageAuthResponse, responsePayload)
	transport.Enqueue(responseMsg)

	// Wait for AUTH_OK
	resultMsg, _ := transport.Dequeue()
	if resultMsg.Type != MessageAuthOK {
		t.Errorf("expected AUTH_OK, got %s", resultMsg.Type)
	}

	wg.Wait()

	if authErr != nil {
		t.Fatalf("Authenticate() error = %v", authErr)
	}
}

func TestAuthServer_Authenticate_InvalidSignature(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	server := NewAuthServer(ks, 10)
	transport := NewMockTransport()

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	clientPub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Use different key to sign (invalid signature)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)

	var authErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, authErr = server.Authenticate(ctx, transport)
	}()

	// Receive the AUTH_CHALLENGE
	challengeMsg, _ := transport.Dequeue()
	var challenge AuthChallengePayload
	json.Unmarshal(challengeMsg.Payload, &challenge)

	// Sign with WRONG key
	nonceBytes, _ := hex.DecodeString(challenge.Nonce)
	signature := ed25519.Sign(wrongPriv, nonceBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Build AUTH_RESPONSE
	pubKeyPEM := publicKeyToPEM(clientPub)
	responsePayload := AuthResponsePayload{
		Nonce:     challenge.Nonce,
		Signature: signatureB64,
		PublicKey: pubKeyPEM,
	}
	responseMsg, _ := NewAuthMessage(MessageAuthResponse, responsePayload)
	transport.Enqueue(responseMsg)

	// Wait for AUTH_FAIL
	resultMsg, _ := transport.Dequeue()
	if resultMsg.Type != MessageAuthFail {
		t.Errorf("expected AUTH_FAIL, got %s", resultMsg.Type)
	}

	var failPayload AuthFailPayload
	json.Unmarshal(resultMsg.Payload, &failPayload)
	if failPayload.Reason != "invalid_signature" {
		t.Errorf("reason = %q, want %q", failPayload.Reason, "invalid_signature")
	}

	wg.Wait()

	if authErr == nil {
		t.Error("Authenticate() should return error for invalid signature")
	}
}

func TestAuthServer_Authenticate_ExpiredNonce(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	server := NewAuthServer(ks, 10)
	// Set very short nonce timeout for testing
	server.nonceTimeout = 10 * time.Millisecond

	transport := NewMockTransport()

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	var authErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, authErr = server.Authenticate(ctx, transport)
	}()

	// Receive the AUTH_CHALLENGE
	challengeMsg, _ := transport.Dequeue()
	var challenge AuthChallengePayload
	json.Unmarshal(challengeMsg.Payload, &challenge)

	// Wait for nonce to expire
	time.Sleep(20 * time.Millisecond)

	// Sign the nonce
	nonceBytes, _ := hex.DecodeString(challenge.Nonce)
	signature := ed25519.Sign(clientPriv, nonceBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Build AUTH_RESPONSE
	pubKeyPEM := publicKeyToPEM(clientPub)
	responsePayload := AuthResponsePayload{
		Nonce:     challenge.Nonce,
		Signature: signatureB64,
		PublicKey: pubKeyPEM,
	}
	responseMsg, _ := NewAuthMessage(MessageAuthResponse, responsePayload)
	transport.Enqueue(responseMsg)

	// Wait for AUTH_FAIL
	resultMsg, _ := transport.Dequeue()
	if resultMsg.Type != MessageAuthFail {
		t.Errorf("expected AUTH_FAIL, got %s", resultMsg.Type)
	}

	var failPayload AuthFailPayload
	json.Unmarshal(resultMsg.Payload, &failPayload)
	if failPayload.Reason != "expired_nonce" {
		t.Errorf("reason = %q, want %q", failPayload.Reason, "expired_nonce")
	}

	wg.Wait()

	if authErr == nil {
		t.Error("Authenticate() should return error for expired nonce")
	}
}

func TestAuthServer_Authenticate_WrongNonce(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	server := NewAuthServer(ks, 10)
	transport := NewMockTransport()

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	var authErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, authErr = server.Authenticate(ctx, transport)
	}()

	// Receive the AUTH_CHALLENGE but ignore its nonce
	transport.Dequeue()

	// Use a different nonce
	wrongNonce := GenerateNonce()
	nonceBytes, _ := hex.DecodeString(wrongNonce)
	signature := ed25519.Sign(clientPriv, nonceBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Build AUTH_RESPONSE with wrong nonce
	pubKeyPEM := publicKeyToPEM(clientPub)
	responsePayload := AuthResponsePayload{
		Nonce:     wrongNonce,
		Signature: signatureB64,
		PublicKey: pubKeyPEM,
	}
	responseMsg, _ := NewAuthMessage(MessageAuthResponse, responsePayload)
	transport.Enqueue(responseMsg)

	// Wait for AUTH_FAIL
	resultMsg, _ := transport.Dequeue()
	if resultMsg.Type != MessageAuthFail {
		t.Errorf("expected AUTH_FAIL, got %s", resultMsg.Type)
	}

	var failPayload AuthFailPayload
	json.Unmarshal(resultMsg.Payload, &failPayload)
	if failPayload.Reason != "expired_nonce" {
		t.Errorf("reason = %q, want %q", failPayload.Reason, "expired_nonce")
	}

	wg.Wait()

	if authErr == nil {
		t.Error("Authenticate() should return error for wrong nonce")
	}
}

func TestAuthServer_Authenticate_MissingPublicKey(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	server := NewAuthServer(ks, 10)
	transport := NewMockTransport()

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	var authErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, authErr = server.Authenticate(ctx, transport)
	}()

	// Receive the AUTH_CHALLENGE
	challengeMsg, _ := transport.Dequeue()
	var challenge AuthChallengePayload
	json.Unmarshal(challengeMsg.Payload, &challenge)

	// Sign the nonce
	nonceBytes, _ := hex.DecodeString(challenge.Nonce)
	signature := ed25519.Sign(clientPriv, nonceBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Build AUTH_RESPONSE without public key (should fail for new client)
	responsePayload := AuthResponsePayload{
		Nonce:     challenge.Nonce,
		Signature: signatureB64,
		PublicKey: "", // Missing!
	}
	responseMsg, _ := NewAuthMessage(MessageAuthResponse, responsePayload)
	transport.Enqueue(responseMsg)

	// Wait for AUTH_FAIL
	resultMsg, _ := transport.Dequeue()
	if resultMsg.Type != MessageAuthFail {
		t.Errorf("expected AUTH_FAIL, got %s", resultMsg.Type)
	}

	var failPayload AuthFailPayload
	json.Unmarshal(resultMsg.Payload, &failPayload)
	if failPayload.Reason != "missing_public_key" {
		t.Errorf("reason = %q, want %q", failPayload.Reason, "missing_public_key")
	}

	wg.Wait()

	if authErr == nil {
		t.Error("Authenticate() should return error for missing public key")
	}
}

func TestAuthServer_Authenticate_UnexpectedMessage(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	server := NewAuthServer(ks, 10)
	transport := NewMockTransport()

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	var authErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, authErr = server.Authenticate(ctx, transport)
	}()

	// Receive the AUTH_CHALLENGE
	transport.Dequeue()

	// Send wrong message type
	wrongMsg, _ := NewAuthMessage(MessageEnrollRequest, map[string]string{"foo": "bar"})
	transport.Enqueue(wrongMsg)

	// Wait for AUTH_FAIL
	resultMsg, _ := transport.Dequeue()
	if resultMsg.Type != MessageAuthFail {
		t.Errorf("expected AUTH_FAIL, got %s", resultMsg.Type)
	}

	wg.Wait()

	if authErr == nil {
		t.Error("Authenticate() should return error for unexpected message")
	}
}

func TestAuthServer_NonceTracking(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	server := NewAuthServer(ks, 10)

	// Verify pendingNonces map starts empty
	server.mu.Lock()
	if len(server.pendingNonces) != 0 {
		t.Error("pendingNonces should start empty")
	}
	server.mu.Unlock()
}

// createLinkedTransports creates a pair of linked MockTransports where
// messages sent on one appear in the receive channel of the other.
func createLinkedTransports(t *testing.T) (*MockTransport, *MockTransport) {
	t.Helper()
	clientTransport := NewMockTransport()
	serverTransport := NewMockTransport()

	ctx := context.Background()
	if err := clientTransport.Connect(ctx); err != nil {
		t.Fatalf("clientTransport.Connect() error = %v", err)
	}
	if err := serverTransport.Connect(ctx); err != nil {
		t.Fatalf("serverTransport.Connect() error = %v", err)
	}

	// Bridge: client's send -> server's recv, server's send -> client's recv
	go func() {
		for msg := range clientTransport.sendCh {
			serverTransport.recvCh <- msg
		}
	}()
	go func() {
		for msg := range serverTransport.sendCh {
			clientTransport.recvCh <- msg
		}
	}()

	return clientTransport, serverTransport
}

// TestAuthClientServerIntegration verifies that AuthClient and AuthServer
// can complete the full authentication handshake together.
func TestAuthClientServerIntegration(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up server with key store
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}
	server := NewAuthServer(ks, 10)

	// Set up client with key path
	clientKeyPath := filepath.Join(tmpDir, "client-key.pem")
	clientTransport, serverTransport := createLinkedTransports(t)
	client := NewAuthClient(clientTransport, clientKeyPath)

	// Generate client key
	if err := client.LoadOrGenerateKey(); err != nil {
		t.Fatalf("LoadOrGenerateKey() error = %v", err)
	}

	ctx := context.Background()

	// Run client and server in separate goroutines with linked transports
	var clientErr, serverErr error
	var serverPubKey ed25519.PublicKey
	var wg sync.WaitGroup

	wg.Add(2)

	// Server goroutine uses serverTransport
	go func() {
		defer wg.Done()
		serverPubKey, serverErr = server.Authenticate(ctx, serverTransport)
	}()

	// Client goroutine uses clientTransport
	go func() {
		defer wg.Done()
		clientErr = client.Authenticate(ctx)
	}()

	wg.Wait()

	// Verify both completed successfully
	if clientErr != nil {
		t.Errorf("client Authenticate() error = %v", clientErr)
	}
	if serverErr != nil {
		t.Errorf("server Authenticate() error = %v", serverErr)
	}

	// Verify server received the correct public key
	if serverPubKey != nil && client.publicKey != nil {
		if !serverPubKey.Equal(client.publicKey) {
			t.Error("server did not receive correct client public key")
		}
	}

	// Verify key was registered in TOFU store
	if client.publicKey != nil && !ks.IsKnown(client.publicKey) {
		t.Error("client key should be registered in key store after TOFU")
	}
}

// TestAuthClientServerIntegration_ReconnectWithKnownKey verifies that a
// previously registered client can authenticate again.
func TestAuthClientServerIntegration_ReconnectWithKnownKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up server with key store
	ks, err := NewKeyStore(filepath.Join(tmpDir, "keys.json"))
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}
	server := NewAuthServer(ks, 10)

	// Set up client with key path
	clientKeyPath := filepath.Join(tmpDir, "client-key.pem")

	// First connection: TOFU registration
	{
		clientTransport, serverTransport := createLinkedTransports(t)
		client := NewAuthClient(clientTransport, clientKeyPath)
		if err := client.LoadOrGenerateKey(); err != nil {
			t.Fatalf("LoadOrGenerateKey() error = %v", err)
		}

		ctx := context.Background()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			server.Authenticate(ctx, serverTransport)
		}()

		go func() {
			defer wg.Done()
			client.Authenticate(ctx)
		}()

		wg.Wait()
	}

	// Second connection: reconnect with known key
	{
		clientTransport, serverTransport := createLinkedTransports(t)
		client := NewAuthClient(clientTransport, clientKeyPath)
		// Load existing key (not generate)
		if err := client.LoadOrGenerateKey(); err != nil {
			t.Fatalf("LoadOrGenerateKey() error = %v", err)
		}

		ctx := context.Background()

		var clientErr, serverErr error
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_, serverErr = server.Authenticate(ctx, serverTransport)
		}()

		go func() {
			defer wg.Done()
			clientErr = client.Authenticate(ctx)
		}()

		wg.Wait()

		if clientErr != nil {
			t.Errorf("reconnect: client Authenticate() error = %v", clientErr)
		}
		if serverErr != nil {
			t.Errorf("reconnect: server Authenticate() error = %v", serverErr)
		}
	}
}

// Helper function to convert ed25519 public key to PEM format
func publicKeyToPEM(pub ed25519.PublicKey) string {
	pkixBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixBytes,
	}
	return string(pem.EncodeToMemory(block))
}
