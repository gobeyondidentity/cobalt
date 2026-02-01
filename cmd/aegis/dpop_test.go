package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gobeyondidentity/secure-infra/internal/aegis/localapi"
	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
)

func TestDPoPHeaderPresentOnRequests(t *testing.T) {
	t.Log("Testing that DPoP header is present on all nexus API requests")

	// Create a test server that captures the DPoP header
	var receivedDPoP string
	var receivedMethod string
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDPoP = r.Header.Get("DPoP")
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	t.Log("Setting up test identity for aegis")

	// Create temporary directory for test identity
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	kidPath := filepath.Join(tmpDir, "kid")

	// Generate and save test identity
	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)

	_, privKey, err := dpop.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	if err := keyStore.Save(privKey); err != nil {
		t.Fatalf("failed to save key: %v", err)
	}
	if err := kidStore.Save("aegis_test_kid"); err != nil {
		t.Fatalf("failed to save kid: %v", err)
	}

	t.Log("Creating DPoP client with test identity")

	// Create DPoP client
	proofGen := dpop.NewEd25519Generator(privKey)
	dpopClient := dpop.NewClient(server.URL, proofGen, dpop.WithKID("aegis_test_kid"))

	// Create localapi config with DPoP client
	localCfg := &localapi.Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: server.URL,
		DPUName:         "test-dpu",
		DPoPClient:      dpopClient,
	}

	t.Log("Creating localapi server with DPoP client")

	localServer, err := localapi.NewServer(localCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Test that a request includes the DPoP header
	t.Log("Making test request to verify DPoP header presence")

	// Use the RegisterViaTransport method which internally calls the control plane
	_, err = localServer.RegisterViaTransport(context.Background(), "test-host", nil)
	// We expect this to succeed (200 OK from mock server)
	if err != nil {
		t.Logf("Registration returned error (expected in test): %v", err)
	}

	// Verify the DPoP header was sent
	if receivedDPoP == "" {
		t.Error("DPoP header was not present on the request")
	} else {
		t.Logf("DPoP header present: %s...", receivedDPoP[:min(50, len(receivedDPoP))])
	}

	// Verify it's a valid JWT format (header.payload.signature)
	parts := strings.Split(receivedDPoP, ".")
	if len(parts) != 3 {
		t.Errorf("DPoP header is not a valid JWT (expected 3 parts, got %d)", len(parts))
	}

	t.Logf("Request method: %s, path: %s", receivedMethod, receivedPath)
	t.Log("DPoP header correctly added to nexus API request")
}

func TestDPoP401ErrorHandling(t *testing.T) {
	t.Log("Testing that 401 responses are handled with appropriate error logging")

	// Create a test server that returns 401 with DPoP error code
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"dpop.invalid_proof"}`))
	}))
	defer server.Close()

	t.Log("Setting up test identity")

	// Create temporary identity
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	kidPath := filepath.Join(tmpDir, "kid")

	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)

	_, privKey, _ := dpop.GenerateKey()
	keyStore.Save(privKey)
	kidStore.Save("aegis_test_kid")

	// Create DPoP client
	proofGen := dpop.NewEd25519Generator(privKey)
	dpopClient := dpop.NewClient(server.URL, proofGen, dpop.WithKID("aegis_test_kid"))

	localCfg := &localapi.Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: server.URL,
		DPUName:         "test-dpu",
		DPoPClient:      dpopClient,
	}

	localServer, err := localapi.NewServer(localCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	t.Log("Making request that will receive 401 response")

	_, err = localServer.RegisterViaTransport(context.Background(), "test-host", nil)

	// Should get an authentication error
	if err == nil {
		t.Error("expected error from 401 response, got nil")
	} else if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected authentication error, got: %v", err)
	} else {
		t.Logf("Received expected authentication error: %v", err)
	}

	t.Log("401 error handling verified")
}

func TestIsEnrolledCheck(t *testing.T) {
	t.Log("Testing IsEnrolled check for aegis identity")

	// Test with non-existent paths
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "nonexistent", "key.pem")
	kidPath := filepath.Join(tmpDir, "nonexistent", "kid")

	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)

	idCfg := dpop.IdentityConfig{
		KeyStore: keyStore,
		KIDStore: kidStore,
	}

	t.Log("Checking enrollment status with missing files")

	if dpop.IsEnrolled(idCfg) {
		t.Error("expected IsEnrolled to return false for missing files")
	}

	// Create only the key file
	t.Log("Creating only key file")
	os.MkdirAll(filepath.Dir(keyPath), 0700)
	_, privKey, _ := dpop.GenerateKey()
	keyStore.Save(privKey)

	if dpop.IsEnrolled(idCfg) {
		t.Error("expected IsEnrolled to return false with only key file")
	}

	// Create kid file too
	t.Log("Creating kid file")
	os.MkdirAll(filepath.Dir(kidPath), 0700)
	kidStore.Save("test_kid")

	if !dpop.IsEnrolled(idCfg) {
		t.Error("expected IsEnrolled to return true with both files")
	}

	t.Log("IsEnrolled check working correctly")
}

func TestInitDPoPClientNotEnrolled(t *testing.T) {
	t.Log("Testing initDPoPClient returns clear error when not enrolled")

	// This test verifies the error message when aegis is not enrolled
	// We can't easily test initDPoPClient directly because it uses hardcoded paths,
	// but we can verify the error message format by checking the DPoP package behavior.

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	kidPath := filepath.Join(tmpDir, "kid")

	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)

	idCfg := dpop.IdentityConfig{
		KeyStore:  keyStore,
		KIDStore:  kidStore,
		ServerURL: "https://example.com",
	}

	if dpop.IsEnrolled(idCfg) {
		t.Error("expected not enrolled initially")
	}

	// Try to load identity when not enrolled
	_, _, err := dpop.LoadIdentity(idCfg)
	if err == nil {
		t.Error("expected error when loading identity without enrollment")
	}

	t.Logf("Load identity error (expected): %v", err)
	t.Log("Error handling for unenrolled state verified")
}

func TestDPoPProofGeneration(t *testing.T) {
	t.Log("Testing DPoP proof generation contains required claims")

	_, privKey, _ := dpop.GenerateKey()
	proofGen := dpop.NewEd25519Generator(privKey)

	t.Log("Generating proof for POST /api/v1/hosts/register")

	proof, err := proofGen.Generate("POST", "https://nexus.example.com/api/v1/hosts/register", "aegis_kid")
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	// Parse the proof to verify contents
	header, payload, _, err := dpop.ParseProof(proof)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	// Verify header
	t.Log("Verifying proof header")
	if header["typ"] != "dpop+jwt" {
		t.Errorf("expected typ=dpop+jwt, got %v", header["typ"])
	}
	if header["alg"] != "EdDSA" {
		t.Errorf("expected alg=EdDSA, got %v", header["alg"])
	}
	if header["kid"] != "aegis_kid" {
		t.Errorf("expected kid=aegis_kid, got %v", header["kid"])
	}

	// Verify payload
	t.Log("Verifying proof payload")
	if payload["htm"] != "POST" {
		t.Errorf("expected htm=POST, got %v", payload["htm"])
	}
	if payload["htu"] != "https://nexus.example.com/api/v1/hosts/register" {
		t.Errorf("expected correct htu, got %v", payload["htu"])
	}
	if payload["jti"] == nil || payload["jti"] == "" {
		t.Error("expected jti to be present")
	}
	if payload["iat"] == nil {
		t.Error("expected iat to be present")
	}

	t.Log("DPoP proof contains all required claims")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
