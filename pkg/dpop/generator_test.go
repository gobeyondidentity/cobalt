package dpop

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGenerateProof_ValidJWT(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	_ = pub // not used in this test

	t.Log("Generating DPoP proof for POST https://example.com/api/v1/push")
	proof, err := GenerateProof(priv, "POST", "https://example.com/api/v1/push", "test-kid")
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	t.Log("Verifying JWT has three base64url-encoded parts separated by dots")
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	for i, part := range parts {
		if part == "" {
			t.Errorf("part %d is empty", i)
		}
		// Verify each part is valid base64url
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			t.Errorf("part %d is not valid base64url: %v", i, err)
		}
	}
	t.Log("JWT structure is valid: header.payload.signature")
}

func TestGenerateProof_HeaderClaims(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	t.Log("Generating DPoP proof with kid='test-kid-123'")
	proof, err := GenerateProof(priv, "GET", "https://example.com/resource", "test-kid-123")
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	t.Log("Decoding and parsing JWT header")
	parts := strings.Split(proof, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to parse header JSON: %v", err)
	}

	t.Log("Verifying typ='dpop+jwt'")
	if header.Typ != TypeDPoP {
		t.Errorf("typ: expected %q, got %q", TypeDPoP, header.Typ)
	}

	t.Log("Verifying alg='EdDSA'")
	if header.Alg != AlgEdDSA {
		t.Errorf("alg: expected %q, got %q", AlgEdDSA, header.Alg)
	}

	t.Log("Verifying kid='test-kid-123'")
	if header.Kid != "test-kid-123" {
		t.Errorf("kid: expected %q, got %q", "test-kid-123", header.Kid)
	}

	t.Log("Verifying jwk is not present when kid is provided")
	if header.JWK != nil {
		t.Error("jwk should not be present when kid is provided")
	}
	t.Log("Header claims are correct")
}

func TestGenerateProof_PayloadClaims(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	beforeIat := time.Now().Unix()
	t.Log("Generating DPoP proof for POST https://api.example.com/v1/credentials")
	proof, err := GenerateProof(priv, "POST", "https://api.example.com/v1/credentials", "kid-1")
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}
	afterIat := time.Now().Unix()

	t.Log("Decoding and parsing JWT payload")
	parts := strings.Split(proof, ".")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("failed to parse payload JSON: %v", err)
	}

	t.Log("Verifying jti is non-empty (UUID)")
	if claims.JTI == "" {
		t.Error("jti is empty")
	}
	// UUID format: 8-4-4-4-12 characters
	if len(claims.JTI) != 36 {
		t.Errorf("jti length: expected 36 (UUID format), got %d", len(claims.JTI))
	}

	t.Log("Verifying htm='POST'")
	if claims.HTM != "POST" {
		t.Errorf("htm: expected %q, got %q", "POST", claims.HTM)
	}

	t.Log("Verifying htu='https://api.example.com/v1/credentials'")
	if claims.HTU != "https://api.example.com/v1/credentials" {
		t.Errorf("htu: expected %q, got %q", "https://api.example.com/v1/credentials", claims.HTU)
	}

	t.Log("Verifying iat is within expected time window")
	if claims.IAT < beforeIat || claims.IAT > afterIat {
		t.Errorf("iat %d outside expected range [%d, %d]", claims.IAT, beforeIat, afterIat)
	}
	t.Log("Payload claims are correct")
}

func TestGenerateProof_UniqueJTI(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	t.Log("Generating first DPoP proof")
	proof1, err := GenerateProof(priv, "GET", "https://example.com/resource", "kid")
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	t.Log("Generating second DPoP proof")
	proof2, err := GenerateProof(priv, "GET", "https://example.com/resource", "kid")
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	t.Log("Extracting jti from both proofs")
	jti1 := extractJTI(t, proof1)
	jti2 := extractJTI(t, proof2)

	t.Log("Verifying jti values are different")
	if jti1 == jti2 {
		t.Error("jti values should be unique for each proof")
	}
	t.Logf("jti1=%s, jti2=%s (both unique)", jti1, jti2)
}

func TestGenerateProof_JTIRandomness(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	t.Log("Generating 1000 jti values to verify uniqueness and randomness")
	jtis := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		proof, err := GenerateProof(priv, "GET", "https://example.com/", "kid")
		if err != nil {
			t.Fatalf("GenerateProof iteration %d failed: %v", i, err)
		}
		jti := extractJTI(t, proof)
		if _, exists := jtis[jti]; exists {
			t.Fatalf("duplicate jti found at iteration %d: %s", i, jti)
		}
		jtis[jti] = struct{}{}
	}
	t.Log("All 1000 jti values are unique")
}

func TestGenerateProof_URLNormalization(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	tests := []struct {
		name        string
		inputURL    string
		expectedHTU string
	}{
		{
			name:        "query string stripped",
			inputURL:    "https://example.com/api?query=1&page=2",
			expectedHTU: "https://example.com/api",
		},
		{
			name:        "fragment stripped",
			inputURL:    "https://example.com/api#section",
			expectedHTU: "https://example.com/api",
		},
		{
			name:        "query and fragment stripped",
			inputURL:    "https://example.com/api?query=1#frag",
			expectedHTU: "https://example.com/api",
		},
		{
			name:        "uppercase host lowercased",
			inputURL:    "https://EXAMPLE.COM/api/v1/push",
			expectedHTU: "https://example.com/api/v1/push",
		},
		{
			name:        "mixed case host lowercased",
			inputURL:    "https://Api.ExAmPlE.COM/Resource",
			expectedHTU: "https://api.example.com/Resource",
		},
		{
			name:        "default HTTPS port 443 removed",
			inputURL:    "https://example.com:443/api",
			expectedHTU: "https://example.com/api",
		},
		{
			name:        "default HTTP port 80 removed",
			inputURL:    "http://example.com:80/api",
			expectedHTU: "http://example.com/api",
		},
		{
			name:        "non-default port preserved",
			inputURL:    "https://example.com:8443/api",
			expectedHTU: "https://example.com:8443/api",
		},
		{
			name:        "path preserved exactly",
			inputURL:    "https://example.com/api/v1/credentials/abc-123",
			expectedHTU: "https://example.com/api/v1/credentials/abc-123",
		},
		{
			name:        "root path",
			inputURL:    "https://example.com/",
			expectedHTU: "https://example.com/",
		},
		{
			name:        "no path",
			inputURL:    "https://example.com",
			expectedHTU: "https://example.com",
		},
		{
			name:        "full normalization",
			inputURL:    "https://EXAMPLE.COM:443/api/v1/push?query=1#frag",
			expectedHTU: "https://example.com/api/v1/push",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing URL normalization: %s -> %s", tt.inputURL, tt.expectedHTU)
			proof, err := GenerateProof(priv, "GET", tt.inputURL, "kid")
			if err != nil {
				t.Fatalf("GenerateProof failed: %v", err)
			}

			htu := extractHTU(t, proof)
			if htu != tt.expectedHTU {
				t.Errorf("htu: expected %q, got %q", tt.expectedHTU, htu)
			}
		})
	}
}

func TestGenerateProof_SignatureVerifies(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	t.Log("Generating DPoP proof")
	proof, err := GenerateProof(priv, "POST", "https://example.com/api", "test-kid")
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	t.Log("Extracting signature and signing input from JWT")
	parts := strings.Split(proof, ".")
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	t.Log("Verifying signature with public key")
	if !ed25519.Verify(pub, []byte(signingInput), signature) {
		t.Error("signature verification failed")
	}
	t.Log("Signature is valid")
}

func TestGenerateProof_WithJWK(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	t.Log("Generating DPoP proof with empty kid (enrollment case)")
	proof, err := GenerateProof(priv, "POST", "https://example.com/enroll", "")
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	t.Log("Decoding and parsing JWT header")
	parts := strings.Split(proof, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to parse header JSON: %v", err)
	}

	t.Log("Verifying kid is empty")
	if header.Kid != "" {
		t.Errorf("kid should be empty, got %q", header.Kid)
	}

	t.Log("Verifying jwk is present")
	if header.JWK == nil {
		t.Fatal("jwk should be present when kid is empty")
	}

	t.Log("Verifying jwk contains correct public key")
	if header.JWK.Kty != "OKP" {
		t.Errorf("jwk.kty: expected %q, got %q", "OKP", header.JWK.Kty)
	}
	if header.JWK.Crv != "Ed25519" {
		t.Errorf("jwk.crv: expected %q, got %q", "Ed25519", header.JWK.Crv)
	}

	expectedX := base64.RawURLEncoding.EncodeToString(pub)
	if header.JWK.X != expectedX {
		t.Errorf("jwk.x: expected %q, got %q", expectedX, header.JWK.X)
	}
	t.Log("JWK is correctly embedded in header")
}

func TestSignRequest(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	_ = pub

	t.Log("Creating HTTP request")
	req, err := http.NewRequest("POST", "https://api.example.com/v1/credentials", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	t.Log("Signing request with SignRequest")
	if err := SignRequest(req, priv, "my-kid"); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	t.Log("Verifying DPoP header is present")
	dpopHeader := req.Header.Get("DPoP")
	if dpopHeader == "" {
		t.Fatal("DPoP header not present")
	}

	t.Log("Verifying DPoP header contains valid JWT")
	parts := strings.Split(dpopHeader, ".")
	if len(parts) != 3 {
		t.Errorf("DPoP header is not valid JWT: expected 3 parts, got %d", len(parts))
	}

	t.Log("Verifying JWT claims match request")
	claims := extractClaims(t, dpopHeader)
	if claims.HTM != "POST" {
		t.Errorf("htm: expected %q, got %q", "POST", claims.HTM)
	}
	if claims.HTU != "https://api.example.com/v1/credentials" {
		t.Errorf("htu: expected %q, got %q", "https://api.example.com/v1/credentials", claims.HTU)
	}
	t.Log("SignRequest correctly added DPoP header")
}

func TestSignRequest_HostHeaderIgnored(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	t.Log("Creating HTTP request with URL pointing to real-host.com")
	req, err := http.NewRequest("POST", "https://real-host.com/api", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	t.Log("Setting Host header to attacker-host.com (simulating Host header injection)")
	req.Host = "attacker-host.com"

	t.Log("Signing request")
	if err := SignRequest(req, priv, "kid"); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	t.Log("Verifying htu uses URL, not Host header")
	dpopHeader := req.Header.Get("DPoP")
	claims := extractClaims(t, dpopHeader)
	if claims.HTU != "https://real-host.com/api" {
		t.Errorf("htu should use URL not Host header: expected %q, got %q", "https://real-host.com/api", claims.HTU)
	}
	t.Log("Host header injection prevented: htu uses request URL")
}

func TestGenerateProof_MethodCaseSensitivity(t *testing.T) {
	t.Log("Generating Ed25519 key pair for test")
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	t.Log("Generating proof with lowercase 'post' method")
	proof, err := GenerateProof(priv, "post", "https://example.com/api", "kid")
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	t.Log("Verifying htm preserves exact case")
	claims := extractClaims(t, proof)
	if claims.HTM != "post" {
		t.Errorf("htm should preserve exact method case: expected %q, got %q", "post", claims.HTM)
	}
	t.Log("HTTP method case preserved correctly")
}

// Helper functions

func extractJTI(t *testing.T, proof string) string {
	t.Helper()
	return extractClaims(t, proof).JTI
}

func extractHTU(t *testing.T, proof string) string {
	t.Helper()
	return extractClaims(t, proof).HTU
}

func extractClaims(t *testing.T, proof string) *Claims {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT: expected 3 parts, got %d", len(parts))
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("failed to parse claims: %v", err)
	}
	return &claims
}
