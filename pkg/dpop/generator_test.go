package dpop

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGenerateProof_ValidJWT(t *testing.T) {
	t.Log("Testing proof generator produces valid JWT structure")

	_, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	proof, err := gen.Generate("POST", "https://example.com/api/v1/push", "km_abc123")
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	// JWT should have 3 parts separated by dots
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 JWT parts, got %d", len(parts))
	}

	// Each part should be non-empty base64url
	for i, part := range parts {
		if part == "" {
			t.Errorf("part %d is empty", i)
		}
		// Check for valid base64url characters
		for _, c := range part {
			if !isBase64URLChar(c) {
				t.Errorf("part %d contains invalid character: %c", i, c)
				break
			}
		}
	}

	t.Log("Valid JWT structure produced")
}

func isBase64URLChar(c rune) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_'
}

func TestGenerateProof_HeaderClaims(t *testing.T) {
	t.Log("Testing proof header contains correct claims")

	_, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	proof, _ := gen.Generate("GET", "https://example.com/api", "km_test")

	header, _, _, err := ParseProof(proof)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	// Check typ
	if header["typ"] != "dpop+jwt" {
		t.Errorf("expected typ=dpop+jwt, got %v", header["typ"])
	}

	// Check alg
	if header["alg"] != "EdDSA" {
		t.Errorf("expected alg=EdDSA, got %v", header["alg"])
	}

	// Check kid is present (since we provided one)
	if header["kid"] != "km_test" {
		t.Errorf("expected kid=km_test, got %v", header["kid"])
	}

	// jwk should NOT be present when kid is provided
	if header["jwk"] != nil {
		t.Error("jwk should not be present when kid is provided")
	}

	t.Log("Header claims correct")
}

func TestGenerateProof_HeaderWithJWK(t *testing.T) {
	t.Log("Testing proof header contains JWK when no kid (enrollment)")

	pubKey, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	// Empty kid = enrollment mode
	proof, _ := gen.Generate("POST", "https://example.com/enroll/complete", "")

	header, _, _, err := ParseProof(proof)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	// kid should NOT be present
	if header["kid"] != nil {
		t.Errorf("kid should not be present during enrollment, got %v", header["kid"])
	}

	// jwk should be present
	jwk, ok := header["jwk"].(map[string]any)
	if !ok {
		t.Fatal("jwk should be present during enrollment")
	}

	// Verify JWK structure
	if jwk["kty"] != "OKP" {
		t.Errorf("expected kty=OKP, got %v", jwk["kty"])
	}
	if jwk["crv"] != "Ed25519" {
		t.Errorf("expected crv=Ed25519, got %v", jwk["crv"])
	}

	// Verify x contains the public key
	xB64, _ := jwk["x"].(string)
	xBytes, err := base64URLDecode(xB64)
	if err != nil {
		t.Fatalf("failed to decode x: %v", err)
	}
	if !ed25519.PublicKey(xBytes).Equal(pubKey) {
		t.Error("JWK x does not match public key")
	}

	t.Log("JWK correctly included during enrollment")
}

func TestGenerateProof_PayloadClaims(t *testing.T) {
	t.Log("Testing proof payload contains correct claims")

	_, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	beforeTime := time.Now().Unix()
	proof, _ := gen.Generate("POST", "https://example.com/api/v1/push", "km_test")
	afterTime := time.Now().Unix()

	_, payload, _, err := ParseProof(proof)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	// Check jti is present and non-empty
	jti, ok := payload["jti"].(string)
	if !ok || jti == "" {
		t.Error("jti should be a non-empty string")
	}

	// Check htm
	if payload["htm"] != "POST" {
		t.Errorf("expected htm=POST, got %v", payload["htm"])
	}

	// Check htu (should be normalized)
	if payload["htu"] != "https://example.com/api/v1/push" {
		t.Errorf("expected htu=https://example.com/api/v1/push, got %v", payload["htu"])
	}

	// Check iat is within expected range
	iat, ok := payload["iat"].(float64)
	if !ok {
		t.Error("iat should be a number")
	} else if int64(iat) < beforeTime || int64(iat) > afterTime {
		t.Errorf("iat %v outside expected range [%v, %v]", iat, beforeTime, afterTime)
	}

	t.Log("Payload claims correct")
}

func TestGenerateProof_UniqueJTI(t *testing.T) {
	t.Log("Testing each proof has unique jti")

	_, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	seen := make(map[string]bool)
	count := 100

	for i := 0; i < count; i++ {
		proof, _ := gen.Generate("GET", "https://example.com/api", "km_test")
		_, payload, _, _ := ParseProof(proof)
		jti := payload["jti"].(string)

		if seen[jti] {
			t.Errorf("duplicate jti found: %s", jti)
		}
		seen[jti] = true
	}

	if len(seen) != count {
		t.Errorf("expected %d unique jti values, got %d", count, len(seen))
	}

	t.Log("All jti values unique")
}

func TestGenerateProof_JTIRandomness(t *testing.T) {
	t.Log("Testing jti values are random (UUIDv4), not sequential")

	_, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	var jtis []string
	for i := 0; i < 1000; i++ {
		proof, _ := gen.Generate("GET", "https://example.com/api", "km_test")
		_, payload, _, _ := ParseProof(proof)
		jtis = append(jtis, payload["jti"].(string))
	}

	// Check that jti values look like UUIDs (36 chars with hyphens)
	for i, jti := range jtis {
		if len(jti) != 36 {
			t.Errorf("jti[%d] length %d, expected 36 (UUID format)", i, len(jti))
		}
		// UUID format: 8-4-4-4-12
		if jti[8] != '-' || jti[13] != '-' || jti[18] != '-' || jti[23] != '-' {
			t.Errorf("jti[%d] doesn't match UUID format: %s", i, jti)
		}
	}

	// Check for sequential patterns (first 8 chars shouldn't increment)
	// This is a weak check but catches obvious mistakes
	prefixes := make(map[string]int)
	for _, jti := range jtis {
		prefix := jti[:8]
		prefixes[prefix]++
	}

	// With random UUIDs, we expect diverse prefixes
	// If more than 10% have the same prefix, something is wrong
	maxCount := 0
	for _, count := range prefixes {
		if count > maxCount {
			maxCount = count
		}
	}
	if maxCount > 100 { // More than 10% with same prefix
		t.Errorf("jti prefixes not random enough: max count %d out of 1000", maxCount)
	}

	t.Log("jti values appear random (UUIDv4)")
}

func TestGenerateProof_URLNormalization(t *testing.T) {
	t.Log("Testing URL normalization per RFC 9449")

	_, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	tests := []struct {
		name     string
		inputURI string
		wantHtu  string
	}{
		{
			name:     "basic https",
			inputURI: "https://example.com/api",
			wantHtu:  "https://example.com/api",
		},
		{
			name:     "uppercase host",
			inputURI: "https://EXAMPLE.COM/api",
			wantHtu:  "https://example.com/api",
		},
		{
			name:     "uppercase scheme",
			inputURI: "HTTPS://example.com/api",
			wantHtu:  "https://example.com/api",
		},
		{
			name:     "with query string",
			inputURI: "https://example.com/api?foo=bar",
			wantHtu:  "https://example.com/api",
		},
		{
			name:     "with fragment",
			inputURI: "https://example.com/api#section",
			wantHtu:  "https://example.com/api",
		},
		{
			name:     "with query and fragment",
			inputURI: "https://example.com/api?foo=bar#section",
			wantHtu:  "https://example.com/api",
		},
		{
			name:     "default https port",
			inputURI: "https://example.com:443/api",
			wantHtu:  "https://example.com/api",
		},
		{
			name:     "non-default https port",
			inputURI: "https://example.com:8443/api",
			wantHtu:  "https://example.com:8443/api",
		},
		{
			name:     "default http port",
			inputURI: "http://example.com:80/api",
			wantHtu:  "http://example.com/api",
		},
		{
			name:     "non-default http port",
			inputURI: "http://example.com:8080/api",
			wantHtu:  "http://example.com:8080/api",
		},
		{
			name:     "no path",
			inputURI: "https://example.com",
			wantHtu:  "https://example.com/",
		},
		{
			name:     "mixed case path preserved",
			inputURI: "https://example.com/API/V1",
			wantHtu:  "https://example.com/API/V1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof, err := gen.Generate("GET", tc.inputURI, "km_test")
			if err != nil {
				t.Fatalf("failed to generate proof: %v", err)
			}

			_, payload, _, _ := ParseProof(proof)
			if payload["htu"] != tc.wantHtu {
				t.Errorf("htu = %v, want %v", payload["htu"], tc.wantHtu)
			}
		})
	}

	t.Log("URL normalization correct")
}

func TestGenerateProof_SignatureVerifies(t *testing.T) {
	t.Log("Testing proof signature verifies with public key")

	pubKey, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	proof, _ := gen.Generate("POST", "https://example.com/api", "km_test")

	if !VerifyProof(proof, pubKey) {
		t.Error("signature verification failed")
	}

	t.Log("Signature verification passed")
}

func TestGenerateProof_SignatureFailsWithWrongKey(t *testing.T) {
	t.Log("Testing proof signature fails with wrong public key")

	_, privKey, _ := GenerateKey()
	otherPubKey, _, _ := GenerateKey()

	gen := NewEd25519Generator(privKey)
	proof, _ := gen.Generate("POST", "https://example.com/api", "km_test")

	if VerifyProof(proof, otherPubKey) {
		t.Error("signature should not verify with different key")
	}

	t.Log("Signature correctly fails with wrong key")
}

func TestGenerateProof_MethodCaseSensitivity(t *testing.T) {
	t.Log("Testing HTTP method is preserved exactly (case-sensitive)")

	_, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	tests := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "get", "Post"}

	for _, method := range tests {
		proof, _ := gen.Generate(method, "https://example.com/api", "km_test")
		_, payload, _, _ := ParseProof(proof)

		if payload["htm"] != method {
			t.Errorf("method %q became %q", method, payload["htm"])
		}
	}

	t.Log("HTTP method case preserved")
}

func TestSignRequest(t *testing.T) {
	t.Log("Testing SignRequest adds DPoP header to request")

	_, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	req := httptest.NewRequest("POST", "https://example.com/api/v1/push", nil)

	err := gen.SignRequest(req, "km_test")
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	dpopHeader := req.Header.Get("DPoP")
	if dpopHeader == "" {
		t.Error("DPoP header not set")
	}

	// Verify the header is a valid JWT
	parts := strings.Split(dpopHeader, ".")
	if len(parts) != 3 {
		t.Errorf("DPoP header is not valid JWT: %d parts", len(parts))
	}

	t.Log("SignRequest correctly adds DPoP header")
}

func TestSignRequest_HostHeaderIgnored(t *testing.T) {
	t.Log("Testing SignRequest uses URL, not Host header (prevents injection)")

	pubKey, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	// Create request with URL to example.com but Host header set to attacker.com
	req := httptest.NewRequest("GET", "https://example.com/api", nil)
	req.Host = "attacker.com" // Attacker tries to inject different host

	err := gen.SignRequest(req, "km_test")
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	// Parse the proof and check htu
	proof := req.Header.Get("DPoP")
	_, payload, _, _ := ParseProof(proof)

	htu := payload["htu"].(string)

	// htu should use URL host, not Host header
	if strings.Contains(htu, "attacker.com") {
		t.Error("htu should not contain attacker.com (Host header injection)")
	}

	// Note: httptest.NewRequest sets URL.Host from the URL string
	// So we verify the proof still verifies correctly
	if !VerifyProof(proof, pubKey) {
		t.Error("proof should still be valid")
	}

	t.Log("Host header injection prevented")
}

func TestSignRequest_FreshProofEachCall(t *testing.T) {
	t.Log("Testing SignRequest generates fresh proof each call (no replay)")

	_, privKey, _ := GenerateKey()
	gen := NewEd25519Generator(privKey)

	req1 := httptest.NewRequest("GET", "https://example.com/api", nil)
	req2 := httptest.NewRequest("GET", "https://example.com/api", nil)

	gen.SignRequest(req1, "km_test")
	gen.SignRequest(req2, "km_test")

	proof1 := req1.Header.Get("DPoP")
	proof2 := req2.Header.Get("DPoP")

	if proof1 == proof2 {
		t.Error("each SignRequest call should generate different proof")
	}

	// Parse and check jti values are different
	_, payload1, _, _ := ParseProof(proof1)
	_, payload2, _, _ := ParseProof(proof2)

	if payload1["jti"] == payload2["jti"] {
		t.Error("jti should be different for each proof")
	}

	t.Log("Fresh proof generated for each call")
}

func TestParseProof_Invalid(t *testing.T) {
	t.Log("Testing ParseProof handles invalid input")

	tests := []struct {
		name  string
		proof string
	}{
		{"empty", ""},
		{"one part", "header"},
		{"two parts", "header.payload"},
		{"four parts", "a.b.c.d"},
		{"invalid base64 header", "!!!.payload.sig"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ParseProof(tc.proof)
			if err == nil {
				t.Error("expected error for invalid proof")
			}
		})
	}

	t.Log("Invalid proofs correctly rejected")
}

func TestVerifyProof_Invalid(t *testing.T) {
	t.Log("Testing VerifyProof handles invalid input")

	pubKey, _, _ := GenerateKey()

	tests := []string{
		"",
		"not.a.jwt",
		"aGVhZGVy.cGF5bG9hZA.c2ln", // Valid base64 but wrong signature
	}

	for _, proof := range tests {
		if VerifyProof(proof, pubKey) {
			t.Errorf("VerifyProof should return false for: %q", proof)
		}
	}

	t.Log("Invalid proofs correctly rejected by VerifyProof")
}

func TestNormalizeURI_Invalid(t *testing.T) {
	t.Log("Testing normalizeURI handles invalid URIs")

	_, err := normalizeURI("://invalid")
	if err == nil {
		t.Error("expected error for invalid URI")
	}

	t.Log("Invalid URI correctly rejected")
}

func TestGeneratorImplementsInterface(t *testing.T) {
	t.Log("Testing Ed25519Generator implements ProofGenerator interface")

	_, privKey, _ := GenerateKey()
	var _ ProofGenerator = NewEd25519Generator(privKey)

	t.Log("Interface implementation verified")
}

func TestIntegrationWithClient(t *testing.T) {
	t.Log("Testing generator integrates with DPoP client")

	// Create a test server that verifies DPoP
	pubKey, privKey, _ := GenerateKey()
	var receivedProof string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedProof = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with generator
	gen := NewEd25519Generator(privKey)
	client := NewClient(server.URL, gen, WithKID("km_test"))

	// Make request
	resp, err := client.Get("/api/v1/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// Verify proof was sent and is valid
	if receivedProof == "" {
		t.Fatal("no DPoP proof received")
	}

	if !VerifyProof(receivedProof, pubKey) {
		t.Error("received proof does not verify")
	}

	t.Log("Generator integrates correctly with client")
}
