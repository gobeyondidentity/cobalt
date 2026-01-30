package dpop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// testKeyPair generates an ed25519 key pair for testing.
func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return pub, priv
}

// makeProof constructs a DPoP proof JWT from the given components.
func makeProof(header Header, claims Claims, privateKey ed25519.PrivateKey) string {
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64
}

// makeProofWithRawParts constructs a proof from raw base64 parts (for testing malformed proofs).
func makeProofWithRawParts(headerB64, claimsB64, signatureB64 string) string {
	return headerB64 + "." + claimsB64 + "." + signatureB64
}

// validHeader returns a valid DPoP header for testing.
func validHeader(kid string) Header {
	return Header{
		Typ: TypeDPoP,
		Alg: AlgEdDSA,
		Kid: kid,
	}
}

// validClaims returns valid DPoP claims for testing.
func validClaims() Claims {
	return Claims{
		JTI: "test-jti-12345",
		HTM: "POST",
		HTU: "https://example.com/api/push",
		IAT: time.Now().Unix(),
	}
}

// TestValidatorValidProof tests that a valid proof is accepted and returns the kid.
func TestValidatorValidProof(t *testing.T) {
	t.Log("Testing valid DPoP proof acceptance")

	pub, priv := testKeyPair(t)
	kid := "test-key-123"

	header := validHeader(kid)
	claims := validClaims()
	proof := makeProof(header, claims, priv)

	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	v := NewValidator(DefaultValidatorConfig())
	gotKid, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)

	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if gotKid != kid {
		t.Errorf("expected kid %q, got %q", kid, gotKid)
	}
}

// TestValidatorMissingProof tests that empty proof returns dpop.missing_proof.
func TestValidatorMissingProof(t *testing.T) {
	t.Log("Testing missing DPoP proof rejection")

	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey { return nil }

	_, err := v.ValidateProof("", "POST", "https://example.com/api", keyLookup)
	if err == nil {
		t.Error("expected error for missing proof")
	}
	if ErrorCode(err) != ErrCodeMissingProof {
		t.Errorf("expected error code %s, got %s", ErrCodeMissingProof, ErrorCode(err))
	}
}

// TestValidatorJWTPartCount tests that proofs with wrong number of parts are rejected.
func TestValidatorJWTPartCount(t *testing.T) {
	t.Log("Testing JWT part count validation")

	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey { return nil }

	tests := []struct {
		name  string
		proof string
	}{
		{"two parts", "eyJhbGciOiJFZERTQSJ9.eyJqdGkiOiJ0ZXN0In0"},
		{"four parts", "eyJhbGciOiJFZERTQSJ9.eyJqdGkiOiJ0ZXN0In0.c2lnbmF0dXJl.ZXh0cmE"},
		{"one part", "eyJhbGciOiJFZERTQSJ9"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing proof with %s", tc.name)
			_, err := v.ValidateProof(tc.proof, "POST", "https://example.com/api", keyLookup)
			if err == nil {
				t.Error("expected error for malformed proof")
			}
			if ErrorCode(err) != ErrCodeInvalidProof {
				t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
			}
		})
	}
}

// TestValidatorEmptyParts tests that proofs with empty parts are rejected.
func TestValidatorEmptyParts(t *testing.T) {
	t.Log("Testing JWT with empty parts validation")

	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey { return nil }

	tests := []struct {
		name  string
		proof string
	}{
		{"empty header", ".eyJqdGkiOiJ0ZXN0In0.c2lnbmF0dXJl"},
		{"empty payload", "eyJhbGciOiJFZERTQSJ9..c2lnbmF0dXJl"},
		{"empty signature", "eyJhbGciOiJFZERTQSJ9.eyJqdGkiOiJ0ZXN0In0."},
		{"all empty", ".."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing proof with %s", tc.name)
			_, err := v.ValidateProof(tc.proof, "POST", "https://example.com/api", keyLookup)
			if err == nil {
				t.Error("expected error for proof with empty parts")
			}
			if ErrorCode(err) != ErrCodeInvalidProof {
				t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
			}
		})
	}
}

// TestValidatorInvalidBase64 tests that invalid base64url encoding is rejected.
func TestValidatorInvalidBase64(t *testing.T) {
	t.Log("Testing invalid base64url encoding rejection")

	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey { return nil }

	// Invalid base64 characters: +, /, =, and other non-base64url chars
	tests := []struct {
		name  string
		proof string
	}{
		{"invalid header base64", "!!!invalid!!!.eyJqdGkiOiJ0ZXN0In0.c2lnbmF0dXJl"},
		{"invalid payload base64", "eyJhbGciOiJFZERTQSJ9.!!!invalid!!!.c2lnbmF0dXJl"},
		{"invalid signature base64", "eyJhbGciOiJFZERTQSJ9.eyJqdGkiOiJ0ZXN0In0.!!!invalid!!!"},
		{"standard base64 padding", "eyJhbGciOiJFZERTQSJ9==.eyJqdGkiOiJ0ZXN0In0.c2lnbmF0dXJl"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing proof with %s", tc.name)
			_, err := v.ValidateProof(tc.proof, "POST", "https://example.com/api", keyLookup)
			if err == nil {
				t.Error("expected error for invalid base64")
			}
			if ErrorCode(err) != ErrCodeInvalidProof {
				t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
			}
		})
	}
}

// TestValidatorTypCheck tests that typ must be exactly "dpop+jwt".
func TestValidatorTypCheck(t *testing.T) {
	t.Log("Testing typ header validation")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	tests := []struct {
		name string
		typ  string
	}{
		{"typ=jwt", "jwt"},
		{"typ=JWT", "JWT"},
		{"typ=dpop", "dpop"},
		{"typ=DPOP+JWT", "DPOP+JWT"},
		{"typ empty", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing proof with %s", tc.name)
			header := Header{
				Typ: tc.typ,
				Alg: AlgEdDSA,
				Kid: kid,
			}
			claims := validClaims()
			proof := makeProof(header, claims, priv)

			_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
			if err == nil {
				t.Error("expected error for wrong typ")
			}
			if ErrorCode(err) != ErrCodeInvalidProof {
				t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
			}
		})
	}
}

// TestValidatorTypMissing tests that missing typ is rejected.
func TestValidatorTypMissing(t *testing.T) {
	t.Log("Testing missing typ header rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	// Create header without typ (omitempty would not help here, but we can use a raw map)
	headerMap := map[string]interface{}{
		"alg": AlgEdDSA,
		"kid": kid,
		// typ intentionally missing
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claims := validClaims()
	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := ed25519.Sign(priv, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	proof := signingInput + "." + signatureB64

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for missing typ")
	}
	if ErrorCode(err) != ErrCodeInvalidProof {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
	}
}

// TestValidatorAlgCheck tests algorithm validation.
func TestValidatorAlgCheck(t *testing.T) {
	t.Log("Testing alg header validation (algorithm confusion prevention)")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	tests := []struct {
		name string
		alg  string
	}{
		{"alg=none", "none"},
		{"alg=HS256", "HS256"},
		{"alg=RS256", "RS256"},
		{"alg=ES256", "ES256"},
		{"alg=PS256", "PS256"},
		{"alg=eddsa (lowercase)", "eddsa"},
		{"alg empty", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing proof with %s", tc.name)
			header := Header{
				Typ: TypeDPoP,
				Alg: tc.alg,
				Kid: kid,
			}
			claims := validClaims()
			proof := makeProof(header, claims, priv)

			_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
			if err == nil {
				t.Error("expected error for wrong alg")
			}
			if ErrorCode(err) != ErrCodeInvalidProof {
				t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
			}
		})
	}
}

// TestValidatorAlgMissing tests that missing alg is rejected.
func TestValidatorAlgMissing(t *testing.T) {
	t.Log("Testing missing alg header rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	// Create header without alg
	headerMap := map[string]interface{}{
		"typ": TypeDPoP,
		"kid": kid,
		// alg intentionally missing
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claims := validClaims()
	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := ed25519.Sign(priv, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	proof := signingInput + "." + signatureB64

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for missing alg")
	}
	if ErrorCode(err) != ErrCodeInvalidProof {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
	}
}

// TestValidatorHTMMissing tests that missing htm claim is rejected.
func TestValidatorHTMMissing(t *testing.T) {
	t.Log("Testing missing htm claim rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Claims without htm
	claimsMap := map[string]interface{}{
		"jti": "test-jti",
		"htu": "https://example.com/api/push",
		"iat": time.Now().Unix(),
		// htm intentionally missing
	}
	claimsJSON, _ := json.Marshal(claimsMap)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := ed25519.Sign(priv, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	proof := signingInput + "." + signatureB64

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for missing htm")
	}
	if ErrorCode(err) != ErrCodeInvalidProof {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
	}
}

// TestValidatorSizeLimit tests that oversized proofs are rejected.
func TestValidatorSizeLimit(t *testing.T) {
	t.Log("Testing proof size limit (8KB)")

	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey { return nil }

	// Create a proof larger than 8KB
	// Base64 encoding increases size by ~33%, so we need ~6KB of raw data to exceed 8KB encoded
	largePayload := strings.Repeat("a", 9000)
	proof := "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVkRFNBIn0." + largePayload + ".c2lnbmF0dXJl"

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api", keyLookup)
	if err == nil {
		t.Error("expected error for oversized proof")
	}
	if ErrorCode(err) != ErrCodeInvalidProof {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
	}
}

// TestValidatorUnknownKey tests that unknown kid returns ErrUnknownKey.
func TestValidatorUnknownKey(t *testing.T) {
	t.Log("Testing unknown kid rejection")

	_, priv := testKeyPair(t)
	kid := "unknown-key-12345"
	v := NewValidator(DefaultValidatorConfig())

	// KeyLookup returns nil for all keys
	keyLookup := func(k string) ed25519.PublicKey { return nil }

	header := validHeader(kid)
	claims := validClaims()
	proof := makeProof(header, claims, priv)

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for unknown key")
	}
	if ErrorCode(err) != ErrCodeUnknownKey {
		t.Errorf("expected error code %s, got %s", ErrCodeUnknownKey, ErrorCode(err))
	}
}

// TestValidatorKidMissing tests that missing kid is rejected.
func TestValidatorKidMissing(t *testing.T) {
	t.Log("Testing missing kid rejection")

	_, priv := testKeyPair(t)
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey { return nil }

	header := Header{
		Typ: TypeDPoP,
		Alg: AlgEdDSA,
		Kid: "", // Empty kid
	}
	claims := validClaims()
	proof := makeProof(header, claims, priv)

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for missing kid")
	}
	if ErrorCode(err) != ErrCodeInvalidProof {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidProof, ErrorCode(err))
	}
}

// TestValidatorSignatureCorrupted tests that corrupted signatures are rejected.
func TestValidatorSignatureCorrupted(t *testing.T) {
	t.Log("Testing corrupted signature rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	validProof := makeProof(header, claims, priv)

	// Split the proof and corrupt the signature (bit flip)
	parts := strings.Split(validProof, ".")
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sigBytes[0] ^= 0xFF // Flip bits in first byte
	parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
	corruptedProof := strings.Join(parts, ".")

	_, err := v.ValidateProof(corruptedProof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for corrupted signature")
	}
	if ErrorCode(err) != ErrCodeInvalidSignature {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidSignature, ErrorCode(err))
	}
}

// TestValidatorSignatureWrongKey tests that signatures from different key are rejected.
func TestValidatorSignatureWrongKey(t *testing.T) {
	t.Log("Testing signature from different key rejection")

	pub1, _ := testKeyPair(t)       // Key we expect
	_, priv2 := testKeyPair(t)      // Different key used to sign
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub1 // Return first key
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	proof := makeProof(header, claims, priv2) // Sign with second key

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for wrong key signature")
	}
	if ErrorCode(err) != ErrCodeInvalidSignature {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidSignature, ErrorCode(err))
	}
}

// TestValidatorSignatureEmpty tests that empty signatures are rejected.
func TestValidatorSignatureEmpty(t *testing.T) {
	t.Log("Testing empty signature rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	validProof := makeProof(header, claims, priv)

	// Replace signature with empty string (but keep the dot)
	parts := strings.Split(validProof, ".")
	parts[2] = ""
	emptySignatureProof := strings.Join(parts, ".")

	// This should be caught by the empty parts check first
	_, err := v.ValidateProof(emptySignatureProof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for empty signature")
	}
	// Could be ErrCodeInvalidProof (empty part) or ErrCodeInvalidSignature
	code := ErrorCode(err)
	if code != ErrCodeInvalidProof && code != ErrCodeInvalidSignature {
		t.Errorf("expected error code %s or %s, got %s", ErrCodeInvalidProof, ErrCodeInvalidSignature, code)
	}
}

// TestValidatorIATTooOld tests that old iat values are rejected.
func TestValidatorIATTooOld(t *testing.T) {
	t.Log("Testing iat too old rejection (120s in past with 60s tolerance)")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	claims.IAT = time.Now().Add(-120 * time.Second).Unix() // 120 seconds in the past
	proof := makeProof(header, claims, priv)

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for old iat")
	}
	if ErrorCode(err) != ErrCodeInvalidIAT {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidIAT, ErrorCode(err))
	}
}

// TestValidatorIATFuture tests that future iat values are rejected.
func TestValidatorIATFuture(t *testing.T) {
	t.Log("Testing iat in future rejection (120s in future)")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	claims.IAT = time.Now().Add(120 * time.Second).Unix() // 120 seconds in the future
	proof := makeProof(header, claims, priv)

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for future iat")
	}
	if ErrorCode(err) != ErrCodeInvalidIAT {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidIAT, ErrorCode(err))
	}
}

// TestValidatorIATZero tests that zero iat is rejected.
func TestValidatorIATZero(t *testing.T) {
	t.Log("Testing iat=0 rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	claims.IAT = 0
	proof := makeProof(header, claims, priv)

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for iat=0")
	}
	if ErrorCode(err) != ErrCodeInvalidIAT {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidIAT, ErrorCode(err))
	}
}

// TestValidatorIATNegative tests that negative iat is rejected.
func TestValidatorIATNegative(t *testing.T) {
	t.Log("Testing negative iat rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	claims.IAT = -1000
	proof := makeProof(header, claims, priv)

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for negative iat")
	}
	if ErrorCode(err) != ErrCodeInvalidIAT {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidIAT, ErrorCode(err))
	}
}

// TestValidatorIATFarFuture tests that far future iat (year 2200) is rejected.
func TestValidatorIATFarFuture(t *testing.T) {
	t.Log("Testing far future iat rejection (year 2200)")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	// Year 2200 timestamp
	claims.IAT = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	proof := makeProof(header, claims, priv)

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for far future iat")
	}
	if ErrorCode(err) != ErrCodeInvalidIAT {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidIAT, ErrorCode(err))
	}
}

// TestValidatorIATWithinTolerance tests that iat within tolerance is accepted.
func TestValidatorIATWithinTolerance(t *testing.T) {
	t.Log("Testing iat within tolerance acceptance (30s in past with 60s tolerance)")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	claims.IAT = time.Now().Add(-30 * time.Second).Unix() // 30 seconds in the past (within 60s tolerance)
	proof := makeProof(header, claims, priv)

	gotKid, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err != nil {
		t.Errorf("expected no error for iat within tolerance, got: %v", err)
	}
	if gotKid != kid {
		t.Errorf("expected kid %q, got %q", kid, gotKid)
	}
}

// TestValidatorMethodMismatch tests that htm must match request method.
func TestValidatorMethodMismatch(t *testing.T) {
	t.Log("Testing HTTP method mismatch rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	claims.HTM = "GET" // Proof claims GET
	proof := makeProof(header, claims, priv)

	// But request method is POST
	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for method mismatch")
	}
	if ErrorCode(err) != ErrCodeMethodMismatch {
		t.Errorf("expected error code %s, got %s", ErrCodeMethodMismatch, ErrorCode(err))
	}
}

// TestValidatorURISchemeMismatch tests that htu scheme must match.
func TestValidatorURISchemeMismatch(t *testing.T) {
	t.Log("Testing URI scheme mismatch rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	claims.HTU = "http://example.com/api/push" // HTTP
	proof := makeProof(header, claims, priv)

	// But request is HTTPS
	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for scheme mismatch")
	}
	if ErrorCode(err) != ErrCodeURIMismatch {
		t.Errorf("expected error code %s, got %s", ErrCodeURIMismatch, ErrorCode(err))
	}
}

// TestValidatorURIHostMismatch tests that htu host must match.
func TestValidatorURIHostMismatch(t *testing.T) {
	t.Log("Testing URI host mismatch rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	claims.HTU = "https://other.com/api/push" // Different host
	proof := makeProof(header, claims, priv)

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for host mismatch")
	}
	if ErrorCode(err) != ErrCodeURIMismatch {
		t.Errorf("expected error code %s, got %s", ErrCodeURIMismatch, ErrorCode(err))
	}
}

// TestValidatorURIPathMismatch tests that htu path must match.
func TestValidatorURIPathMismatch(t *testing.T) {
	t.Log("Testing URI path mismatch rejection")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	header := validHeader(kid)
	claims := validClaims()
	claims.HTU = "https://example.com/api/other" // Different path
	proof := makeProof(header, claims, priv)

	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for path mismatch")
	}
	if ErrorCode(err) != ErrCodeURIMismatch {
		t.Errorf("expected error code %s, got %s", ErrCodeURIMismatch, ErrorCode(err))
	}
}

// TestValidatorURINormalization tests URL normalization for htu comparison.
func TestValidatorURINormalization(t *testing.T) {
	t.Log("Testing URL normalization for htu comparison")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	v := NewValidator(DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	tests := []struct {
		name       string
		proofHTU   string
		requestURI string
		shouldPass bool
	}{
		{
			name:       "case insensitive host",
			proofHTU:   "https://example.com/api/push",
			requestURI: "https://EXAMPLE.COM/api/push",
			shouldPass: true,
		},
		{
			name:       "query string ignored",
			proofHTU:   "https://example.com/api/push",
			requestURI: "https://example.com/api/push?q=1",
			shouldPass: true,
		},
		{
			name:       "fragment ignored",
			proofHTU:   "https://example.com/api/push",
			requestURI: "https://example.com/api/push#section",
			shouldPass: true,
		},
		{
			name:       "default https port removed",
			proofHTU:   "https://example.com/api/push",
			requestURI: "https://example.com:443/api/push",
			shouldPass: true,
		},
		{
			name:       "default http port removed",
			proofHTU:   "http://example.com/api/push",
			requestURI: "http://example.com:80/api/push",
			shouldPass: true,
		},
		{
			name:       "non-default port preserved",
			proofHTU:   "https://example.com:8443/api/push",
			requestURI: "https://example.com:8443/api/push",
			shouldPass: true,
		},
		{
			name:       "non-default port mismatch",
			proofHTU:   "https://example.com/api/push",
			requestURI: "https://example.com:8443/api/push",
			shouldPass: false,
		},
		{
			name:       "path case sensitive",
			proofHTU:   "https://example.com/api/Push",
			requestURI: "https://example.com/api/push",
			shouldPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing: proof htu=%q, request uri=%q", tc.proofHTU, tc.requestURI)
			header := validHeader(kid)
			claims := validClaims()
			claims.HTU = tc.proofHTU
			proof := makeProof(header, claims, priv)

			_, err := v.ValidateProof(proof, "POST", tc.requestURI, keyLookup)
			if tc.shouldPass && err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
			if !tc.shouldPass && err == nil {
				t.Error("expected error, got success")
			}
			if !tc.shouldPass && err != nil && ErrorCode(err) != ErrCodeURIMismatch {
				t.Errorf("expected error code %s, got %s", ErrCodeURIMismatch, ErrorCode(err))
			}
		})
	}
}

// TestNormalizeURL tests the URL normalization function directly.
func TestNormalizeURL(t *testing.T) {
	t.Log("Testing URL normalization function")

	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple https",
			input:    "https://example.com/api/push",
			expected: "https://example.com/api/push",
		},
		{
			name:     "uppercase host normalized",
			input:    "https://EXAMPLE.COM/api/push",
			expected: "https://example.com/api/push",
		},
		{
			name:     "uppercase scheme normalized",
			input:    "HTTPS://example.com/api/push",
			expected: "https://example.com/api/push",
		},
		{
			name:     "query removed",
			input:    "https://example.com/api/push?q=1&x=2",
			expected: "https://example.com/api/push",
		},
		{
			name:     "fragment removed",
			input:    "https://example.com/api/push#frag",
			expected: "https://example.com/api/push",
		},
		{
			name:     "default https port removed",
			input:    "https://example.com:443/api",
			expected: "https://example.com/api",
		},
		{
			name:     "default http port removed",
			input:    "http://example.com:80/api",
			expected: "http://example.com/api",
		},
		{
			name:     "non-default port preserved",
			input:    "https://example.com:8443/api",
			expected: "https://example.com:8443/api",
		},
		{
			name:     "complex example",
			input:    "https://EXAMPLE.COM/api/push?q=1#frag",
			expected: "https://example.com/api/push",
		},
		{
			name:    "invalid URL",
			input:   "://invalid",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Normalizing: %q", tc.input)
			result, err := normalizeURL(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

// TestValidatorCustomConfig tests that custom validator config works.
func TestValidatorCustomConfig(t *testing.T) {
	t.Log("Testing custom validator configuration")

	pub, priv := testKeyPair(t)
	kid := "test-key"
	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	// Use a very short clock skew tolerance
	config := ValidatorConfig{
		ClockSkew:   5 * time.Second,
		MaxProofAge: 5 * time.Second,
	}
	v := NewValidator(config)

	header := validHeader(kid)
	claims := validClaims()
	claims.IAT = time.Now().Add(-10 * time.Second).Unix() // 10 seconds ago
	proof := makeProof(header, claims, priv)

	// Should fail with strict tolerance
	_, err := v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err == nil {
		t.Error("expected error for iat outside strict tolerance")
	}
	if ErrorCode(err) != ErrCodeInvalidIAT {
		t.Errorf("expected error code %s, got %s", ErrCodeInvalidIAT, ErrorCode(err))
	}

	// Now with generous tolerance, should pass
	generousConfig := ValidatorConfig{
		ClockSkew:   120 * time.Second,
		MaxProofAge: 120 * time.Second,
	}
	generousValidator := NewValidator(generousConfig)

	gotKid, err := generousValidator.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	if err != nil {
		t.Errorf("expected success with generous tolerance, got: %v", err)
	}
	if gotKid != kid {
		t.Errorf("expected kid %q, got %q", kid, gotKid)
	}
}

// TestDefaultValidatorConfig tests that default config has sensible values.
func TestDefaultValidatorConfig(t *testing.T) {
	t.Log("Testing default validator configuration values")

	config := DefaultValidatorConfig()

	if config.ClockSkew != 60*time.Second {
		t.Errorf("expected ClockSkew 60s, got %v", config.ClockSkew)
	}
	if config.MaxProofAge != 60*time.Second {
		t.Errorf("expected MaxProofAge 60s, got %v", config.MaxProofAge)
	}
}

// BenchmarkValidateProof measures the performance of DPoP proof validation.
func BenchmarkValidateProof(b *testing.B) {
	// Setup: generate key pair and create a valid proof
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key pair: %v", err)
	}
	kid := "bench-key-123"

	header := Header{
		Typ: TypeDPoP,
		Alg: AlgEdDSA,
		Kid: kid,
	}
	claims := Claims{
		JTI: "bench-jti-12345",
		HTM: "POST",
		HTU: "https://example.com/api/push",
		IAT: time.Now().Unix(),
	}
	proof := makeProof(header, claims, priv)

	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	v := NewValidator(DefaultValidatorConfig())

	// Reset timer to exclude setup time
	b.ResetTimer()

	// Run the benchmark
	for i := 0; i < b.N; i++ {
		_, _ = v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	}
}
