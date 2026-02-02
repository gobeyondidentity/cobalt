package dpop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()
	t.Log("Generating Ed25519 key pair")
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	t.Log("Verifying key lengths")
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}

	t.Log("Verifying key pair correspondence via signature")
	message := []byte("test message")
	sig := ed25519.Sign(priv, message)
	if !ed25519.Verify(pub, message, sig) {
		t.Error("generated key pair signature verification failed")
	}
}

func TestGenerateKeyPairUniqueness(t *testing.T) {
	t.Parallel()
	t.Log("Generating 1000 key pairs to verify uniqueness")
	seen := make(map[string]bool)

	for i := 0; i < 1000; i++ {
		pub, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair iteration %d failed: %v", i, err)
		}

		fp := KeyFingerprint(pub)
		if seen[fp] {
			t.Fatalf("duplicate fingerprint at iteration %d: %s", i, fp)
		}
		seen[fp] = true
	}
	t.Log("All 1000 keys are unique")
}

func TestKeyFingerprintSameKey(t *testing.T) {
	t.Parallel()
	t.Log("Verifying same key produces same fingerprint")
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	fp1 := KeyFingerprint(pub)
	fp2 := KeyFingerprint(pub)

	if fp1 != fp2 {
		t.Errorf("same key produced different fingerprints: %q vs %q", fp1, fp2)
	}
	t.Logf("Fingerprint: %s", fp1)
}

func TestKeyFingerprintDifferentKeys(t *testing.T) {
	t.Parallel()
	t.Log("Verifying different keys produce different fingerprints")
	pub1, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pub2, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	fp1 := KeyFingerprint(pub1)
	fp2 := KeyFingerprint(pub2)

	if fp1 == fp2 {
		t.Errorf("different keys produced same fingerprint: %q", fp1)
	}
	t.Logf("Fingerprint 1: %s", fp1)
	t.Logf("Fingerprint 2: %s", fp2)
}

func TestKeyFingerprintFormat(t *testing.T) {
	t.Parallel()
	t.Log("Verifying fingerprint is 64-character hex (SHA256)")
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	fp := KeyFingerprint(pub)
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(fp))
	}

	// Should be lowercase hex
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("fingerprint contains non-hex character: %c", c)
		}
	}
	t.Logf("Fingerprint: %s", fp)
}

func TestLoadPrivateKeyPEMValid(t *testing.T) {
	t.Parallel()
	t.Log("Loading valid Ed25519 private key from PEM")
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Marshal to PKCS8 PEM
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(priv))
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	})

	t.Log("Parsing PEM data")
	loadedPriv, err := LoadPrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM failed: %v", err)
	}

	t.Log("Verifying loaded key matches original")
	if !bytes.Equal(loadedPriv, priv) {
		t.Error("loaded private key does not match original")
	}

	// Verify the loaded key can sign correctly
	t.Log("Verifying loaded key can create valid signatures")
	message := []byte("test")
	sig := ed25519.Sign(loadedPriv, message)
	if !ed25519.Verify(pub, message, sig) {
		t.Error("loaded private key signature verification failed")
	}
}

func TestLoadPrivateKeyPEMRejectsRSA(t *testing.T) {
	t.Parallel()
	t.Log("Rejecting RSA private key in Ed25519 loader")

	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA key generation failed: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	})

	_, err = LoadPrivateKeyPEM(pemData)
	if err == nil {
		t.Fatal("LoadPrivateKeyPEM should reject RSA key")
	}

	t.Logf("Rejection error: %v", err)
	if !strings.Contains(err.Error(), "Ed25519") && !strings.Contains(err.Error(), "ed25519") {
		t.Error("error message should mention Ed25519")
	}
}

func TestLoadPrivateKeyPEMRejectsECDSA(t *testing.T) {
	t.Parallel()
	t.Log("Rejecting ECDSA P-256 private key in Ed25519 loader")

	// Generate ECDSA P-256 key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ECDSA key generation failed: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	})

	_, err = LoadPrivateKeyPEM(pemData)
	if err == nil {
		t.Fatal("LoadPrivateKeyPEM should reject ECDSA key")
	}

	t.Logf("Rejection error: %v", err)
	if !strings.Contains(err.Error(), "Ed25519") && !strings.Contains(err.Error(), "ed25519") {
		t.Error("error message should mention Ed25519")
	}
}

func TestLoadPublicKeyPEMValid(t *testing.T) {
	t.Parallel()
	t.Log("Loading valid Ed25519 public key from PEM")
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Marshal to PKIX PEM
	pkix, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey failed: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkix,
	})

	t.Log("Parsing PEM data")
	loadedPub, err := LoadPublicKeyPEM(pemData)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM failed: %v", err)
	}

	t.Log("Verifying loaded key matches original")
	if !bytes.Equal(loadedPub, pub) {
		t.Error("loaded public key does not match original")
	}
}

func TestLoadPublicKeyPEMRejectsRSA(t *testing.T) {
	t.Parallel()
	t.Log("Rejecting RSA public key in Ed25519 loader")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA key generation failed: %v", err)
	}

	pkix, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey failed: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkix,
	})

	_, err = LoadPublicKeyPEM(pemData)
	if err == nil {
		t.Fatal("LoadPublicKeyPEM should reject RSA key")
	}

	t.Logf("Rejection error: %v", err)
}

func TestLoadPublicKeyPEMRejectsECDSA(t *testing.T) {
	t.Parallel()
	t.Log("Rejecting ECDSA P-256 public key in Ed25519 loader")

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ECDSA key generation failed: %v", err)
	}

	pkix, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey failed: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkix,
	})

	_, err = LoadPublicKeyPEM(pemData)
	if err == nil {
		t.Fatal("LoadPublicKeyPEM should reject ECDSA key")
	}

	t.Logf("Rejection error: %v", err)
}

func TestPublicKeyToJWKAndBack(t *testing.T) {
	t.Parallel()
	t.Log("Testing JWK round-trip: public key -> JWK -> public key")
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	t.Log("Converting public key to JWK")
	jwk := PublicKeyToJWK(pub)

	if jwk.Kty != "OKP" {
		t.Errorf("JWK.Kty = %q, want OKP", jwk.Kty)
	}
	if jwk.Crv != "Ed25519" {
		t.Errorf("JWK.Crv = %q, want Ed25519", jwk.Crv)
	}
	if jwk.X == "" {
		t.Error("JWK.X should not be empty")
	}
	t.Logf("JWK.X = %s", jwk.X)

	t.Log("Converting JWK back to public key")
	recovered, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatalf("JWKToPublicKey failed: %v", err)
	}

	t.Log("Verifying recovered key matches original byte-for-byte")
	if !bytes.Equal(recovered, pub) {
		t.Errorf("recovered key does not match original:\n  original:  %x\n  recovered: %x", pub, recovered)
	}
}

func TestJWKToPublicKeyRejectsWrongKty(t *testing.T) {
	t.Parallel()
	t.Log("Rejecting JWK with wrong kty")

	tests := []struct {
		kty string
	}{
		{"RSA"},
		{"EC"},
		{"oct"},
		{""},
	}

	for _, tt := range tests {
		t.Run(tt.kty, func(t *testing.T) {
			t.Parallel()
			jwk := &JWK{
				Kty: tt.kty,
				Crv: "Ed25519",
				X:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			}

			_, err := JWKToPublicKey(jwk)
			if err == nil {
				t.Errorf("JWKToPublicKey should reject kty=%q", tt.kty)
			}
			t.Logf("Rejection error for kty=%q: %v", tt.kty, err)
		})
	}
}

func TestJWKToPublicKeyRejectsWrongCrv(t *testing.T) {
	t.Parallel()
	t.Log("Rejecting JWK with wrong crv")

	tests := []struct {
		crv string
	}{
		{"P-256"},
		{"P-384"},
		{"P-521"},
		{"secp256k1"},
		{"Ed448"},
		{""},
	}

	for _, tt := range tests {
		t.Run(tt.crv, func(t *testing.T) {
			t.Parallel()
			jwk := &JWK{
				Kty: "OKP",
				Crv: tt.crv,
				X:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			}

			_, err := JWKToPublicKey(jwk)
			if err == nil {
				t.Errorf("JWKToPublicKey should reject crv=%q", tt.crv)
			}
			t.Logf("Rejection error for crv=%q: %v", tt.crv, err)
		})
	}
}

func TestJWKToPublicKeyRejectsInvalidBase64(t *testing.T) {
	t.Parallel()
	t.Log("Rejecting JWK with invalid base64url in X")

	jwk := &JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   "not valid base64!!!",
	}

	_, err := JWKToPublicKey(jwk)
	if err == nil {
		t.Error("JWKToPublicKey should reject invalid base64url")
	}
	t.Logf("Rejection error: %v", err)
}

func TestJWKToPublicKeyRejectsWrongKeyLength(t *testing.T) {
	t.Parallel()
	t.Log("Rejecting JWK with wrong key length")

	// Only 16 bytes instead of 32
	jwk := &JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   "AAAAAAAAAAAAAAAAAAAAAA==", // 16 bytes
	}

	_, err := JWKToPublicKey(jwk)
	if err == nil {
		t.Error("JWKToPublicKey should reject wrong key length")
	}
	t.Logf("Rejection error: %v", err)
}

func TestMalformedPEMHandling(t *testing.T) {
	t.Parallel()
	t.Log("Testing graceful handling of malformed PEM data")

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"garbage", []byte("not pem data at all")},
		{"truncated", []byte("-----BEGIN PRIVATE KEY-----\nAAAA")},
		{"wrong header", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")},
	}

	for _, tt := range tests {
		t.Run("private_"+tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadPrivateKeyPEM(tt.data)
			if err == nil {
				t.Error("LoadPrivateKeyPEM should return error for malformed PEM")
			}
			t.Logf("Error: %v", err)
		})

		t.Run("public_"+tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadPublicKeyPEM(tt.data)
			if err == nil {
				t.Error("LoadPublicKeyPEM should return error for malformed PEM")
			}
			t.Logf("Error: %v", err)
		})
	}
}

func TestErrorMessagesNoPrivateKeyMaterial(t *testing.T) {
	t.Parallel()
	t.Log("Verifying error messages do not contain private key material")

	// Generate a key and create intentionally malformed PEM
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create PEM with wrong type (will fail parsing but error shouldn't leak key)
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE", // Wrong type
		Bytes: priv,          // Contains private key bytes
	})

	_, loadErr := LoadPrivateKeyPEM(badPEM)
	if loadErr == nil {
		t.Fatal("expected error for wrong PEM type")
	}

	errMsg := loadErr.Error()
	privHex := string(priv)

	// Error message should not contain raw key bytes
	if strings.Contains(errMsg, privHex) {
		t.Error("error message contains raw private key bytes")
	}
	if len(errMsg) > 200 {
		t.Errorf("error message suspiciously long (%d chars), may contain key material", len(errMsg))
	}
	t.Logf("Error message: %s", errMsg)
}
