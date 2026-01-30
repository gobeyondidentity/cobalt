package dpop

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// GenerateKeyPair generates a new Ed25519 key pair using cryptographically
// secure random number generation.
//
// Returns the public key (32 bytes) and private key (64 bytes).
// Uses crypto/rand for secure entropy; never uses math/rand.
func GenerateKeyPair() (publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// KeyFingerprint computes the SHA256 fingerprint of an Ed25519 public key.
// Returns a lowercase hex string (64 characters).
//
// This fingerprint is used for key identification and deduplication.
// The same key always produces the same fingerprint.
func KeyFingerprint(publicKey ed25519.PublicKey) string {
	hash := sha256.Sum256(publicKey)
	return hex.EncodeToString(hash[:])
}

// LoadPrivateKeyPEM parses an Ed25519 private key from PEM-encoded data.
// Accepts PKCS#8 format ("PRIVATE KEY" block).
//
// Returns an error if the PEM is malformed or contains a non-Ed25519 key.
// Error messages never contain key material.
func LoadPrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block: no valid PEM data found")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM block type %q, expected PRIVATE KEY", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519: only Ed25519 keys are supported")
	}

	return ed25519Key, nil
}

// LoadPublicKeyPEM parses an Ed25519 public key from PEM-encoded data.
// Accepts PKIX format ("PUBLIC KEY" block).
//
// Returns an error if the PEM is malformed or contains a non-Ed25519 key.
func LoadPublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block: no valid PEM data found")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM block type %q, expected PUBLIC KEY", block.Type)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	ed25519Key, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519: only Ed25519 keys are supported")
	}

	return ed25519Key, nil
}

// PublicKeyToJWK converts an Ed25519 public key to JWK format.
// The resulting JWK can be embedded in DPoP proof headers for enrollment.
//
// JWK fields:
//   - kty: "OKP" (Octet Key Pair, per RFC 8037)
//   - crv: "Ed25519"
//   - x: base64url-encoded public key bytes
func PublicKeyToJWK(publicKey ed25519.PublicKey) *JWK {
	return &JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(publicKey),
	}
}

// JWKToPublicKey converts a JWK to an Ed25519 public key.
// Performs strict validation of kty and crv fields.
//
// Returns an error if:
//   - kty is not "OKP"
//   - crv is not "Ed25519"
//   - X is not valid base64url
//   - decoded key length is not 32 bytes
func JWKToPublicKey(jwk *JWK) (ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" {
		return nil, fmt.Errorf("invalid JWK: kty must be OKP, got %q", jwk.Kty)
	}

	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("invalid JWK: crv must be Ed25519, got %q", jwk.Crv)
	}

	keyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK: failed to decode X parameter: %w", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid JWK: X parameter has wrong length %d, expected %d", len(keyBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(keyBytes), nil
}
