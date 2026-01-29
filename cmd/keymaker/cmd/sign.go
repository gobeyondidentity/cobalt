package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// jwtHeader is the standard JWT header for Ed25519 signing.
type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// jwtClaims represents the JWT claims for km authentication.
type jwtClaims struct {
	KeyMakerID string `json:"kid"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
	Nonce      string `json:"nonce"`
}

const (
	// jwtValidity is the validity duration for generated JWTs (5 minutes).
	jwtValidity = 5 * time.Minute
)

// signRequest adds a JWT Bearer token to an HTTP request.
// Header: Authorization: Bearer <jwt>
// JWT format: header.claims.signature (base64url encoded)
func signRequest(req *http.Request, config *KMConfig, body []byte) error {
	// Load private key
	privateKey, err := loadPrivateKey(config.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Generate JWT
	token, err := generateJWT(config.KeyMakerID, privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Add Authorization header
	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

// generateJWT creates a signed JWT token for the given KeyMaker ID.
func generateJWT(keyMakerID string, privateKey ed25519.PrivateKey) (string, error) {
	// Create header
	header := jwtHeader{
		Algorithm: "EdDSA",
		Type:      "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Generate nonce (16 random bytes as hex)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	// Create claims
	now := time.Now()
	claims := jwtClaims{
		KeyMakerID: keyMakerID,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(jwtValidity).Unix(),
		Nonce:      nonce,
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Sign header.claims
	signedData := []byte(headerB64 + "." + claimsB64)
	signature := ed25519.Sign(privateKey, signedData)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Return JWT: header.claims.signature
	return headerB64 + "." + claimsB64 + "." + signatureB64, nil
}

// loadPrivateKey reads an Ed25519 private key from the given path.
// The file should contain a raw 64-byte Ed25519 private key.
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(data))
	}

	return ed25519.PrivateKey(data), nil
}
