package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
)

// signRequest adds authentication headers to an HTTP request.
// Headers added:
//   - X-KM-ID: KeyMaker ID
//   - X-KM-Signature: Base64-encoded Ed25519 signature of request body
func signRequest(req *http.Request, config *KMConfig, body []byte) error {
	// Load private key
	privateKey, err := loadPrivateKey(config.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Sign the request body
	signature := ed25519.Sign(privateKey, body)

	// Add headers
	req.Header.Set("X-KM-ID", config.KeyMakerID)
	req.Header.Set("X-KM-Signature", base64.StdEncoding.EncodeToString(signature))

	return nil
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
