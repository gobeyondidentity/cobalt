// Package store provides SQLite-based storage for DPU registry.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

const (
	// envKeyName is the environment variable containing the master encryption key.
	envKeyName = "SECURE_INFRA_KEY"
	// nonceSize is the size of the GCM nonce (12 bytes is standard for AES-GCM).
	nonceSize = 12
)

var (
	// ErrNoEncryptionKey indicates the encryption key environment variable is not set.
	ErrNoEncryptionKey = errors.New("SECURE_INFRA_KEY environment variable not set")
	// devModeWarningOnce ensures the dev mode warning is only logged once.
	devModeWarningOnce sync.Once
)

// deriveKey derives a 32-byte AES-256 key from the SECURE_INFRA_KEY environment variable
// using SHA-256 hash.
func deriveKey() ([]byte, bool) {
	keyStr := os.Getenv(envKeyName)
	if keyStr == "" {
		return nil, false
	}
	hash := sha256.Sum256([]byte(keyStr))
	return hash[:], true
}

// EncryptPrivateKey encrypts a private key using AES-256-GCM.
// The master key is derived from the SECURE_INFRA_KEY environment variable.
// If the environment variable is not set, returns plaintext with a logged warning (dev mode).
//
// Encryption format: nonce (12 bytes) || ciphertext
func EncryptPrivateKey(plaintext []byte) ([]byte, error) {
	key, ok := deriveKey()
	if !ok {
		devModeWarningOnce.Do(func() {
			log.Printf("WARNING: %s not set, private keys stored in plaintext (dev mode)", envKeyName)
		})
		return plaintext, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptPrivateKey decrypts a private key that was encrypted with EncryptPrivateKey.
// If SECURE_INFRA_KEY is not set, assumes plaintext was stored (dev mode) and returns as-is.
//
// Expected format: nonce (12 bytes) || ciphertext
func DecryptPrivateKey(ciphertext []byte) ([]byte, error) {
	key, ok := deriveKey()
	if !ok {
		devModeWarningOnce.Do(func() {
			log.Printf("WARNING: %s not set, assuming plaintext private keys (dev mode)", envKeyName)
		})
		return ciphertext, nil
	}

	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := ciphertext[:nonceSize]
	encryptedData := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// IsEncryptionEnabled returns true if SECURE_INFRA_KEY is set and encryption is active.
func IsEncryptionEnabled() bool {
	_, ok := deriveKey()
	return ok
}
