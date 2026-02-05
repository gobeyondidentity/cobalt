package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	// insecureModeAllowed controls whether plaintext storage is permitted.
	// Default is false; must be explicitly enabled via SetInsecureMode(true).
	// Uses atomic.Bool for safe concurrent access from parallel tests.
	insecureModeAllowed atomic.Bool
)

// SetInsecureMode enables or disables insecure mode (plaintext key storage).
// When enabled, encryption functions will return plaintext if no encryption key is set.
// This should only be used for development/testing.
func SetInsecureMode(allowed bool) {
	insecureModeAllowed.Store(allowed)
}

// InsecureModeAllowed returns whether insecure mode (plaintext storage) is enabled.
func InsecureModeAllowed() bool {
	return insecureModeAllowed.Load()
}

// DefaultKeyPath returns the default path for the auto-generated encryption key file,
// following XDG Base Directory spec.
// Uses the CLI name set via SetCLIName (defaults to "bluectl").
func DefaultKeyPath() string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, _ := os.UserHomeDir()
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, cliName, "key")
}

// LoadOrGenerateKey loads the encryption key from file or generates a new one.
// Priority:
//  1. Environment variable SECURE_INFRA_KEY (always takes precedence)
//  2. Key file at the specified path
//  3. Generate new key and save to file
//
// Returns the key string (either from env, file, or newly generated).
func LoadOrGenerateKey(keyPath string) (string, error) {
	// Check env var first (override)
	if keyStr := os.Getenv(envKeyName); keyStr != "" {
		return keyStr, nil
	}

	// Try to read existing key file
	data, err := os.ReadFile(keyPath)
	if err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// File doesn't exist, generate new key
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}

	// Generate 32 random bytes
	keyBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	// Hex-encode to 64 character string
	keyStr := hex.EncodeToString(keyBytes)

	// Create parent directory with 0700 permissions
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create key directory: %w", err)
	}

	// Write key file with 0600 permissions
	if err := os.WriteFile(keyPath, []byte(keyStr), 0600); err != nil {
		return "", fmt.Errorf("failed to write key file: %w", err)
	}

	log.Printf("Generated new encryption key at %s", keyPath)
	return keyStr, nil
}

// deriveKey derives a 32-byte AES-256 key from the encryption key
// using SHA-256 hash. It first tries to load or generate a key.
func deriveKey() ([]byte, bool) {
	keyStr, err := LoadOrGenerateKey(DefaultKeyPath())
	if err != nil {
		// Log error but don't expose details
		log.Printf("Warning: could not load or generate encryption key: %v", err)
		return nil, false
	}
	if keyStr == "" {
		return nil, false
	}
	hash := sha256.Sum256([]byte(keyStr))
	return hash[:], true
}

// EncryptPrivateKey encrypts a private key using AES-256-GCM.
// The master key is derived from the SECURE_INFRA_KEY environment variable.
//
// If SECURE_INFRA_KEY is not set:
//   - If insecure mode is enabled (via SetInsecureMode), returns plaintext
//   - Otherwise, returns ErrNoEncryptionKey
//
// Encryption format: nonce (12 bytes) || ciphertext
func EncryptPrivateKey(plaintext []byte) ([]byte, error) {
	key, ok := deriveKey()
	if !ok {
		if insecureModeAllowed.Load() {
			return plaintext, nil
		}
		return nil, ErrNoEncryptionKey
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
//
// If SECURE_INFRA_KEY is not set:
//   - If insecure mode is enabled (via SetInsecureMode), returns data as-is (plaintext)
//   - Otherwise, returns ErrNoEncryptionKey
//
// Expected format: nonce (12 bytes) || ciphertext
func DecryptPrivateKey(ciphertext []byte) ([]byte, error) {
	key, ok := deriveKey()
	if !ok {
		if insecureModeAllowed.Load() {
			return ciphertext, nil
		}
		return nil, ErrNoEncryptionKey
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
