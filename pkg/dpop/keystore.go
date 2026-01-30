package dpop

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// KeyStore provides access to cryptographic keys for DPoP proof generation.
// Implementations must be safe for concurrent use.
type KeyStore interface {
	// Load loads the private key from storage.
	// Returns an error if the key doesn't exist or cannot be loaded.
	Load() (ed25519.PrivateKey, error)

	// Save saves a private key to storage.
	// Returns an error if the key cannot be saved.
	Save(key ed25519.PrivateKey) error

	// Exists returns true if a key exists in storage.
	Exists() bool

	// Path returns the storage path (for display purposes).
	Path() string
}

// KIDStore provides storage for the server-assigned key ID.
type KIDStore interface {
	// Load loads the kid from storage.
	Load() (string, error)

	// Save saves the kid to storage.
	Save(kid string) error

	// Exists returns true if a kid exists in storage.
	Exists() bool
}

var (
	// ErrKeyNotFound indicates the key does not exist in storage.
	ErrKeyNotFound = errors.New("key not found")

	// ErrInvalidPermissions indicates the key file has insecure permissions.
	ErrInvalidPermissions = errors.New("insecure file permissions: must be 0600")

	// ErrInvalidKeyFormat indicates the key file is not valid PEM-encoded Ed25519.
	ErrInvalidKeyFormat = errors.New("invalid key format: expected PEM-encoded Ed25519 private key")

	// ErrKIDNotFound indicates the kid does not exist in storage.
	ErrKIDNotFound = errors.New("kid not found")
)

// FileKeyStore stores Ed25519 private keys in PEM-encoded files.
// It enforces 0600 permissions to protect key confidentiality.
type FileKeyStore struct {
	path string
}

// NewFileKeyStore creates a new file-based key store.
func NewFileKeyStore(path string) *FileKeyStore {
	return &FileKeyStore{path: path}
}

// Load loads the private key from the file.
// Returns ErrKeyNotFound if the file doesn't exist.
// Returns ErrInvalidPermissions if the file has permissions other than 0600.
func (s *FileKeyStore) Load() (ed25519.PrivateKey, error) {
	// Check if file exists
	info, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}

	// Check permissions (Unix only, skip on Windows)
	mode := info.Mode().Perm()
	if mode != 0600 {
		return nil, fmt.Errorf("%w: got %04o, want 0600", ErrInvalidPermissions, mode)
	}

	// Read file
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	// Parse PEM
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidKeyFormat
	}

	// Expect PRIVATE KEY type (PKCS8) or ED25519 PRIVATE KEY
	if block.Type != "PRIVATE KEY" && block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("%w: unexpected PEM type %q", ErrInvalidKeyFormat, block.Type)
	}

	// Parse the key bytes
	// Ed25519 private key is 64 bytes (32 seed + 32 public)
	// or 32 bytes (seed only, need to derive)
	keyBytes := block.Bytes

	switch len(keyBytes) {
	case ed25519.PrivateKeySize: // 64 bytes - full private key
		return ed25519.PrivateKey(keyBytes), nil
	case ed25519.SeedSize: // 32 bytes - seed only
		return ed25519.NewKeyFromSeed(keyBytes), nil
	default:
		// Try PKCS8 format using proper ASN.1 parsing
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKeyFormat, err)
		}
		ed25519Key, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: not an Ed25519 key", ErrInvalidKeyFormat)
		}
		return ed25519Key, nil
	}
}

// Save saves the private key to the file with 0600 permissions.
// Creates parent directories if they don't exist.
func (s *FileKeyStore) Save(key ed25519.PrivateKey) error {
	// Create parent directory
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	// Encode as PEM
	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: key.Seed(), // Store just the seed (32 bytes)
	}
	data := pem.EncodeToMemory(block)

	// Write with restricted permissions
	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	return nil
}

// Exists returns true if the key file exists.
func (s *FileKeyStore) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Path returns the file path.
func (s *FileKeyStore) Path() string {
	return s.path
}

// FileKIDStore stores the server-assigned kid in a file.
type FileKIDStore struct {
	path string
}

// NewFileKIDStore creates a new file-based kid store.
func NewFileKIDStore(path string) *FileKIDStore {
	return &FileKIDStore{path: path}
}

// Load loads the kid from the file.
func (s *FileKIDStore) Load() (string, error) {
	// Check if file exists
	info, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return "", ErrKIDNotFound
	}
	if err != nil {
		return "", fmt.Errorf("stat kid file: %w", err)
	}

	// Check permissions
	mode := info.Mode().Perm()
	if mode != 0600 {
		return "", fmt.Errorf("%w: got %04o, want 0600", ErrInvalidPermissions, mode)
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return "", fmt.Errorf("read kid file: %w", err)
	}

	return string(data), nil
}

// Save saves the kid to the file with 0600 permissions.
func (s *FileKIDStore) Save(kid string) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create kid directory: %w", err)
	}

	if err := os.WriteFile(s.path, []byte(kid), 0600); err != nil {
		return fmt.Errorf("write kid file: %w", err)
	}

	return nil
}

// Exists returns true if the kid file exists.
func (s *FileKIDStore) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// CheckFilePermissions verifies a file has 0600 permissions.
// Returns nil if permissions are correct, error otherwise.
func CheckFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		return fmt.Errorf("%w: got %04o, want 0600", ErrInvalidPermissions, mode)
	}

	return nil
}

// DefaultKeyPaths returns the default key and kid paths for each client type.
func DefaultKeyPaths(clientType string) (keyPath, kidPath string) {
	homeDir, _ := os.UserHomeDir()

	switch clientType {
	case "km":
		return filepath.Join(homeDir, ".km", "key.pem"),
			filepath.Join(homeDir, ".km", "kid")
	case "bluectl":
		return filepath.Join(homeDir, ".bluectl", "key.pem"),
			filepath.Join(homeDir, ".bluectl", "kid")
	case "aegis":
		return "/etc/aegis/key.pem", "/etc/aegis/kid"
	default:
		return "", ""
	}
}

// GenerateKey generates a new Ed25519 keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	return pub, priv, nil
}

// Ensure interfaces are implemented
var (
	_ KeyStore = (*FileKeyStore)(nil)
	_ KIDStore = (*FileKIDStore)(nil)
)

// IsPermissionError returns true if the error is due to invalid permissions.
func IsPermissionError(err error) bool {
	return errors.Is(err, ErrInvalidPermissions)
}

// IsNotFoundError returns true if the error is due to missing key/kid.
func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrKeyNotFound) || errors.Is(err, ErrKIDNotFound) || errors.Is(err, fs.ErrNotExist)
}
