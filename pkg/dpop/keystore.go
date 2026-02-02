package dpop

import (
	"crypto/ed25519"
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
	// Deprecated: Use KeyNotFoundError for errors with path information.
	ErrKeyNotFound = errors.New("key not found")

	// ErrInvalidPermissions indicates the key file has insecure permissions.
	// On Unix: file mode must be 0600
	// On Windows: file must not be accessible to Everyone, Users, or Authenticated Users
	ErrInvalidPermissions = errors.New("insecure file permissions: file accessible to other users")

	// ErrInvalidKeyFormat indicates the key file is not in the expected format.
	ErrInvalidKeyFormat = errors.New("invalid key format: expected ED25519 PRIVATE KEY PEM with 32-byte seed")

	// ErrKIDNotFound indicates the kid does not exist in storage.
	ErrKIDNotFound = errors.New("kid not found")
)

// KeyNotFoundError indicates the key does not exist at the specified path.
type KeyNotFoundError struct {
	Path string
}

func (e *KeyNotFoundError) Error() string {
	return fmt.Sprintf("key not found at %s", e.Path)
}

// Is allows errors.Is to match against ErrKeyNotFound for backward compatibility.
func (e *KeyNotFoundError) Is(target error) bool {
	return target == ErrKeyNotFound
}

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
// Returns KeyNotFoundError if the file doesn't exist.
// Returns ErrInvalidPermissions if the file is accessible to other users.
func (s *FileKeyStore) Load() (ed25519.PrivateKey, error) {
	// Check if file exists
	_, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return nil, &KeyNotFoundError{Path: s.path}
	}
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}

	// Check permissions (platform-specific)
	if err := checkFilePermissions(s.path); err != nil {
		return nil, err
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

	// Only accept ED25519 PRIVATE KEY type (what Save() writes)
	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("%w: got PEM type %q", ErrInvalidKeyFormat, block.Type)
	}

	// Only accept 32-byte seed (what Save() writes)
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeyFormat, len(block.Bytes))
	}

	return ed25519.NewKeyFromSeed(block.Bytes), nil
}

// Save saves the private key to the file with owner-only permissions.
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

	// Write file (0600 on Unix, default on Windows)
	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	// Set proper permissions (platform-specific)
	if err := setFilePermissions(s.path); err != nil {
		return fmt.Errorf("set key file permissions: %w", err)
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
	_, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return "", ErrKIDNotFound
	}
	if err != nil {
		return "", fmt.Errorf("stat kid file: %w", err)
	}

	// Check permissions (platform-specific)
	if err := checkFilePermissions(s.path); err != nil {
		return "", err
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return "", fmt.Errorf("read kid file: %w", err)
	}

	return string(data), nil
}

// Save saves the kid to the file with owner-only permissions.
func (s *FileKIDStore) Save(kid string) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create kid directory: %w", err)
	}

	// Write file (0600 on Unix, default on Windows)
	if err := os.WriteFile(s.path, []byte(kid), 0600); err != nil {
		return fmt.Errorf("write kid file: %w", err)
	}

	// Set proper permissions (platform-specific)
	if err := setFilePermissions(s.path); err != nil {
		return fmt.Errorf("set kid file permissions: %w", err)
	}

	return nil
}

// Exists returns true if the kid file exists.
func (s *FileKIDStore) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// CheckFilePermissions verifies a file has owner-only access.
// On Unix: file mode must be 0600
// On Windows: file must not be accessible to Everyone, Users, or Authenticated Users
// Returns nil if permissions are correct, error otherwise.
func CheckFilePermissions(path string) error {
	return checkFilePermissions(path)
}

// DefaultKeyPaths returns the default key and kid paths for each client type.
// Environment variables can override defaults (useful for testing):
//   - AEGIS_KEY_PATH, AEGIS_KID_PATH
//   - BLUECTL_KEY_PATH, BLUECTL_KID_PATH
//   - KM_KEY_PATH, KM_KID_PATH
func DefaultKeyPaths(clientType string) (keyPath, kidPath string) {
	// Check for environment variable overrides (useful for testing)
	switch clientType {
	case "aegis":
		if env := os.Getenv("AEGIS_KEY_PATH"); env != "" {
			kidEnv := os.Getenv("AEGIS_KID_PATH")
			if kidEnv == "" {
				kidEnv = filepath.Join(filepath.Dir(env), "kid")
			}
			return env, kidEnv
		}
	case "bluectl":
		if env := os.Getenv("BLUECTL_KEY_PATH"); env != "" {
			kidEnv := os.Getenv("BLUECTL_KID_PATH")
			if kidEnv == "" {
				kidEnv = filepath.Join(filepath.Dir(env), "kid")
			}
			return env, kidEnv
		}
	case "km":
		if env := os.Getenv("KM_KEY_PATH"); env != "" {
			kidEnv := os.Getenv("KM_KID_PATH")
			if kidEnv == "" {
				kidEnv = filepath.Join(filepath.Dir(env), "kid")
			}
			return env, kidEnv
		}
	}

	// Fall back to platform defaults
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
