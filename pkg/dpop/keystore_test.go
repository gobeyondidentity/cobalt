package dpop

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileKeyStoreSaveAndLoad(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKeyStore save and load round-trip")

	// Create temp directory
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")

	store := NewFileKeyStore(keyPath)

	// Generate a key
	t.Log("Generating Ed25519 keypair")
	_, privKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Save the key
	t.Log("Saving key to file")
	if err := store.Save(privKey); err != nil {
		t.Fatalf("failed to save key: %v", err)
	}

	// Verify file exists
	if !store.Exists() {
		t.Error("key file should exist after save")
	}

	// Verify permissions (Unix only - Windows Mode().Perm() returns 0666 regardless of ACLs)
	if runtime.GOOS != "windows" {
		t.Log("Verifying file permissions are 0600")
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("failed to stat key file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("expected permissions 0600, got %04o", info.Mode().Perm())
		}
	}

	// Load the key
	t.Log("Loading key from file")
	loadedKey, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load key: %v", err)
	}

	// Verify the key matches
	if !privKey.Equal(loadedKey) {
		t.Error("loaded key does not match saved key")
	}

	t.Log("Save and load round-trip successful")
}

func TestFileKeyStoreNotFound(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKeyStore returns ErrKeyNotFound for missing file")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "nonexistent-key.pem")

	store := NewFileKeyStore(keyPath)

	if store.Exists() {
		t.Error("key file should not exist")
	}

	_, err := store.Load()
	if err == nil {
		t.Error("expected error for missing key file")
	}
	if !IsNotFoundError(err) {
		t.Errorf("expected ErrKeyNotFound, got: %v", err)
	}

	t.Log("Missing file correctly returns ErrKeyNotFound")
}

func TestFileKeyStoreInvalidPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based test not applicable on Windows; see permissions_windows_test.go")
	}

	t.Log("Testing FileKeyStore rejects file with 0644 permissions")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "insecure-key.pem")

	// Create a key file with bad permissions
	_, privKey, _ := GenerateKey()
	store := NewFileKeyStore(keyPath)
	store.Save(privKey)

	// Change permissions to 0644 (insecure)
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}

	t.Log("Attempting to load key with 0644 permissions")
	_, err := store.Load()
	if err == nil {
		t.Error("expected error for insecure permissions")
	}
	if !IsPermissionError(err) {
		t.Errorf("expected ErrInvalidPermissions, got: %v", err)
	}

	t.Log("Insecure permissions correctly rejected")
}

func TestFileKeyStoreInvalidPermissions0666(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based test not applicable on Windows; see permissions_windows_test.go")
	}

	t.Log("Testing FileKeyStore rejects file with 0666 permissions")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "world-readable-key.pem")

	_, privKey, _ := GenerateKey()
	store := NewFileKeyStore(keyPath)
	store.Save(privKey)

	// Change permissions to 0666 (world-readable)
	if err := os.Chmod(keyPath, 0666); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}

	t.Log("Attempting to load key with 0666 permissions")
	_, err := store.Load()
	if err == nil {
		t.Error("expected error for world-readable permissions")
	}
	if !IsPermissionError(err) {
		t.Errorf("expected ErrInvalidPermissions, got: %v", err)
	}

	t.Log("World-readable permissions correctly rejected")
}

func TestFileKeyStoreCreatesParentDirectories(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKeyStore creates parent directories")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "nested", "dirs", "key.pem")

	store := NewFileKeyStore(keyPath)

	_, privKey, _ := GenerateKey()

	t.Log("Saving key to nested path")
	if err := store.Save(privKey); err != nil {
		t.Fatalf("failed to save key: %v", err)
	}

	// Verify parent dir permissions (Unix only - Windows Mode().Perm() doesn't reflect ACLs)
	if runtime.GOOS != "windows" {
		parentDir := filepath.Dir(keyPath)
		info, err := os.Stat(parentDir)
		if err != nil {
			t.Fatalf("failed to stat parent dir: %v", err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("expected parent dir permissions 0700, got %04o", info.Mode().Perm())
		}
		t.Log("Parent directories created with correct permissions")
	}
}

func TestFileKIDStoreSaveAndLoad(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKIDStore save and load round-trip")

	tmpDir := t.TempDir()
	kidPath := filepath.Join(tmpDir, "kid")

	store := NewFileKIDStore(kidPath)

	testKID := "km_abc123"

	t.Log("Saving kid to file")
	if err := store.Save(testKID); err != nil {
		t.Fatalf("failed to save kid: %v", err)
	}

	if !store.Exists() {
		t.Error("kid file should exist after save")
	}

	// Verify permissions (Unix only - Windows Mode().Perm() returns 0666 regardless of ACLs)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(kidPath)
		if err != nil {
			t.Fatalf("failed to stat kid file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("expected permissions 0600, got %04o", info.Mode().Perm())
		}
	}

	t.Log("Loading kid from file")
	loadedKID, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load kid: %v", err)
	}

	if loadedKID != testKID {
		t.Errorf("expected kid %q, got %q", testKID, loadedKID)
	}

	t.Log("KID save and load round-trip successful")
}

func TestFileKIDStoreNotFound(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKIDStore returns ErrKIDNotFound for missing file")

	tmpDir := t.TempDir()
	kidPath := filepath.Join(tmpDir, "nonexistent-kid")

	store := NewFileKIDStore(kidPath)

	if store.Exists() {
		t.Error("kid file should not exist")
	}

	_, err := store.Load()
	if err == nil {
		t.Error("expected error for missing kid file")
	}
	if !IsNotFoundError(err) {
		t.Errorf("expected ErrKIDNotFound, got: %v", err)
	}

	t.Log("Missing kid file correctly returns ErrKIDNotFound")
}

func TestFileKIDStoreInvalidPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based test not applicable on Windows; see permissions_windows_test.go")
	}

	t.Log("Testing FileKIDStore rejects file with 0644 permissions")

	tmpDir := t.TempDir()
	kidPath := filepath.Join(tmpDir, "insecure-kid")

	store := NewFileKIDStore(kidPath)
	store.Save("km_test")

	// Change permissions to 0644
	if err := os.Chmod(kidPath, 0644); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}

	t.Log("Attempting to load kid with 0644 permissions")
	_, err := store.Load()
	if err == nil {
		t.Error("expected error for insecure permissions")
	}
	if !IsPermissionError(err) {
		t.Errorf("expected ErrInvalidPermissions, got: %v", err)
	}

	t.Log("Insecure permissions correctly rejected for kid file")
}

func TestDefaultKeyPaths(t *testing.T) {
	t.Parallel()
	t.Log("Testing DefaultKeyPaths returns correct paths")

	tests := []struct {
		clientType    string
		expectKeyDir  string
		expectKIDDir  string
	}{
		{"km", ".km", ".km"},
		{"bluectl", ".bluectl", ".bluectl"},
		{"aegis", "/etc/aegis", "/etc/aegis"},
	}

	homeDir, _ := os.UserHomeDir()

	for _, tc := range tests {
		keyPath, kidPath := DefaultKeyPaths(tc.clientType)

		if tc.clientType == "aegis" {
			if keyPath != "/etc/aegis/key.pem" {
				t.Errorf("aegis key path: expected /etc/aegis/key.pem, got %s", keyPath)
			}
			if kidPath != "/etc/aegis/kid" {
				t.Errorf("aegis kid path: expected /etc/aegis/kid, got %s", kidPath)
			}
		} else {
			expectedKeyPath := filepath.Join(homeDir, tc.expectKeyDir, "key.pem")
			expectedKIDPath := filepath.Join(homeDir, tc.expectKIDDir, "kid")

			if keyPath != expectedKeyPath {
				t.Errorf("%s key path: expected %s, got %s", tc.clientType, expectedKeyPath, keyPath)
			}
			if kidPath != expectedKIDPath {
				t.Errorf("%s kid path: expected %s, got %s", tc.clientType, expectedKIDPath, kidPath)
			}
		}
	}

	t.Log("Default key paths correct for all client types")
}

func TestDefaultKeyPaths_EnvOverride(t *testing.T) {
	t.Parallel()
	t.Log("Testing DefaultKeyPaths respects environment variable overrides")

	// Test aegis override
	t.Run("aegis_override", func(t *testing.T) {
		os.Setenv("AEGIS_KEY_PATH", "/custom/aegis/key.pem")
		os.Setenv("AEGIS_KID_PATH", "/custom/aegis/kid")
		defer func() {
			os.Unsetenv("AEGIS_KEY_PATH")
			os.Unsetenv("AEGIS_KID_PATH")
		}()

		keyPath, kidPath := DefaultKeyPaths("aegis")
		if keyPath != "/custom/aegis/key.pem" {
			t.Errorf("aegis key path override: expected /custom/aegis/key.pem, got %s", keyPath)
		}
		if kidPath != "/custom/aegis/kid" {
			t.Errorf("aegis kid path override: expected /custom/aegis/kid, got %s", kidPath)
		}
	})

	// Test aegis override with only KEY_PATH (KID_PATH should be derived)
	t.Run("aegis_override_derived_kid", func(t *testing.T) {
		os.Setenv("AEGIS_KEY_PATH", "/custom/path/key.pem")
		os.Unsetenv("AEGIS_KID_PATH")
		defer os.Unsetenv("AEGIS_KEY_PATH")

		keyPath, kidPath := DefaultKeyPaths("aegis")
		if keyPath != "/custom/path/key.pem" {
			t.Errorf("aegis key path override: expected /custom/path/key.pem, got %s", keyPath)
		}
		// Derived path uses filepath.Join which returns OS-native separators
		expectedKidPath := filepath.FromSlash("/custom/path/kid")
		if kidPath != expectedKidPath {
			t.Errorf("aegis kid path (derived): expected %s, got %s", expectedKidPath, kidPath)
		}
	})

	// Test bluectl override
	t.Run("bluectl_override", func(t *testing.T) {
		os.Setenv("BLUECTL_KEY_PATH", "/tmp/test/.bluectl/key.pem")
		os.Setenv("BLUECTL_KID_PATH", "/tmp/test/.bluectl/kid")
		defer func() {
			os.Unsetenv("BLUECTL_KEY_PATH")
			os.Unsetenv("BLUECTL_KID_PATH")
		}()

		keyPath, kidPath := DefaultKeyPaths("bluectl")
		if keyPath != "/tmp/test/.bluectl/key.pem" {
			t.Errorf("bluectl key path override: expected /tmp/test/.bluectl/key.pem, got %s", keyPath)
		}
		if kidPath != "/tmp/test/.bluectl/kid" {
			t.Errorf("bluectl kid path override: expected /tmp/test/.bluectl/kid, got %s", kidPath)
		}
	})

	// Test km override
	t.Run("km_override", func(t *testing.T) {
		os.Setenv("KM_KEY_PATH", "/var/lib/km/key.pem")
		os.Setenv("KM_KID_PATH", "/var/lib/km/kid")
		defer func() {
			os.Unsetenv("KM_KEY_PATH")
			os.Unsetenv("KM_KID_PATH")
		}()

		keyPath, kidPath := DefaultKeyPaths("km")
		if keyPath != "/var/lib/km/key.pem" {
			t.Errorf("km key path override: expected /var/lib/km/key.pem, got %s", keyPath)
		}
		if kidPath != "/var/lib/km/kid" {
			t.Errorf("km kid path override: expected /var/lib/km/kid, got %s", kidPath)
		}
	})

	t.Log("Environment variable overrides work correctly")
}

func TestGenerateKey(t *testing.T) {
	t.Parallel()
	t.Log("Testing GenerateKey creates valid Ed25519 keypair")

	pubKey, privKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Verify sizes
	if len(pubKey) != ed25519.PublicKeySize {
		t.Errorf("public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubKey))
	}
	if len(privKey) != ed25519.PrivateKeySize {
		t.Errorf("private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privKey))
	}

	// Verify they work together (sign and verify)
	message := []byte("test message")
	signature := ed25519.Sign(privKey, message)

	if !ed25519.Verify(pubKey, message, signature) {
		t.Error("generated keypair failed sign/verify test")
	}

	t.Log("Generated keypair is valid")
}

func TestFileKeyStoreRoundTrip(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKeyStore round-trip: generate, save, load")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "seed-key.pem")

	// Create and save a key
	_, privKey, _ := GenerateKey()

	store := NewFileKeyStore(keyPath)
	if err := store.Save(privKey); err != nil {
		t.Fatalf("failed to save key: %v", err)
	}

	loadedKey, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load key: %v", err)
	}

	if !privKey.Equal(loadedKey) {
		t.Error("loaded key does not match original")
	}

	t.Log("Round-trip successful")
}

func TestFileKeyStoreInvalidPEM(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKeyStore rejects invalid PEM data")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid.pem")

	// Write invalid data
	if err := os.WriteFile(keyPath, []byte("not valid pem data"), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	// Set permissions so permission check passes, allowing format check to run
	if err := setFilePermissions(keyPath); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	store := NewFileKeyStore(keyPath)
	_, err := store.Load()
	if err == nil {
		t.Error("expected error for invalid PEM data")
	}

	t.Log("Invalid PEM data correctly rejected")
}

func TestFileKeyStoreWrongKeyType(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKeyStore rejects wrong key type")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrong-type.pem")

	// Write a PEM block with wrong type
	pemData := `-----BEGIN RSA PRIVATE KEY-----
dGVzdCBkYXRh
-----END RSA PRIVATE KEY-----
`
	if err := os.WriteFile(keyPath, []byte(pemData), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	// Set permissions so permission check passes, allowing format check to run
	if err := setFilePermissions(keyPath); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	store := NewFileKeyStore(keyPath)
	_, err := store.Load()
	if err == nil {
		t.Error("expected error for wrong key type")
	}

	t.Log("Wrong key type correctly rejected")
}

func TestCheckFilePermissions(t *testing.T) {
	t.Parallel()
	t.Log("Testing CheckFilePermissions utility function")

	tmpDir := t.TempDir()

	// Test correct permissions
	goodPath := filepath.Join(tmpDir, "good")
	os.WriteFile(goodPath, []byte("test"), 0600)
	// On Windows, we need to explicitly set restrictive DACL
	if err := setFilePermissions(goodPath); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	if err := CheckFilePermissions(goodPath); err != nil {
		t.Errorf("expected no error for properly secured file, got: %v", err)
	}

	// Test incorrect permissions (Unix-specific test using chmod)
	if runtime.GOOS != "windows" {
		badPath := filepath.Join(tmpDir, "bad")
		os.WriteFile(badPath, []byte("test"), 0644)

		if err := CheckFilePermissions(badPath); err == nil {
			t.Error("expected error for 0644 permissions")
		}
	}

	// Test nonexistent file
	if err := CheckFilePermissions(filepath.Join(tmpDir, "nonexistent")); err == nil {
		t.Error("expected error for nonexistent file")
	}

	t.Log("CheckFilePermissions works correctly")
}

// =============================================================================
// Rejection Tests: Verify Load() only accepts what Save() writes
// =============================================================================

func TestFileKeyStoreRejects64ByteRawKey(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKeyStore rejects 64-byte raw key (only accepts 32-byte seed)")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "raw64.pem")

	// Create a 64-byte key (full private key format)
	_, privKey, _ := GenerateKey()

	// Write as ED25519 PRIVATE KEY but with 64 bytes instead of 32
	pemData := "-----BEGIN ED25519 PRIVATE KEY-----\n" +
		base64Encode(privKey) + "\n" +
		"-----END ED25519 PRIVATE KEY-----\n"

	if err := os.WriteFile(keyPath, []byte(pemData), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	// Set permissions so permission check passes, allowing format check to run
	if err := setFilePermissions(keyPath); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	store := NewFileKeyStore(keyPath)
	_, err := store.Load()
	if err == nil {
		t.Fatal("expected error for 64-byte key, got nil")
	}
	if !errors.Is(err, ErrInvalidKeyFormat) {
		t.Errorf("expected ErrInvalidKeyFormat, got: %v", err)
	}
	t.Logf("64-byte raw key correctly rejected: %v", err)
}

func TestFileKeyStoreRejectsPKCS8Format(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKeyStore rejects PKCS8 format (PRIVATE KEY PEM type)")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "pkcs8.pem")

	// Write a PEM block with PRIVATE KEY type (PKCS8 style)
	// Content doesn't matter since we reject based on PEM type
	pemData := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHKJh6YGZoSkOl9hn7Nit8y7NbmOAUx2zGzW1lq3klqZ
-----END PRIVATE KEY-----
`
	if err := os.WriteFile(keyPath, []byte(pemData), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	// Set permissions so permission check passes, allowing format check to run
	if err := setFilePermissions(keyPath); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	store := NewFileKeyStore(keyPath)
	_, err := store.Load()
	if err == nil {
		t.Fatal("expected error for PKCS8 format, got nil")
	}
	if !errors.Is(err, ErrInvalidKeyFormat) {
		t.Errorf("expected ErrInvalidKeyFormat, got: %v", err)
	}
	t.Logf("PKCS8 format correctly rejected: %v", err)
}

func TestFileKeyStoreRejectsWrongSizeSeed(t *testing.T) {
	t.Parallel()
	t.Log("Testing FileKeyStore rejects wrong size seeds (31 and 33 bytes)")

	tmpDir := t.TempDir()

	tests := []struct {
		name string
		size int
	}{
		{"31 bytes (too small)", 31},
		{"33 bytes (too large)", 33},
		{"16 bytes (way too small)", 16},
		{"64 bytes (full key, not seed)", 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyPath := filepath.Join(tmpDir, "wrong-size.pem")

			// Create wrong-sized data
			wrongSizeData := make([]byte, tc.size)
			for i := range wrongSizeData {
				wrongSizeData[i] = byte(i)
			}

			pemData := "-----BEGIN ED25519 PRIVATE KEY-----\n" +
				base64Encode(wrongSizeData) + "\n" +
				"-----END ED25519 PRIVATE KEY-----\n"

			if err := os.WriteFile(keyPath, []byte(pemData), 0600); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}
			// Set permissions so permission check passes, allowing format check to run
			if err := setFilePermissions(keyPath); err != nil {
				t.Fatalf("failed to set permissions: %v", err)
			}

			store := NewFileKeyStore(keyPath)
			_, err := store.Load()
			if err == nil {
				t.Fatalf("expected error for %d-byte content, got nil", tc.size)
			}
			if !errors.Is(err, ErrInvalidKeyFormat) {
				t.Errorf("expected ErrInvalidKeyFormat, got: %v", err)
			}
			t.Logf("%s correctly rejected: %v", tc.name, err)
		})
	}
}

// base64Encode is a helper for tests
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
