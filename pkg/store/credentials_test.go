package store

import (
	"bytes"
	"os"
	"testing"
)

// TestSSHCACRUD tests basic CRUD operations for SSH CAs.
func TestSSHCACRUD(t *testing.T) {
	// Enable insecure mode for test (no encryption key set)
	SetInsecureMode(true)
	defer SetInsecureMode(false)

	store := setupTestStore(t)

	testPublicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample test@example.com")
	testPrivateKey := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntest-private-key-data\n-----END OPENSSH PRIVATE KEY-----")

	// Test CreateSSHCA
	t.Run("CreateSSHCA", func(t *testing.T) {
		err := store.CreateSSHCA("ca1", "test-ca", testPublicKey, testPrivateKey, "ed25519", nil)
		if err != nil {
			t.Fatalf("CreateSSHCA failed: %v", err)
		}
	})

	// Test GetSSHCA
	t.Run("GetSSHCA", func(t *testing.T) {
		ca, err := store.GetSSHCA("test-ca")
		if err != nil {
			t.Fatalf("GetSSHCA failed: %v", err)
		}
		if ca.ID != "ca1" {
			t.Errorf("expected ID 'ca1', got '%s'", ca.ID)
		}
		if ca.Name != "test-ca" {
			t.Errorf("expected name 'test-ca', got '%s'", ca.Name)
		}
		if !bytes.Equal(ca.PublicKey, testPublicKey) {
			t.Errorf("public key mismatch")
		}
		if !bytes.Equal(ca.PrivateKey, testPrivateKey) {
			t.Errorf("private key mismatch after round-trip")
		}
		if ca.KeyType != "ed25519" {
			t.Errorf("expected key_type 'ed25519', got '%s'", ca.KeyType)
		}
	})

	// Test GetSSHCAByID
	t.Run("GetSSHCAByID", func(t *testing.T) {
		ca, err := store.GetSSHCAByID("ca1")
		if err != nil {
			t.Fatalf("GetSSHCAByID failed: %v", err)
		}
		if ca.Name != "test-ca" {
			t.Errorf("expected name 'test-ca', got '%s'", ca.Name)
		}
	})

	// Test CreateSSHCA duplicate name
	t.Run("CreateSSHCA_DuplicateName", func(t *testing.T) {
		err := store.CreateSSHCA("ca2", "test-ca", testPublicKey, testPrivateKey, "ed25519", nil)
		if err == nil {
			t.Error("expected error for duplicate name, got nil")
		}
	})

	// Test GetSSHCA not found
	t.Run("GetSSHCA_NotFound", func(t *testing.T) {
		_, err := store.GetSSHCA("nonexistent")
		if err == nil {
			t.Error("expected error for nonexistent CA, got nil")
		}
	})

	// Test SSHCAExists
	t.Run("SSHCAExists", func(t *testing.T) {
		exists, err := store.SSHCAExists("test-ca")
		if err != nil {
			t.Fatalf("SSHCAExists failed: %v", err)
		}
		if !exists {
			t.Error("expected test-ca to exist")
		}

		exists, err = store.SSHCAExists("nonexistent")
		if err != nil {
			t.Fatalf("SSHCAExists failed: %v", err)
		}
		if exists {
			t.Error("expected nonexistent to not exist")
		}
	})

	// Test ListSSHCAs
	t.Run("ListSSHCAs", func(t *testing.T) {
		// Add another CA
		err := store.CreateSSHCA("ca2", "another-ca", testPublicKey, testPrivateKey, "rsa", nil)
		if err != nil {
			t.Fatalf("CreateSSHCA failed: %v", err)
		}

		cas, err := store.ListSSHCAs()
		if err != nil {
			t.Fatalf("ListSSHCAs failed: %v", err)
		}
		if len(cas) != 2 {
			t.Errorf("expected 2 CAs, got %d", len(cas))
		}

		// Verify private keys are not included in list
		for _, ca := range cas {
			if ca.PrivateKey != nil {
				t.Error("expected nil private key in list result")
			}
		}
	})

	// Test DeleteSSHCA
	t.Run("DeleteSSHCA", func(t *testing.T) {
		err := store.DeleteSSHCA("another-ca")
		if err != nil {
			t.Fatalf("DeleteSSHCA failed: %v", err)
		}

		cas, _ := store.ListSSHCAs()
		if len(cas) != 1 {
			t.Errorf("expected 1 CA after deletion, got %d", len(cas))
		}
	})

	// Test DeleteSSHCA not found
	t.Run("DeleteSSHCA_NotFound", func(t *testing.T) {
		err := store.DeleteSSHCA("nonexistent")
		if err == nil {
			t.Error("expected error for deleting nonexistent CA, got nil")
		}
	})

	// Test DeleteSSHCAByID
	t.Run("DeleteSSHCAByID", func(t *testing.T) {
		// Create a new CA to delete by ID
		err := store.CreateSSHCA("ca3", "delete-by-id-ca", testPublicKey, testPrivateKey, "ed25519", nil)
		if err != nil {
			t.Fatalf("CreateSSHCA failed: %v", err)
		}

		err = store.DeleteSSHCAByID("ca3")
		if err != nil {
			t.Fatalf("DeleteSSHCAByID failed: %v", err)
		}

		_, err = store.GetSSHCAByID("ca3")
		if err == nil {
			t.Error("expected error for deleted CA, got nil")
		}
	})
}

// TestEncryptionWithKey tests encryption/decryption with SECURE_INFRA_KEY set.
func TestEncryptionWithKey(t *testing.T) {
	// Set encryption key
	oldKey := os.Getenv("SECURE_INFRA_KEY")
	os.Setenv("SECURE_INFRA_KEY", "test-encryption-key-12345")
	defer func() {
		if oldKey == "" {
			os.Unsetenv("SECURE_INFRA_KEY")
		} else {
			os.Setenv("SECURE_INFRA_KEY", oldKey)
		}
	}()

	testData := []byte("sensitive-private-key-data")

	// Test encryption
	encrypted, err := EncryptPrivateKey(testData)
	if err != nil {
		t.Fatalf("EncryptPrivateKey failed: %v", err)
	}

	// Encrypted data should be different from plaintext
	if bytes.Equal(encrypted, testData) {
		t.Error("encrypted data should differ from plaintext")
	}

	// Encrypted data should be longer (nonce + ciphertext + auth tag)
	if len(encrypted) <= len(testData) {
		t.Error("encrypted data should be longer than plaintext")
	}

	// Test decryption
	decrypted, err := DecryptPrivateKey(encrypted)
	if err != nil {
		t.Fatalf("DecryptPrivateKey failed: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Error("decrypted data should match original plaintext")
	}
}

// TestEncryptionWithoutKey tests behavior when SECURE_INFRA_KEY is not set with insecure mode enabled.
func TestEncryptionWithoutKey(t *testing.T) {
	// Ensure no encryption key is set
	oldKey := os.Getenv("SECURE_INFRA_KEY")
	os.Unsetenv("SECURE_INFRA_KEY")
	defer func() {
		if oldKey != "" {
			os.Setenv("SECURE_INFRA_KEY", oldKey)
		}
	}()

	// Enable insecure mode for plaintext fallback
	SetInsecureMode(true)
	defer SetInsecureMode(false)

	testData := []byte("sensitive-private-key-data")

	// Without key but with insecure mode, encryption should return plaintext
	encrypted, err := EncryptPrivateKey(testData)
	if err != nil {
		t.Fatalf("EncryptPrivateKey failed: %v", err)
	}

	if !bytes.Equal(encrypted, testData) {
		t.Error("without encryption key in insecure mode, data should be returned as-is")
	}

	// Without key but with insecure mode, decryption should also return as-is
	decrypted, err := DecryptPrivateKey(testData)
	if err != nil {
		t.Fatalf("DecryptPrivateKey failed: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Error("without encryption key in insecure mode, data should be returned as-is")
	}
}

// TestIsEncryptionEnabled tests the encryption status check.
func TestIsEncryptionEnabled(t *testing.T) {
	oldKey := os.Getenv("SECURE_INFRA_KEY")
	defer func() {
		if oldKey != "" {
			os.Setenv("SECURE_INFRA_KEY", oldKey)
		} else {
			os.Unsetenv("SECURE_INFRA_KEY")
		}
	}()

	// Test with key unset
	os.Unsetenv("SECURE_INFRA_KEY")
	if IsEncryptionEnabled() {
		t.Error("expected encryption to be disabled without key")
	}

	// Test with key set
	os.Setenv("SECURE_INFRA_KEY", "test-key")
	if !IsEncryptionEnabled() {
		t.Error("expected encryption to be enabled with key")
	}
}

// TestSSHCARoundTripWithEncryption tests full round-trip with encryption enabled.
func TestSSHCARoundTripWithEncryption(t *testing.T) {
	// Set encryption key
	oldKey := os.Getenv("SECURE_INFRA_KEY")
	os.Setenv("SECURE_INFRA_KEY", "test-encryption-key-roundtrip")
	defer func() {
		if oldKey == "" {
			os.Unsetenv("SECURE_INFRA_KEY")
		} else {
			os.Setenv("SECURE_INFRA_KEY", oldKey)
		}
	}()

	store := setupTestStore(t)

	testPublicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample test@example.com")
	testPrivateKey := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nencrypted-test-private-key-data\n-----END OPENSSH PRIVATE KEY-----")

	// Create CA with encryption enabled
	err := store.CreateSSHCA("encrypted-ca", "encrypted-test-ca", testPublicKey, testPrivateKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("CreateSSHCA failed: %v", err)
	}

	// Retrieve and verify decryption
	ca, err := store.GetSSHCA("encrypted-test-ca")
	if err != nil {
		t.Fatalf("GetSSHCA failed: %v", err)
	}

	if !bytes.Equal(ca.PrivateKey, testPrivateKey) {
		t.Error("private key should match after round-trip with encryption")
	}
	if !bytes.Equal(ca.PublicKey, testPublicKey) {
		t.Error("public key should match after round-trip")
	}
}

// TestDecryptionWithWrongKey tests that decryption fails with wrong key.
func TestDecryptionWithWrongKey(t *testing.T) {
	// Set encryption key
	oldKey := os.Getenv("SECURE_INFRA_KEY")
	os.Setenv("SECURE_INFRA_KEY", "correct-key")
	defer func() {
		if oldKey == "" {
			os.Unsetenv("SECURE_INFRA_KEY")
		} else {
			os.Setenv("SECURE_INFRA_KEY", oldKey)
		}
	}()

	testData := []byte("sensitive-data")
	encrypted, err := EncryptPrivateKey(testData)
	if err != nil {
		t.Fatalf("EncryptPrivateKey failed: %v", err)
	}

	// Change key and try to decrypt
	os.Setenv("SECURE_INFRA_KEY", "wrong-key")
	_, err = DecryptPrivateKey(encrypted)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

// TestDecryptShortCiphertext tests handling of malformed ciphertext.
func TestDecryptShortCiphertext(t *testing.T) {
	oldKey := os.Getenv("SECURE_INFRA_KEY")
	os.Setenv("SECURE_INFRA_KEY", "test-key")
	defer func() {
		if oldKey == "" {
			os.Unsetenv("SECURE_INFRA_KEY")
		} else {
			os.Setenv("SECURE_INFRA_KEY", oldKey)
		}
	}()

	// Ciphertext shorter than nonce size should fail
	shortData := []byte("short")
	_, err := DecryptPrivateKey(shortData)
	if err == nil {
		t.Error("expected error for ciphertext shorter than nonce size")
	}
}
