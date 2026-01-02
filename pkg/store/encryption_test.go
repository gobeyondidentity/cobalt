// Package store provides SQLite-based storage for DPU registry.
package store

import (
	"os"
	"testing"
)

func TestSetInsecureMode(t *testing.T) {
	// Reset state after test
	defer func() {
		insecureModeAllowed = false
	}()

	// Default should be false
	if InsecureModeAllowed() {
		t.Error("insecureModeAllowed should be false by default")
	}

	// Set to true
	SetInsecureMode(true)
	if !InsecureModeAllowed() {
		t.Error("insecureModeAllowed should be true after SetInsecureMode(true)")
	}

	// Set back to false
	SetInsecureMode(false)
	if InsecureModeAllowed() {
		t.Error("insecureModeAllowed should be false after SetInsecureMode(false)")
	}
}

func TestEncryptPrivateKey_WithKeySet(t *testing.T) {
	// Set encryption key
	os.Setenv(envKeyName, "test-encryption-key")
	defer os.Unsetenv(envKeyName)

	plaintext := []byte("secret private key data")
	ciphertext, err := EncryptPrivateKey(plaintext)
	if err != nil {
		t.Fatalf("EncryptPrivateKey failed: %v", err)
	}

	// Ciphertext should be different from plaintext (encrypted)
	if string(ciphertext) == string(plaintext) {
		t.Error("ciphertext should be different from plaintext when key is set")
	}

	// Ciphertext should be longer (nonce + overhead)
	if len(ciphertext) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext due to nonce and auth tag")
	}
}

func TestEncryptPrivateKey_NoKey_InsecureModeOff(t *testing.T) {
	// Ensure no encryption key
	os.Unsetenv(envKeyName)

	// Reset insecure mode
	defer func() {
		insecureModeAllowed = false
	}()
	SetInsecureMode(false)

	plaintext := []byte("secret private key data")
	_, err := EncryptPrivateKey(plaintext)
	if err == nil {
		t.Fatal("EncryptPrivateKey should return error when key not set and insecure mode off")
	}
	if err != ErrNoEncryptionKey {
		t.Errorf("expected ErrNoEncryptionKey, got: %v", err)
	}
}

func TestEncryptPrivateKey_NoKey_InsecureModeOn(t *testing.T) {
	// Ensure no encryption key
	os.Unsetenv(envKeyName)

	// Enable insecure mode
	defer func() {
		insecureModeAllowed = false
	}()
	SetInsecureMode(true)

	plaintext := []byte("secret private key data")
	result, err := EncryptPrivateKey(plaintext)
	if err != nil {
		t.Fatalf("EncryptPrivateKey should not error in insecure mode: %v", err)
	}

	// Should return plaintext as-is
	if string(result) != string(plaintext) {
		t.Error("EncryptPrivateKey should return plaintext in insecure mode")
	}
}

func TestDecryptPrivateKey_WithKeySet(t *testing.T) {
	// Set encryption key
	os.Setenv(envKeyName, "test-encryption-key")
	defer os.Unsetenv(envKeyName)

	originalPlaintext := []byte("secret private key data")

	// Encrypt first
	ciphertext, err := EncryptPrivateKey(originalPlaintext)
	if err != nil {
		t.Fatalf("EncryptPrivateKey failed: %v", err)
	}

	// Decrypt
	decrypted, err := DecryptPrivateKey(ciphertext)
	if err != nil {
		t.Fatalf("DecryptPrivateKey failed: %v", err)
	}

	if string(decrypted) != string(originalPlaintext) {
		t.Error("decrypted data should match original plaintext")
	}
}

func TestDecryptPrivateKey_NoKey_InsecureModeOff(t *testing.T) {
	// Ensure no encryption key
	os.Unsetenv(envKeyName)

	// Reset insecure mode
	defer func() {
		insecureModeAllowed = false
	}()
	SetInsecureMode(false)

	ciphertext := []byte("some data that might be plaintext or ciphertext")
	_, err := DecryptPrivateKey(ciphertext)
	if err == nil {
		t.Fatal("DecryptPrivateKey should return error when key not set and insecure mode off")
	}
	if err != ErrNoEncryptionKey {
		t.Errorf("expected ErrNoEncryptionKey, got: %v", err)
	}
}

func TestDecryptPrivateKey_NoKey_InsecureModeOn(t *testing.T) {
	// Ensure no encryption key
	os.Unsetenv(envKeyName)

	// Enable insecure mode
	defer func() {
		insecureModeAllowed = false
	}()
	SetInsecureMode(true)

	plaintext := []byte("plaintext data stored without encryption")
	result, err := DecryptPrivateKey(plaintext)
	if err != nil {
		t.Fatalf("DecryptPrivateKey should not error in insecure mode: %v", err)
	}

	// Should return data as-is
	if string(result) != string(plaintext) {
		t.Error("DecryptPrivateKey should return data as-is in insecure mode")
	}
}

func TestDecryptPrivateKey_TooShort(t *testing.T) {
	// Set encryption key so we try real decryption
	os.Setenv(envKeyName, "test-encryption-key")
	defer os.Unsetenv(envKeyName)

	// Data shorter than nonce size (12 bytes)
	shortData := []byte("short")
	_, err := DecryptPrivateKey(shortData)
	if err == nil {
		t.Fatal("DecryptPrivateKey should fail with data shorter than nonce size")
	}
}

func TestRoundTrip_Encrypted(t *testing.T) {
	// Set encryption key
	os.Setenv(envKeyName, "test-encryption-key-for-roundtrip")
	defer os.Unsetenv(envKeyName)

	testCases := [][]byte{
		[]byte("short"),
		[]byte("a longer piece of private key data that spans multiple blocks"),
		[]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}, // binary data
		make([]byte, 4096),                          // larger data
	}

	for i, plaintext := range testCases {
		ciphertext, err := EncryptPrivateKey(plaintext)
		if err != nil {
			t.Fatalf("case %d: encrypt failed: %v", i, err)
		}

		decrypted, err := DecryptPrivateKey(ciphertext)
		if err != nil {
			t.Fatalf("case %d: decrypt failed: %v", i, err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("case %d: roundtrip failed, data mismatch", i)
		}
	}
}

func TestIsEncryptionEnabled_Encryption(t *testing.T) {
	// Without key
	os.Unsetenv(envKeyName)
	if IsEncryptionEnabled() {
		t.Error("IsEncryptionEnabled should return false when key not set")
	}

	// With key
	os.Setenv(envKeyName, "test-key")
	defer os.Unsetenv(envKeyName)
	if !IsEncryptionEnabled() {
		t.Error("IsEncryptionEnabled should return true when key is set")
	}
}
