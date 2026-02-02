package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestNewKeyStore(t *testing.T) {
	t.Log("Testing NewKeyStore creates a valid keystore instance")
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "keystore.json")

	ks, err := NewKeyStore(path)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}
	if ks == nil {
		t.Fatal("NewKeyStore() returned nil")
	}
	if ks.path != path {
		t.Errorf("path = %q, want %q", ks.path, path)
	}
}

func TestNewKeyStore_LoadsExisting(t *testing.T) {
	t.Log("Testing NewKeyStore loads existing keys from file")
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "keystore.json")

	t.Log("Creating keystore file with pre-existing key")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	fp := Fingerprint(pub)
	data := map[string][]byte{fp: pub}
	jsonData, _ := json.Marshal(data)
	if err := os.WriteFile(path, jsonData, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Load the keystore
	ks, err := NewKeyStore(path)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	// Verify key was loaded
	if !ks.IsKnown(pub) {
		t.Error("existing key should be known after load")
	}
}

func TestKeyStore_Register(t *testing.T) {
	t.Log("Testing KeyStore.Register adds key and persists to file")
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "keystore.json")

	ks, err := NewKeyStore(path)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Register the key
	if err := ks.Register(pub); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Key should now be known
	if !ks.IsKnown(pub) {
		t.Error("key should be known after registration")
	}

	// Verify it was persisted to file
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var stored map[string][]byte
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	fp := Fingerprint(pub)
	if _, ok := stored[fp]; !ok {
		t.Errorf("key not found in persisted data with fingerprint %s", fp)
	}
}

func TestKeyStore_IsKnown(t *testing.T) {
	t.Log("Testing KeyStore.IsKnown correctly identifies registered vs unregistered keys")
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "keystore.json")

	ks, err := NewKeyStore(path)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	// Neither key is known initially
	if ks.IsKnown(pub1) {
		t.Error("pub1 should not be known initially")
	}
	if ks.IsKnown(pub2) {
		t.Error("pub2 should not be known initially")
	}

	// Register pub1
	if err := ks.Register(pub1); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// pub1 is known, pub2 is not
	if !ks.IsKnown(pub1) {
		t.Error("pub1 should be known after registration")
	}
	if ks.IsKnown(pub2) {
		t.Error("pub2 should not be known")
	}
}

func TestKeyStore_Verify(t *testing.T) {
	t.Log("Testing KeyStore.Verify returns correct status for registered and unregistered keys")
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "keystore.json")

	ks, err := NewKeyStore(path)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Register the key
	if err := ks.Register(pub); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Verify returns true for registered key
	if !ks.Verify(pub) {
		t.Error("Verify() should return true for registered key")
	}

	// Verify returns false for unregistered key
	if ks.Verify(otherPub) {
		t.Error("Verify() should return false for unregistered key")
	}
}

func TestFingerprint(t *testing.T) {
	t.Log("Testing Fingerprint produces consistent SHA256 hex hashes of public keys")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	fp := Fingerprint(pub)

	t.Log("Verifying fingerprint is consistent for same key")
	if fp != Fingerprint(pub) {
		t.Error("Fingerprint() should return consistent results")
	}

	// Fingerprint should be a 64-character hex string (SHA256 = 32 bytes = 64 hex chars)
	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fp))
	}

	// Different keys should have different fingerprints
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if fp == Fingerprint(pub2) {
		t.Error("different keys should have different fingerprints")
	}
}

func TestKeyStore_ConcurrentAccess(t *testing.T) {
	t.Log("Testing KeyStore is safe for concurrent registration and verification")
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "keystore.json")

	ks, err := NewKeyStore(path)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	// Generate multiple keys
	keys := make([]ed25519.PublicKey, 10)
	for i := range keys {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		keys[i] = pub
	}

	// Concurrent registration and verification
	var wg sync.WaitGroup
	for i := range keys {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := ks.Register(keys[idx]); err != nil {
				t.Errorf("Register() error = %v", err)
			}
		}(i)
	}
	wg.Wait()

	// Verify all keys are known
	for i, key := range keys {
		if !ks.IsKnown(key) {
			t.Errorf("key %d should be known after concurrent registration", i)
		}
	}
}

func TestKeyStore_DirectoryCreation(t *testing.T) {
	t.Log("Testing KeyStore creates nested directories for keystore path")
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "subdir", "deep", "keystore.json")

	ks, err := NewKeyStore(path)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := ks.Register(pub); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Verify directory was created
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestKeyStore_FilePermissions(t *testing.T) {
	t.Log("Testing KeyStore file is created with 0600 permissions (Unix only)")
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "keystore.json")

	ks, err := NewKeyStore(path)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := ks.Register(pub); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Verify file permissions (should be 0600)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	// Windows Mode().Perm() returns 0666 regardless of ACLs
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestKeyStore_RegisterDuplicate(t *testing.T) {
	t.Log("Testing KeyStore.Register is idempotent for duplicate key registration")
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "keystore.json")

	ks, err := NewKeyStore(path)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// First registration should succeed
	if err := ks.Register(pub); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}

	// Second registration of same key should be idempotent (no error)
	if err := ks.Register(pub); err != nil {
		t.Fatalf("duplicate Register() should not error, got: %v", err)
	}
}
