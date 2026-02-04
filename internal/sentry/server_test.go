package sentry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	hostv1 "github.com/gobeyondidentity/cobalt/gen/go/host/v1"
)

// Test SSH keys (real format, generated for testing)
// endorctl:allow -- Test fixture: SSH public keys for unit tests, not real credentials
const (
	testEd25519Key1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl root@server"
	testEd25519Key2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@laptop"
	testEd25519Key3 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl bob@desktop"
	testEd25519Key4 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl bob@laptop"
)

func TestServer_ScanSSHKeys_withKeys(t *testing.T) {
	// Create temp directory structure simulating /home
	tmpDir := t.TempDir()
	rootSSH := filepath.Join(tmpDir, "root", ".ssh")
	user1SSH := filepath.Join(tmpDir, "home", "alice", ".ssh")
	user2SSH := filepath.Join(tmpDir, "home", "bob", ".ssh")

	// Create directory structure
	for _, dir := range []string{rootSSH, user1SSH, user2SSH} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatalf("MkdirAll %s: %v", dir, err)
		}
	}

	// Write authorized_keys files with valid SSH keys
	rootKey := testEd25519Key1 + "\n"
	aliceKey := testEd25519Key2 + "\n"
	bobKeys := testEd25519Key3 + "\n" +
		"# comment line\n" +
		testEd25519Key4 + "\n"

	if err := os.WriteFile(filepath.Join(rootSSH, "authorized_keys"), []byte(rootKey), 0600); err != nil {
		t.Fatalf("write root authorized_keys: %v", err)
	}
	if err := os.WriteFile(filepath.Join(user1SSH, "authorized_keys"), []byte(aliceKey), 0600); err != nil {
		t.Fatalf("write alice authorized_keys: %v", err)
	}
	if err := os.WriteFile(filepath.Join(user2SSH, "authorized_keys"), []byte(bobKeys), 0600); err != nil {
		t.Fatalf("write bob authorized_keys: %v", err)
	}

	// Create server with custom paths
	srv := NewServer(&Config{})
	srv.rootSSHPath = filepath.Join(tmpDir, "root", ".ssh", "authorized_keys")
	srv.homeGlobPattern = filepath.Join(tmpDir, "home", "*", ".ssh", "authorized_keys")

	// Call ScanSSHKeys
	resp, err := srv.ScanSSHKeys(context.Background(), &hostv1.ScanSSHKeysRequest{})
	if err != nil {
		t.Fatalf("ScanSSHKeys failed: %v", err)
	}

	// Verify response structure
	if resp == nil {
		t.Fatal("response is nil")
	}
	if resp.ScannedAt == "" {
		t.Error("ScannedAt should not be empty")
	}

	// Verify timestamp is RFC3339
	_, err = time.Parse(time.RFC3339, resp.ScannedAt)
	if err != nil {
		t.Errorf("ScannedAt is not RFC3339: %v", err)
	}

	// Verify we found keys (4 total: 1 root, 1 alice, 2 bob)
	if len(resp.Keys) != 4 {
		t.Errorf("expected 4 keys, got %d", len(resp.Keys))
	}

	// Build a map by user for easier verification
	keysByUser := make(map[string][]*hostv1.SSHKey)
	for _, k := range resp.Keys {
		keysByUser[k.User] = append(keysByUser[k.User], k)
	}

	// Verify root key
	if len(keysByUser["root"]) != 1 {
		t.Errorf("expected 1 root key, got %d", len(keysByUser["root"]))
	}

	// Verify alice key
	if len(keysByUser["alice"]) != 1 {
		t.Errorf("expected 1 alice key, got %d", len(keysByUser["alice"]))
	}

	// Verify bob keys
	if len(keysByUser["bob"]) != 2 {
		t.Errorf("expected 2 bob keys, got %d", len(keysByUser["bob"]))
	}

	// Verify key fields are populated
	for _, k := range resp.Keys {
		if k.KeyType == "" {
			t.Error("KeyType should not be empty")
		}
		if k.Fingerprint == "" {
			t.Error("Fingerprint should not be empty")
		}
		if k.FilePath == "" {
			t.Error("FilePath should not be empty")
		}
		if k.User == "" {
			t.Error("User should not be empty")
		}
	}
}

func TestServer_ScanSSHKeys_noKeys(t *testing.T) {
	// Create temp directory with no authorized_keys files
	tmpDir := t.TempDir()

	srv := NewServer(&Config{})
	srv.rootSSHPath = filepath.Join(tmpDir, "root", ".ssh", "authorized_keys")
	srv.homeGlobPattern = filepath.Join(tmpDir, "home", "*", ".ssh", "authorized_keys")

	resp, err := srv.ScanSSHKeys(context.Background(), &hostv1.ScanSSHKeysRequest{})
	if err != nil {
		t.Fatalf("ScanSSHKeys failed: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	if len(resp.Keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(resp.Keys))
	}
	if resp.ScannedAt == "" {
		t.Error("ScannedAt should not be empty even with no keys")
	}
}

func TestServer_ScanSSHKeys_emptyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	rootSSH := filepath.Join(tmpDir, "root", ".ssh")

	if err := os.MkdirAll(rootSSH, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Create empty authorized_keys file
	if err := os.WriteFile(filepath.Join(rootSSH, "authorized_keys"), []byte(""), 0600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}

	srv := NewServer(&Config{})
	srv.rootSSHPath = filepath.Join(tmpDir, "root", ".ssh", "authorized_keys")
	srv.homeGlobPattern = filepath.Join(tmpDir, "home", "*", ".ssh", "authorized_keys")

	resp, err := srv.ScanSSHKeys(context.Background(), &hostv1.ScanSSHKeysRequest{})
	if err != nil {
		t.Fatalf("ScanSSHKeys failed: %v", err)
	}

	if len(resp.Keys) != 0 {
		t.Errorf("expected 0 keys for empty file, got %d", len(resp.Keys))
	}
}

func TestServer_ScanSSHKeys_onlyComments(t *testing.T) {
	tmpDir := t.TempDir()
	rootSSH := filepath.Join(tmpDir, "root", ".ssh")

	if err := os.MkdirAll(rootSSH, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Create authorized_keys with only comments
	content := "# This is a comment\n# Another comment\n\n"
	if err := os.WriteFile(filepath.Join(rootSSH, "authorized_keys"), []byte(content), 0600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}

	srv := NewServer(&Config{})
	srv.rootSSHPath = filepath.Join(tmpDir, "root", ".ssh", "authorized_keys")
	srv.homeGlobPattern = filepath.Join(tmpDir, "home", "*", ".ssh", "authorized_keys")

	resp, err := srv.ScanSSHKeys(context.Background(), &hostv1.ScanSSHKeysRequest{})
	if err != nil {
		t.Fatalf("ScanSSHKeys failed: %v", err)
	}

	if len(resp.Keys) != 0 {
		t.Errorf("expected 0 keys for comment-only file, got %d", len(resp.Keys))
	}
}

func TestServer_ScanSSHKeys_unreadableFile(t *testing.T) {
	// Skip if running as root (can read any file)
	if os.Getuid() == 0 {
		t.Skip("skipping test when running as root")
	}

	tmpDir := t.TempDir()
	rootSSH := filepath.Join(tmpDir, "root", ".ssh")
	userSSH := filepath.Join(tmpDir, "home", "alice", ".ssh")

	if err := os.MkdirAll(rootSSH, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(userSSH, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Create a readable key file
	aliceKey := testEd25519Key2 + "\n"
	if err := os.WriteFile(filepath.Join(userSSH, "authorized_keys"), []byte(aliceKey), 0600); err != nil {
		t.Fatalf("write alice authorized_keys: %v", err)
	}

	// Create an unreadable key file
	rootKeyPath := filepath.Join(rootSSH, "authorized_keys")
	if err := os.WriteFile(rootKeyPath, []byte("ssh-ed25519 key"), 0000); err != nil {
		t.Fatalf("write root authorized_keys: %v", err)
	}

	srv := NewServer(&Config{})
	srv.rootSSHPath = rootKeyPath
	srv.homeGlobPattern = filepath.Join(tmpDir, "home", "*", ".ssh", "authorized_keys")

	// Should not fail, just skip unreadable files
	resp, err := srv.ScanSSHKeys(context.Background(), &hostv1.ScanSSHKeysRequest{})
	if err != nil {
		t.Fatalf("ScanSSHKeys failed: %v", err)
	}

	// Should still get Alice's key
	if len(resp.Keys) != 1 {
		t.Errorf("expected 1 key (alice), got %d", len(resp.Keys))
	}
}
