package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// mockAddr implements net.Addr for testing
type mockAddr struct {
	network string
	addr    string
}

func (m mockAddr) Network() string { return m.network }
func (m mockAddr) String() string  { return m.addr }

// testRemoteAddr returns a mock net.Addr for testing
func testRemoteAddr(host string) net.Addr {
	return mockAddr{network: "tcp", addr: host}
}

// generateTestHostKey creates an ed25519 host key pair for testing
func generateTestHostKey(t *testing.T) (ssh.PublicKey, ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}
	return pubKey, signer
}

// createTestKnownHostsFile creates a known_hosts file with given entries
func createTestKnownHostsFile(t *testing.T, dir string, entries map[string]ssh.PublicKey) string {
	t.Helper()
	knownHostsPath := filepath.Join(dir, "known_hosts")

	var lines []string
	for hostname, key := range entries {
		line := formatKnownHostsLine(hostname, key)
		lines = append(lines, line)
	}

	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}

	if err := os.WriteFile(knownHostsPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	return knownHostsPath
}

// formatKnownHostsLine formats a hostname and public key for known_hosts
func formatKnownHostsLine(hostname string, key ssh.PublicKey) string {
	return hostname + " " + string(ssh.MarshalAuthorizedKey(key))[:len(ssh.MarshalAuthorizedKey(key))-1] // Remove trailing newline
}

func TestGetKnownHostsPath(t *testing.T) {
	t.Parallel()
	t.Run("returns path in user home directory", func(t *testing.T) {
		path := getKnownHostsPath()

		// Should end with .ssh/known_hosts (use filepath.Join for cross-platform)
		expectedSuffix := filepath.Join(".ssh", "known_hosts")
		if !strings.HasSuffix(path, expectedSuffix) {
			t.Errorf("path should end with %s, got %q", expectedSuffix, path)
		}

		// Should be an absolute path
		if !filepath.IsAbs(path) {
			t.Errorf("path should be absolute, got %q", path)
		}
	})
}

func TestCreateHostKeyCallback(t *testing.T) {
	t.Parallel()
	t.Run("known host matches returns no error", func(t *testing.T) {
		tmpDir := t.TempDir()
		pubKey, _ := generateTestHostKey(t)

		// Create known_hosts with this key
		knownHostsPath := createTestKnownHostsFile(t, tmpDir, map[string]ssh.PublicKey{
			"testhost.example.com": pubKey,
		})

		callback, err := createHostKeyCallback(knownHostsPath, false)
		if err != nil {
			t.Fatalf("createHostKeyCallback failed: %v", err)
		}

		// Simulate connecting to the known host
		err = callback("testhost.example.com:22", testRemoteAddr("testhost.example.com:22"), pubKey)
		if err != nil {
			t.Errorf("callback should succeed for known host, got error: %v", err)
		}
	})

	t.Run("known host with wrong key returns error", func(t *testing.T) {
		tmpDir := t.TempDir()
		knownKey, _ := generateTestHostKey(t)
		wrongKey, _ := generateTestHostKey(t)

		// Create known_hosts with the known key
		knownHostsPath := createTestKnownHostsFile(t, tmpDir, map[string]ssh.PublicKey{
			"testhost.example.com": knownKey,
		})

		callback, err := createHostKeyCallback(knownHostsPath, false)
		if err != nil {
			t.Fatalf("createHostKeyCallback failed: %v", err)
		}

		// Simulate connecting with a different key (potential MITM)
		err = callback("testhost.example.com:22", testRemoteAddr("testhost.example.com:22"), wrongKey)
		if err == nil {
			t.Error("callback should fail when host key doesn't match known_hosts")
		}
	})

	t.Run("unknown host without accept flag returns descriptive error", func(t *testing.T) {
		tmpDir := t.TempDir()
		unknownKey, _ := generateTestHostKey(t)

		// Create empty known_hosts
		knownHostsPath := createTestKnownHostsFile(t, tmpDir, map[string]ssh.PublicKey{})

		callback, err := createHostKeyCallback(knownHostsPath, false)
		if err != nil {
			t.Fatalf("createHostKeyCallback failed: %v", err)
		}

		// Simulate connecting to unknown host
		err = callback("unknown.example.com:22", testRemoteAddr("unknown.example.com:22"), unknownKey)
		if err == nil {
			t.Fatal("callback should fail for unknown host without accept flag")
		}

		errMsg := err.Error()

		// Error should be an UnknownHostKeyError
		var unknownHostErr *UnknownHostKeyError
		if !isUnknownHostKeyError(err, &unknownHostErr) {
			t.Errorf("expected UnknownHostKeyError, got: %T - %v", err, err)
		}

		// Error message should contain the hostname
		if !strings.Contains(errMsg, "unknown.example.com") {
			t.Errorf("error should contain hostname, got: %s", errMsg)
		}

		// Error message should contain fingerprint
		if !strings.Contains(errMsg, "SHA256:") {
			t.Errorf("error should contain SHA256 fingerprint, got: %s", errMsg)
		}

		// Error message should tell user about --accept-host-key
		if !strings.Contains(errMsg, "--accept-host-key") {
			t.Errorf("error should mention --accept-host-key flag, got: %s", errMsg)
		}
	})

	t.Run("unknown host with accept flag adds to known_hosts", func(t *testing.T) {
		tmpDir := t.TempDir()
		unknownKey, _ := generateTestHostKey(t)

		// Create empty known_hosts
		knownHostsPath := createTestKnownHostsFile(t, tmpDir, map[string]ssh.PublicKey{})

		callback, err := createHostKeyCallback(knownHostsPath, true) // acceptHostKey = true
		if err != nil {
			t.Fatalf("createHostKeyCallback failed: %v", err)
		}

		// Simulate connecting to unknown host with accept flag
		err = callback("newhost.example.com:22", testRemoteAddr("newhost.example.com:22"), unknownKey)
		if err != nil {
			t.Errorf("callback should succeed with accept flag, got: %v", err)
		}

		// Verify the key was added to known_hosts
		content, err := os.ReadFile(knownHostsPath)
		if err != nil {
			t.Fatalf("failed to read known_hosts: %v", err)
		}

		if !strings.Contains(string(content), "newhost.example.com") {
			t.Error("known_hosts should contain the new host")
		}
	})

	t.Run("missing known_hosts file with accept flag creates it", func(t *testing.T) {
		tmpDir := t.TempDir()
		unknownKey, _ := generateTestHostKey(t)
		knownHostsPath := filepath.Join(tmpDir, "nonexistent", "known_hosts")

		// Create the parent directory
		if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0700); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}

		callback, err := createHostKeyCallback(knownHostsPath, true)
		if err != nil {
			t.Fatalf("createHostKeyCallback failed: %v", err)
		}

		// Connect to unknown host, should create file
		err = callback("newhost.example.com:22", testRemoteAddr("newhost.example.com:22"), unknownKey)
		if err != nil {
			t.Errorf("callback should succeed and create known_hosts, got: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
			t.Error("known_hosts file should have been created")
		}
	})

	t.Run("hostname with port is normalized", func(t *testing.T) {
		tmpDir := t.TempDir()
		pubKey, _ := generateTestHostKey(t)

		// Create known_hosts with hostname (standard format without port for port 22)
		knownHostsPath := createTestKnownHostsFile(t, tmpDir, map[string]ssh.PublicKey{
			"testhost.example.com": pubKey,
		})

		callback, err := createHostKeyCallback(knownHostsPath, false)
		if err != nil {
			t.Fatalf("createHostKeyCallback failed: %v", err)
		}

		// Should match even when connecting with :22
		err = callback("testhost.example.com:22", testRemoteAddr("testhost.example.com:22"), pubKey)
		if err != nil {
			t.Errorf("callback should match hostname regardless of port 22, got: %v", err)
		}
	})

	t.Run("non-standard port is preserved in known_hosts", func(t *testing.T) {
		tmpDir := t.TempDir()
		pubKey, _ := generateTestHostKey(t)

		// Create known_hosts with bracketed format for non-standard port
		knownHostsPath := createTestKnownHostsFile(t, tmpDir, map[string]ssh.PublicKey{
			"[testhost.example.com]:2222": pubKey,
		})

		callback, err := createHostKeyCallback(knownHostsPath, false)
		if err != nil {
			t.Fatalf("createHostKeyCallback failed: %v", err)
		}

		// Should match with non-standard port
		err = callback("testhost.example.com:2222", testRemoteAddr("testhost.example.com:2222"), pubKey)
		if err != nil {
			t.Errorf("callback should match for non-standard port, got: %v", err)
		}
	})
}

func TestUnknownHostKeyError(t *testing.T) {
	t.Parallel()
	t.Run("error message format", func(t *testing.T) {
		pubKey, _ := generateTestHostKey(t)
		fingerprint := ssh.FingerprintSHA256(pubKey)

		err := &UnknownHostKeyError{
			Hostname:    "test.example.com",
			Fingerprint: fingerprint,
		}

		errMsg := err.Error()

		// Check format matches spec
		if !strings.Contains(errMsg, "SSH host key verification failed") {
			t.Errorf("error should start with 'SSH host key verification failed', got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "test.example.com") {
			t.Errorf("error should contain hostname, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "not in known_hosts") {
			t.Errorf("error should mention 'not in known_hosts', got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "Fingerprint:") {
			t.Errorf("error should contain 'Fingerprint:', got: %s", errMsg)
		}
		if !strings.Contains(errMsg, fingerprint) {
			t.Errorf("error should contain the fingerprint, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "Use --accept-host-key") {
			t.Errorf("error should contain usage hint, got: %s", errMsg)
		}
	})
}

func TestHostKeyFingerprintFormat(t *testing.T) {
	t.Parallel()
	pubKey, _ := generateTestHostKey(t)
	fingerprint := ssh.FingerprintSHA256(pubKey)

	// Fingerprint should start with SHA256:
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Errorf("fingerprint should start with 'SHA256:', got: %s", fingerprint)
	}
}

// isUnknownHostKeyError checks if err is an UnknownHostKeyError and populates target
func isUnknownHostKeyError(err error, target **UnknownHostKeyError) bool {
	if e, ok := err.(*UnknownHostKeyError); ok {
		*target = e
		return true
	}
	return false
}
