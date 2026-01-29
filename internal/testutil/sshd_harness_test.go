package testutil

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSSHdHarness_StartStop(t *testing.T) {
	t.Log("Creating temp directory for sshd harness")
	dataDir := t.TempDir()

	t.Log("Creating new sshd harness")
	h, err := NewSSHdHarness(dataDir)
	if err != nil {
		t.Fatalf("NewSSHdHarness failed: %v", err)
	}

	t.Logf("Harness created: port=%d, configPath=%s", h.Port, h.ConfigPath)

	// Verify host key was generated
	t.Log("Verifying host key was generated")
	if _, err := os.Stat(h.HostKeyPath); err != nil {
		t.Fatalf("host key not found at %s: %v", h.HostKeyPath, err)
	}

	// Verify config was created
	t.Log("Verifying sshd_config was created")
	if _, err := os.Stat(h.ConfigPath); err != nil {
		t.Fatalf("sshd_config not found at %s: %v", h.ConfigPath, err)
	}

	// Verify trusted CA directory exists
	t.Log("Verifying trusted CA directory exists")
	info, err := os.Stat(h.TrustedCADir)
	if err != nil {
		t.Fatalf("trusted CA directory not found at %s: %v", h.TrustedCADir, err)
	}
	if !info.IsDir() {
		t.Fatal("trusted CA path is not a directory")
	}

	t.Log("Starting sshd harness")
	if err := h.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	t.Log("Waiting for sshd to become ready")
	if err := h.WaitReady(5 * time.Second); err != nil {
		h.Stop() // Clean up even if WaitReady fails
		t.Fatalf("WaitReady failed: %v", err)
	}

	t.Logf("sshd is accepting connections at %s", h.Addr())

	// Verify we can connect
	t.Log("Verifying TCP connection to sshd port")
	conn, err := net.Dial("tcp", h.Addr())
	if err != nil {
		h.Stop()
		t.Fatalf("failed to connect to %s: %v", h.Addr(), err)
	}
	conn.Close()

	t.Log("Stopping sshd harness")
	if err := h.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Give the process time to exit
	time.Sleep(100 * time.Millisecond)

	// Verify sshd is no longer listening
	t.Log("Verifying sshd is no longer listening")
	conn, err = net.DialTimeout("tcp", h.Addr(), 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("sshd should not be accepting connections after Stop")
	}

	t.Log("TestSSHdHarness_StartStop passed: full lifecycle verified")
}

func TestSSHdHarness_SetTrustedCA(t *testing.T) {
	t.Log("Creating temp directory for sshd harness")
	dataDir := t.TempDir()

	t.Log("Creating new sshd harness")
	h, err := NewSSHdHarness(dataDir)
	if err != nil {
		t.Fatalf("NewSSHdHarness failed: %v", err)
	}

	// Test CA public key (this is a test key, not a real CA)
	testCAKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestCAKeyForIntegrationTesting test-ca@example.com")

	t.Log("Setting trusted CA 'ops-ca'")
	if err := h.SetTrustedCA("ops-ca", testCAKey); err != nil {
		t.Fatalf("SetTrustedCA failed: %v", err)
	}

	// Verify CA file was created
	expectedPath := filepath.Join(h.TrustedCADir, "ops-ca.pub")
	t.Logf("Verifying CA file exists at %s", expectedPath)
	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read CA file: %v", err)
	}

	// Verify content (should have trailing newline)
	expectedContent := string(testCAKey)
	if expectedContent[len(expectedContent)-1] != '\n' {
		expectedContent += "\n"
	}
	if string(content) != expectedContent {
		t.Errorf("CA file content mismatch:\ngot:  %q\nwant: %q", string(content), expectedContent)
	}

	// Verify permissions
	t.Log("Verifying CA file permissions")
	info, err := os.Stat(expectedPath)
	if err != nil {
		t.Fatalf("failed to stat CA file: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected mode 0644, got %o", info.Mode().Perm())
	}

	// Test adding a second CA
	t.Log("Setting trusted CA 'prod-ca'")
	testCAKey2 := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnotherTestCAKey prod-ca@example.com")
	if err := h.SetTrustedCA("prod-ca", testCAKey2); err != nil {
		t.Fatalf("SetTrustedCA for prod-ca failed: %v", err)
	}

	// Verify both CAs exist
	t.Log("Verifying both CA files exist")
	for _, name := range []string{"ops-ca", "prod-ca"} {
		path := filepath.Join(h.TrustedCADir, name+".pub")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("CA file %s not found: %v", path, err)
		}
	}

	t.Log("TestSSHdHarness_SetTrustedCA passed: CA configuration verified")
}

func TestSSHdHarness_SetTrustedCA_Validation(t *testing.T) {
	t.Log("Creating temp directory for sshd harness")
	dataDir := t.TempDir()

	t.Log("Creating new sshd harness")
	h, err := NewSSHdHarness(dataDir)
	if err != nil {
		t.Fatalf("NewSSHdHarness failed: %v", err)
	}

	t.Log("Testing empty CA name")
	if err := h.SetTrustedCA("", []byte("key")); err == nil {
		t.Error("expected error for empty CA name")
	}

	t.Log("Testing empty public key")
	if err := h.SetTrustedCA("test-ca", nil); err == nil {
		t.Error("expected error for nil public key")
	}
	if err := h.SetTrustedCA("test-ca", []byte{}); err == nil {
		t.Error("expected error for empty public key")
	}

	t.Log("TestSSHdHarness_SetTrustedCA_Validation passed")
}
