package hostagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialInstaller_ensureTrustedCADir(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "trusted-user-ca-keys.d")

	c := &CredentialInstaller{
		TrustedCADir:   caDir,
		SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
	}

	// Directory doesn't exist; should create it
	if err := c.ensureTrustedCADir(); err != nil {
		t.Fatalf("ensureTrustedCADir failed: %v", err)
	}

	info, err := os.Stat(caDir)
	if err != nil {
		t.Fatalf("stat after create: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("expected mode 0755, got %o", info.Mode().Perm())
	}

	// Call again; should be idempotent
	if err := c.ensureTrustedCADir(); err != nil {
		t.Fatalf("ensureTrustedCADir (idempotent) failed: %v", err)
	}
}

func TestCredentialInstaller_ensureTrustedCADir_existsAsFile(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "trusted-user-ca-keys.d")

	// Create as file instead of directory
	if err := os.WriteFile(caDir, []byte("not a dir"), 0644); err != nil {
		t.Fatalf("create file: %v", err)
	}

	c := &CredentialInstaller{
		TrustedCADir:   caDir,
		SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
	}

	err := c.ensureTrustedCADir()
	if err == nil {
		t.Fatal("expected error when path exists as file")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCredentialInstaller_writeCAPublicKey(t *testing.T) {
	tmpDir := t.TempDir()
	c := &CredentialInstaller{
		TrustedCADir:   tmpDir,
		SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
	}

	keyPath := filepath.Join(tmpDir, "test-ca.pub")
	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca")

	if err := c.writeCAPublicKey(keyPath, publicKey); err != nil {
		t.Fatalf("writeCAPublicKey failed: %v", err)
	}

	// Verify content
	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	expected := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca\n"
	if string(content) != expected {
		t.Errorf("content mismatch:\ngot:  %q\nwant: %q", string(content), expected)
	}

	// Verify permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected mode 0644, got %o", info.Mode().Perm())
	}
}

func TestCredentialInstaller_writeCAPublicKey_withTrailingNewline(t *testing.T) {
	tmpDir := t.TempDir()
	c := &CredentialInstaller{
		TrustedCADir:   tmpDir,
		SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
	}

	keyPath := filepath.Join(tmpDir, "test-ca.pub")
	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca\n")

	if err := c.writeCAPublicKey(keyPath, publicKey); err != nil {
		t.Fatalf("writeCAPublicKey failed: %v", err)
	}

	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	// Should not double the newline
	expected := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-ca\n"
	if string(content) != expected {
		t.Errorf("content mismatch:\ngot:  %q\nwant: %q", string(content), expected)
	}
}

func TestCredentialInstaller_ensureSshdConfig_notConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "trusted-user-ca-keys.d")
	configPath := filepath.Join(tmpDir, "sshd_config")

	// Create a minimal sshd_config
	initialConfig := `# SSH Server Configuration
Port 22
PermitRootLogin no
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	c := &CredentialInstaller{
		TrustedCADir:   caDir,
		SshdConfigPath: configPath,
	}

	modified, err := c.ensureSshdConfig()
	if err != nil {
		t.Fatalf("ensureSshdConfig failed: %v", err)
	}
	if !modified {
		t.Error("expected config to be modified")
	}

	// Verify the directive was added
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(content), "TrustedUserCAKeys") {
		t.Error("TrustedUserCAKeys directive not found in config")
	}
	expected := filepath.Join(caDir, "*.pub")
	if !strings.Contains(string(content), expected) {
		t.Errorf("expected path %s not found in config", expected)
	}
}

func TestCredentialInstaller_ensureSshdConfig_alreadyConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "trusted-user-ca-keys.d")
	configPath := filepath.Join(tmpDir, "sshd_config")

	// Create config with TrustedUserCAKeys already set
	initialConfig := `# SSH Server Configuration
Port 22
TrustedUserCAKeys ` + filepath.Join(caDir, "*.pub") + `
PermitRootLogin no
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	c := &CredentialInstaller{
		TrustedCADir:   caDir,
		SshdConfigPath: configPath,
	}

	modified, err := c.ensureSshdConfig()
	if err != nil {
		t.Fatalf("ensureSshdConfig failed: %v", err)
	}
	if modified {
		t.Error("expected config NOT to be modified (already configured)")
	}
}

func TestCredentialInstaller_ensureSshdConfig_commentedOut(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "trusted-user-ca-keys.d")
	configPath := filepath.Join(tmpDir, "sshd_config")

	// Create config with TrustedUserCAKeys commented out
	initialConfig := `# SSH Server Configuration
Port 22
# TrustedUserCAKeys /some/path
PermitRootLogin no
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	c := &CredentialInstaller{
		TrustedCADir:   caDir,
		SshdConfigPath: configPath,
	}

	modified, err := c.ensureSshdConfig()
	if err != nil {
		t.Fatalf("ensureSshdConfig failed: %v", err)
	}
	if !modified {
		t.Error("expected config to be modified (commented version doesn't count)")
	}
}

func TestCredentialInstaller_IsSshdConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "trusted-user-ca-keys.d")
	configPath := filepath.Join(tmpDir, "sshd_config")

	c := &CredentialInstaller{
		TrustedCADir:   caDir,
		SshdConfigPath: configPath,
	}

	// Not configured
	initialConfig := `Port 22
PermitRootLogin no
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configured, err := c.IsSshdConfigured()
	if err != nil {
		t.Fatalf("IsSshdConfigured failed: %v", err)
	}
	if configured {
		t.Error("expected not configured")
	}

	// Now add configuration
	configuredContent := `Port 22
TrustedUserCAKeys ` + filepath.Join(caDir, "*.pub") + `
PermitRootLogin no
`
	if err := os.WriteFile(configPath, []byte(configuredContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configured, err = c.IsSshdConfigured()
	if err != nil {
		t.Fatalf("IsSshdConfigured failed: %v", err)
	}
	if !configured {
		t.Error("expected configured")
	}
}

func TestCredentialInstaller_ListInstalledCAs(t *testing.T) {
	tmpDir := t.TempDir()

	c := &CredentialInstaller{
		TrustedCADir:   tmpDir,
		SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
	}

	// Empty directory
	cas, err := c.ListInstalledCAs()
	if err != nil {
		t.Fatalf("ListInstalledCAs failed: %v", err)
	}
	if len(cas) != 0 {
		t.Errorf("expected empty list, got %v", cas)
	}

	// Add some CA files
	files := []string{"ops-ca.pub", "prod-ca.pub", "test-ca.pub"}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, f), []byte("key"), 0644); err != nil {
			t.Fatalf("create %s: %v", f, err)
		}
	}

	// Add a non-.pub file (should be ignored)
	if err := os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("docs"), 0644); err != nil {
		t.Fatalf("create README.md: %v", err)
	}

	cas, err = c.ListInstalledCAs()
	if err != nil {
		t.Fatalf("ListInstalledCAs failed: %v", err)
	}

	expected := []string{"ops-ca", "prod-ca", "test-ca"}
	if len(cas) != len(expected) {
		t.Errorf("expected %d CAs, got %d: %v", len(expected), len(cas), cas)
	}
}

func TestCredentialInstaller_ListInstalledCAs_dirNotExist(t *testing.T) {
	c := &CredentialInstaller{
		TrustedCADir:   "/nonexistent/path/to/ca/dir",
		SshdConfigPath: "/etc/ssh/sshd_config",
	}

	cas, err := c.ListInstalledCAs()
	if err != nil {
		t.Fatalf("ListInstalledCAs should not error for nonexistent dir: %v", err)
	}
	if cas != nil {
		t.Errorf("expected nil for nonexistent dir, got %v", cas)
	}
}

func TestCredentialInstaller_InstallSSHCA_validation(t *testing.T) {
	c := NewCredentialInstaller()

	// Empty CA name
	_, err := c.InstallSSHCA("", []byte("key"))
	if err == nil {
		t.Error("expected error for empty CA name")
	}
	if !strings.Contains(err.Error(), "CA name is required") {
		t.Errorf("unexpected error: %v", err)
	}

	// Empty public key
	_, err = c.InstallSSHCA("test-ca", nil)
	if err == nil {
		t.Error("expected error for empty public key")
	}
	if !strings.Contains(err.Error(), "public key is required") {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = c.InstallSSHCA("test-ca", []byte{})
	if err == nil {
		t.Error("expected error for empty public key")
	}
}

func TestCredentialInstaller_RemoveSSHCA(t *testing.T) {
	tmpDir := t.TempDir()

	c := &CredentialInstaller{
		TrustedCADir:   tmpDir,
		SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
	}

	// Create a CA file
	caPath := filepath.Join(tmpDir, "test-ca.pub")
	if err := os.WriteFile(caPath, []byte("key"), 0644); err != nil {
		t.Fatalf("create CA file: %v", err)
	}

	// Remove it (will fail on sshd reload, but file should be gone)
	err := c.RemoveSSHCA("test-ca")
	// We expect reload to fail in test environment
	if err != nil && !strings.Contains(err.Error(), "sshd reload failed") {
		t.Fatalf("RemoveSSHCA unexpected error: %v", err)
	}

	// Verify file is gone
	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Error("CA file should have been removed")
	}
}

func TestCredentialInstaller_RemoveSSHCA_notExists(t *testing.T) {
	tmpDir := t.TempDir()

	c := &CredentialInstaller{
		TrustedCADir:   tmpDir,
		SshdConfigPath: filepath.Join(tmpDir, "sshd_config"),
	}

	err := c.RemoveSSHCA("nonexistent-ca")
	if err == nil {
		t.Error("expected error for nonexistent CA")
	}
	if !strings.Contains(err.Error(), "is not installed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCredentialInstaller_RemoveSSHCA_validation(t *testing.T) {
	c := NewCredentialInstaller()

	err := c.RemoveSSHCA("")
	if err == nil {
		t.Error("expected error for empty CA name")
	}
	if !strings.Contains(err.Error(), "CA name is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewCredentialInstaller(t *testing.T) {
	c := NewCredentialInstaller()

	if c.TrustedCADir != DefaultTrustedCADir {
		t.Errorf("TrustedCADir: got %s, want %s", c.TrustedCADir, DefaultTrustedCADir)
	}
	if c.SshdConfigPath != DefaultSshdConfigPath {
		t.Errorf("SshdConfigPath: got %s, want %s", c.SshdConfigPath, DefaultSshdConfigPath)
	}
}
