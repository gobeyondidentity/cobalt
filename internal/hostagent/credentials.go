// Package hostagent implements the Host Agent functionality.
package hostagent

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// DefaultTrustedCADir is the default directory for SSH CA public keys.
	DefaultTrustedCADir = "/etc/ssh/trusted-user-ca-keys.d"

	// DefaultSshdConfigPath is the default path to sshd_config.
	DefaultSshdConfigPath = "/etc/ssh/sshd_config"

	// TrustedUserCAKeysDirective is the sshd_config directive for CA keys directory.
	TrustedUserCAKeysDirective = "TrustedUserCAKeys"
)

// CredentialInstaller handles local credential installation on the host.
type CredentialInstaller struct {
	TrustedCADir   string
	SshdConfigPath string
}

// NewCredentialInstaller creates a new installer with default paths.
func NewCredentialInstaller() *CredentialInstaller {
	return &CredentialInstaller{
		TrustedCADir:   DefaultTrustedCADir,
		SshdConfigPath: DefaultSshdConfigPath,
	}
}

// InstallSSHCAResult contains the result of an SSH CA installation.
type InstallSSHCAResult struct {
	InstalledPath string
	SshdReloaded  bool
	ConfigUpdated bool
}

// InstallSSHCA installs an SSH CA public key locally.
// It creates the trusted CA directory if needed, writes the public key,
// updates sshd_config if necessary, and reloads sshd.
func (c *CredentialInstaller) InstallSSHCA(caName string, publicKey []byte) (*InstallSSHCAResult, error) {
	if caName == "" {
		return nil, fmt.Errorf("CA name is required")
	}
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("public key is required")
	}

	result := &InstallSSHCAResult{}

	// Step 1: Create trusted CA directory if it doesn't exist
	if err := c.ensureTrustedCADir(); err != nil {
		return nil, fmt.Errorf("create trusted CA directory: %w", err)
	}

	// Step 2: Write the CA public key to file
	keyPath := filepath.Join(c.TrustedCADir, caName+".pub")
	if err := c.writeCAPublicKey(keyPath, publicKey); err != nil {
		return nil, fmt.Errorf("write CA public key: %w", err)
	}
	result.InstalledPath = keyPath

	// Step 3: Update sshd_config if TrustedUserCAKeys is not configured
	configUpdated, err := c.ensureSshdConfig()
	if err != nil {
		return nil, fmt.Errorf("update sshd_config: %w", err)
	}
	result.ConfigUpdated = configUpdated

	// Step 4: Reload sshd to apply changes
	if err := c.reloadSshd(); err != nil {
		// Log warning but don't fail; key is installed
		return result, fmt.Errorf("reload sshd (key installed but reload failed): %w", err)
	}
	result.SshdReloaded = true

	return result, nil
}

// ensureTrustedCADir creates the trusted CA directory with proper permissions.
func (c *CredentialInstaller) ensureTrustedCADir() error {
	info, err := os.Stat(c.TrustedCADir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", c.TrustedCADir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", c.TrustedCADir, err)
	}

	// Create directory with mode 0755 (world-readable, owner-writable)
	if err := os.MkdirAll(c.TrustedCADir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", c.TrustedCADir, err)
	}

	return nil
}

// writeCAPublicKey writes the CA public key to a file with proper permissions.
func (c *CredentialInstaller) writeCAPublicKey(path string, publicKey []byte) error {
	// Ensure the key ends with a newline
	data := publicKey
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}

	// Write with mode 0644 (world-readable, owner-writable)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

// ensureSshdConfig checks if TrustedUserCAKeys is configured and adds it if not.
// Returns true if the config was modified.
func (c *CredentialInstaller) ensureSshdConfig() (bool, error) {
	// Read current config
	content, err := os.ReadFile(c.SshdConfigPath)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", c.SshdConfigPath, err)
	}

	// Check if TrustedUserCAKeys is already configured for our directory
	lines := strings.Split(string(content), "\n")
	wildcard := filepath.Join(c.TrustedCADir, "*.pub")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Check for existing TrustedUserCAKeys directive
		if strings.HasPrefix(trimmed, TrustedUserCAKeysDirective) {
			// Already configured; check if it points to our directory
			if strings.Contains(trimmed, c.TrustedCADir) {
				return false, nil // Already configured correctly
			}
			// Configured but pointing elsewhere; we'll add our entry anyway
			// (sshd supports multiple TrustedUserCAKeys directives)
		}
	}

	// Append TrustedUserCAKeys directive
	configLine := fmt.Sprintf("\n# Added by Secure Infrastructure Host Agent\n%s %s\n",
		TrustedUserCAKeysDirective, wildcard)

	f, err := os.OpenFile(c.SshdConfigPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return false, fmt.Errorf("open %s for append: %w", c.SshdConfigPath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(configLine); err != nil {
		return false, fmt.Errorf("append to %s: %w", c.SshdConfigPath, err)
	}

	return true, nil
}

// reloadSshd reloads the SSH daemon to apply configuration changes.
func (c *CredentialInstaller) reloadSshd() error {
	// Try systemctl first (modern systems)
	cmd := exec.Command("systemctl", "reload", "sshd")
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Try systemctl with ssh (Debian/Ubuntu)
	cmd = exec.Command("systemctl", "reload", "ssh")
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Fall back to service command
	cmd = exec.Command("service", "sshd", "reload")
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Try service ssh (Debian/Ubuntu)
	cmd = exec.Command("service", "ssh", "reload")
	if err := cmd.Run(); err == nil {
		return nil
	}

	return fmt.Errorf("failed to reload sshd via systemctl or service")
}

// IsSshdConfigured checks if TrustedUserCAKeys is configured for the trusted CA directory.
func (c *CredentialInstaller) IsSshdConfigured() (bool, error) {
	f, err := os.Open(c.SshdConfigPath)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", c.SshdConfigPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, TrustedUserCAKeysDirective) &&
			strings.Contains(line, c.TrustedCADir) {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scan %s: %w", c.SshdConfigPath, err)
	}

	return false, nil
}

// ListInstalledCAs returns a list of installed CA names.
func (c *CredentialInstaller) ListInstalledCAs() ([]string, error) {
	entries, err := os.ReadDir(c.TrustedCADir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", c.TrustedCADir, err)
	}

	var cas []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".pub") {
			cas = append(cas, strings.TrimSuffix(name, ".pub"))
		}
	}

	return cas, nil
}

// RemoveSSHCA removes an installed SSH CA public key.
func (c *CredentialInstaller) RemoveSSHCA(caName string) error {
	if caName == "" {
		return fmt.Errorf("CA name is required")
	}

	keyPath := filepath.Join(c.TrustedCADir, caName+".pub")
	if err := os.Remove(keyPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("CA '%s' is not installed", caName)
		}
		return fmt.Errorf("remove %s: %w", keyPath, err)
	}

	// Reload sshd to apply the removal
	if err := c.reloadSshd(); err != nil {
		return fmt.Errorf("CA removed but sshd reload failed: %w", err)
	}

	return nil
}
