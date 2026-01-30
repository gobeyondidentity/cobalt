//go:build !windows

// Package testutil provides testing utilities for Secure Infrastructure.
package testutil

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// SSHdHarness manages an isolated sshd instance for testing.
// It runs sshd on a non-standard port with a temporary configuration,
// allowing integration tests to verify SSH certificate authentication.
type SSHdHarness struct {
	DataDir      string // temp directory root (created by caller)
	Port         int    // listening port
	ConfigPath   string // path to sshd_config
	HostKeyPath  string // path to host key
	TrustedCADir string // path to trusted-user-ca-keys.d

	mu      sync.Mutex
	cmd     *exec.Cmd
	started bool
}

// NewSSHdHarness creates a harness using the provided temp directory.
// Caller should pass t.TempDir() for automatic cleanup.
//
// This function:
//   - Generates an ed25519 host key
//   - Creates the trusted CA directory
//   - Writes a minimal sshd_config
//
// Returns an error if any setup step fails.
func NewSSHdHarness(dataDir string) (*SSHdHarness, error) {
	h := &SSHdHarness{
		DataDir:      dataDir,
		ConfigPath:   filepath.Join(dataDir, "sshd_config"),
		HostKeyPath:  filepath.Join(dataDir, "ssh_host_ed25519_key"),
		TrustedCADir: filepath.Join(dataDir, "trusted-user-ca-keys.d"),
	}

	// Find an available port
	port, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("find available port: %w", err)
	}
	h.Port = port

	// Create trusted CA directory
	if err := os.MkdirAll(h.TrustedCADir, 0755); err != nil {
		return nil, fmt.Errorf("create trusted CA directory: %w", err)
	}

	// Generate host key
	if err := h.generateHostKey(); err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	// Write sshd_config
	if err := h.writeConfig(); err != nil {
		return nil, fmt.Errorf("write sshd_config: %w", err)
	}

	return h, nil
}

// Start launches sshd in foreground mode (-D flag).
// The process is managed internally and terminated by Stop().
func (h *SSHdHarness) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.started {
		return fmt.Errorf("sshd already started")
	}

	sshdPath := findSSHd()
	if sshdPath == "" {
		return fmt.Errorf("sshd not found in PATH or common locations")
	}

	// Run sshd in debug mode with our config
	// -D: foreground mode (don't daemonize)
	// -e: log to stderr instead of syslog
	// -f: config file path
	h.cmd = exec.Command(sshdPath, "-D", "-e", "-f", h.ConfigPath)
	h.cmd.Stdout = os.Stdout
	h.cmd.Stderr = os.Stderr

	if err := h.cmd.Start(); err != nil {
		return fmt.Errorf("start sshd: %w", err)
	}

	h.started = true
	return nil
}

// Stop terminates the sshd process.
// It is safe to call Stop multiple times.
func (h *SSHdHarness) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.started || h.cmd == nil || h.cmd.Process == nil {
		return nil
	}

	// Send SIGTERM for graceful shutdown
	if err := h.cmd.Process.Signal(os.Interrupt); err != nil {
		// If signal fails, try Kill
		if killErr := h.cmd.Process.Kill(); killErr != nil {
			return fmt.Errorf("failed to stop sshd: signal=%v, kill=%v", err, killErr)
		}
	}

	// Wait for process to exit (with timeout)
	done := make(chan error, 1)
	go func() {
		done <- h.cmd.Wait()
	}()

	select {
	case <-done:
		// Process exited
	case <-time.After(5 * time.Second):
		// Force kill if still running
		h.cmd.Process.Kill()
	}

	h.started = false
	return nil
}

// SetTrustedCA writes a CA public key to the trusted CA directory.
// sshd will trust certificates signed by this CA after a reload.
func (h *SSHdHarness) SetTrustedCA(caName string, publicKey []byte) error {
	if caName == "" {
		return fmt.Errorf("CA name is required")
	}
	if len(publicKey) == 0 {
		return fmt.Errorf("public key is required")
	}

	// Ensure key ends with newline
	data := publicKey
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}

	keyPath := filepath.Join(h.TrustedCADir, caName+".pub")
	if err := os.WriteFile(keyPath, data, 0644); err != nil {
		return fmt.Errorf("write CA public key: %w", err)
	}

	return nil
}

// Addr returns the address to connect to (e.g., "127.0.0.1:2222").
func (h *SSHdHarness) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", h.Port)
}

// WaitReady blocks until sshd is accepting connections or timeout expires.
func (h *SSHdHarness) WaitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	pollInterval := 50 * time.Millisecond

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", h.Addr(), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(pollInterval)
	}

	return fmt.Errorf("sshd not ready after %v", timeout)
}

// generateHostKey creates an ed25519 host key using ssh-keygen.
func (h *SSHdHarness) generateHostKey() error {
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", h.HostKeyPath, "-N", "")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh-keygen: %w: %s", err, output)
	}
	return nil
}

// writeConfig creates a minimal sshd_config for testing.
func (h *SSHdHarness) writeConfig() error {
	// Build TrustedUserCAKeys directive with wildcard
	trustedCAWildcard := filepath.Join(h.TrustedCADir, "*.pub")

	config := fmt.Sprintf(`# sshd_config for integration testing
# Generated by SSHdHarness

Port %d
ListenAddress 127.0.0.1

# Host key
HostKey %s

# Authentication
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedPrincipalsFile none

# Certificate authentication
TrustedUserCAKeys %s

# Logging
LogLevel DEBUG

# PID file
PidFile %s
`, h.Port, h.HostKeyPath, trustedCAWildcard, filepath.Join(h.DataDir, "sshd.pid"))

	// On older systems, UsePrivilegeSeparation may be needed
	// Modern sshd (OpenSSH 7.5+) removed this option
	if !isModernSSHd() {
		config += "\n# Disable privilege separation for unprivileged testing\nUsePrivilegeSeparation no\n"
	}

	return os.WriteFile(h.ConfigPath, []byte(config), 0644)
}

// findAvailablePort finds an available TCP port by binding to port 0.
func findAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port, nil
}

// findSSHd locates the sshd binary.
func findSSHd() string {
	// Try common locations
	paths := []string{
		"/usr/sbin/sshd",
		"/usr/local/sbin/sshd",
		"/opt/homebrew/sbin/sshd",
	}

	// On macOS, also check the system location
	if runtime.GOOS == "darwin" {
		paths = append([]string{"/usr/sbin/sshd"}, paths...)
	}

	// Check each path
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Fall back to PATH lookup
	if path, err := exec.LookPath("sshd"); err == nil {
		return path
	}

	return ""
}

// isModernSSHd checks if the system has OpenSSH 7.5+ which removed UsePrivilegeSeparation.
func isModernSSHd() bool {
	// Modern systems (macOS 10.13+, Ubuntu 18.04+, etc.) have modern sshd
	// For simplicity, assume modern unless we detect otherwise
	// UsePrivilegeSeparation was removed in OpenSSH 7.5 (released 2017-03-20)
	return true
}
