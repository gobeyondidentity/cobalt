package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/sshscan"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// scanHostSSH scans a host via SSH and returns SSH keys found.
// It uses ssh-agent for authentication by default, or an explicit key if provided.
// If acceptHostKey is true, unknown hosts will be added to known_hosts (TOFU).
func scanHostSSH(hostname, sshUser, sshKeyPath string, acceptHostKey bool, timeout time.Duration) (*ScanResult, error) {
	client, err := connectSSH(hostname, sshUser, sshKeyPath, acceptHostKey, timeout)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// Try with sudo first, fall back to without
	output, err := runRemoteCommand(client, buildAuthorizedKeysCommand(true))
	if err != nil {
		// Try without sudo
		output, err = runRemoteCommand(client, buildAuthorizedKeysCommand(false))
		if err != nil {
			return nil, fmt.Errorf("failed to read authorized_keys: %w", err)
		}
	}

	keys := parseSSHOutput(output, hostname)

	return &ScanResult{
		Host:      hostname,
		Method:    "ssh",
		Keys:      keysFromScanResultKeys(keys),
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// connectSSH establishes an SSH connection to the host with proper host key verification.
// If acceptHostKey is true, unknown hosts will be added to known_hosts (TOFU pattern).
func connectSSH(hostname, user, keyPath string, acceptHostKey bool, timeout time.Duration) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	if keyPath != "" {
		// Validate path before reading (defense in depth against path traversal)
		if err := validateSSHKeyPath(keyPath); err != nil {
			return nil, err
		}

		// Use explicit private key
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH key: %w", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH key: %w", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else {
		// Use ssh-agent
		agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			return nil, fmt.Errorf("SSH authentication failed: ssh-agent not available (set SSH_AUTH_SOCK or use --ssh-key)")
		}
		defer agentConn.Close()

		agentClient := agent.NewClient(agentConn)
		authMethods = append(authMethods, ssh.PublicKeysCallback(agentClient.Signers))
	}

	// Set up host key verification using known_hosts
	knownHostsPath := getKnownHostsPath()
	hostKeyCallback, err := createHostKeyCallback(knownHostsPath, acceptHostKey)
	if err != nil {
		return nil, fmt.Errorf("failed to set up host key verification: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	// Add default SSH port if not specified
	addr := hostname
	if !strings.Contains(hostname, ":") {
		addr = hostname + ":22"
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, fmt.Errorf("SSH authentication failed (check credentials)")
		}
		if strings.Contains(err.Error(), "connection refused") {
			return nil, fmt.Errorf("connection refused (check SSH service)")
		}
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			return nil, fmt.Errorf("timeout after %v (check network)", timeout)
		}
		return nil, fmt.Errorf("SSH connection failed: %w", err)
	}

	return client, nil
}

// runRemoteCommand executes a command on the remote host and returns stdout.
func runRemoteCommand(client *ssh.Client, command string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		// Even if command fails, we might have partial output
		// Check if there's useful output despite exit code
		if len(output) > 0 && strings.Contains(string(output), "ssh-") {
			return string(output), nil
		}
		return "", err
	}

	return string(output), nil
}

// buildAuthorizedKeysCommand returns the shell command to read authorized_keys files.
// Uses grep -H to ensure file paths are prepended to each line for user extraction.
func buildAuthorizedKeysCommand(useSudo bool) string {
	cmd := "grep -H . /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null"
	if useSudo {
		cmd = "sudo " + cmd
	}
	return cmd
}

// parseSSHOutput parses the output of the remote authorized_keys grep command.
// The output format is either:
//   - /path/to/file:key-line (grep -H output with file paths)
//   - key-line (fallback for single file or raw output)
func parseSSHOutput(output, hostname string) []ScanResultKey {
	var keys []ScanResultKey

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip error messages from cat
		if strings.HasPrefix(line, "cat:") {
			continue
		}

		filePath, keyLine := extractPathAndKey(line)

		// If no key line was extracted (error line, etc), skip
		if keyLine == "" {
			continue
		}

		// Parse the SSH key
		parsedKey, err := sshscan.ParseLine(keyLine)
		if err != nil || parsedKey == nil {
			continue
		}

		// Extract username from file path
		user := ""
		if filePath != "" {
			user = sshscan.ExtractUsername(filePath)
		}

		keys = append(keys, ScanResultKey{
			Host:        hostname,
			Method:      "ssh",
			User:        user,
			KeyType:     parsedKey.KeyType,
			KeyBits:     parsedKey.KeyBits,
			Fingerprint: parsedKey.Fingerprint,
			Comment:     parsedKey.Comment,
			FilePath:    filePath,
		})
	}

	return keys
}

// extractPathAndKey splits a line into file path and key content.
// Returns (path, key) where path may be empty if no path prefix found.
func extractPathAndKey(line string) (string, string) {
	// Check for path prefix pattern: /path/to/authorized_keys:key-type ...
	// The path always starts with / and contains /.ssh/authorized_keys:
	if !strings.HasPrefix(line, "/") {
		// No path prefix, return empty path and full line as key
		// But skip if it looks like an error message
		if strings.HasPrefix(line, "cat:") || strings.HasPrefix(line, "sudo:") {
			return "", ""
		}
		// Check if it looks like a valid key
		if strings.HasPrefix(line, "ssh-") || strings.HasPrefix(line, "ecdsa-") {
			return "", line
		}
		return "", ""
	}

	// Look for authorized_keys: pattern
	authKeysMarker := "authorized_keys:"
	idx := strings.Index(line, authKeysMarker)
	if idx == -1 {
		// Path prefix but no authorized_keys marker (might be error message)
		return "", ""
	}

	// Extract the file path (everything up to and including "authorized_keys", excluding colon)
	filePath := line[:idx+len(authKeysMarker)-1] // -1 to exclude the colon
	keyLine := line[idx+len(authKeysMarker):]

	return filePath, keyLine
}

// keysFromScanResultKeys converts ScanResultKey slice to sshscan.SSHKey slice.
func keysFromScanResultKeys(resultKeys []ScanResultKey) []sshscan.SSHKey {
	keys := make([]sshscan.SSHKey, len(resultKeys))
	for i, rk := range resultKeys {
		keys[i] = sshscan.SSHKey{
			User:        rk.User,
			KeyType:     rk.KeyType,
			KeyBits:     rk.KeyBits,
			Fingerprint: rk.Fingerprint,
			Comment:     rk.Comment,
			FilePath:    rk.FilePath,
		}
	}
	return keys
}

// validateSSHKeyPath checks that the key path is safe to read.
// Allowed paths: ~/.ssh/*, current directory/*, or paths ending with common key names.
// This is defense in depth; the CLI operator is trusted but we validate anyway.
func validateSSHKeyPath(keyPath string) error {
	// Get absolute path to resolve any ../ traversal
	absPath, err := filepath.Abs(keyPath)
	if err != nil {
		return fmt.Errorf("invalid SSH key path: %w", err)
	}

	// Get home directory for ~/.ssh check
	home, err := os.UserHomeDir()
	if err != nil {
		// If we can't get home dir, skip that check but continue with others
		home = ""
	}

	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		// If we can't get cwd, skip that check but continue with others
		cwd = ""
	}

	// Check if path is within ~/.ssh/
	if home != "" {
		sshDir := filepath.Join(home, ".ssh")
		if strings.HasPrefix(absPath, sshDir+string(filepath.Separator)) || absPath == sshDir {
			return nil
		}
	}

	// Check if path is within current working directory
	if cwd != "" {
		if strings.HasPrefix(absPath, cwd+string(filepath.Separator)) || absPath == cwd {
			return nil
		}
	}

	// Allow common key file patterns anywhere (for flexibility with non-standard locations)
	base := filepath.Base(absPath)
	if isCommonKeyFileName(base) {
		return nil
	}

	return fmt.Errorf("invalid SSH key path: path must be within ~/.ssh/ or current directory (got %s)", absPath)
}

// isCommonKeyFileName checks if the filename matches common SSH key naming patterns.
func isCommonKeyFileName(name string) bool {
	commonNames := []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "identity"}
	for _, n := range commonNames {
		if name == n || strings.HasPrefix(name, n+".") {
			return true
		}
	}
	return false
}
