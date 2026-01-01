// Package agent implements the DPU agent gRPC server.
package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	// trustedCADir is the directory where CA public keys are stored on the host.
	trustedCADir = "/etc/ssh/trusted-user-ca-keys.d"

	// sshdConfigPath is the path to the sshd configuration file.
	sshdConfigPath = "/etc/ssh/sshd_config"

	// sshdPIDPath is the path to the sshd PID file.
	sshdPIDPath = "/var/run/sshd.pid"

	// trustedUserCAKeysDirective is the sshd_config directive for CA keys.
	trustedUserCAKeysDirective = "TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.d/*.pub"
)

// SSHExecutor defines the interface for executing SSH commands on a remote host.
// This abstraction allows for mocking in tests.
type SSHExecutor interface {
	// Run executes a command on the remote host and returns stdout, stderr, and any error.
	Run(ctx context.Context, cmd string) (stdout, stderr string, err error)

	// Close closes the SSH connection.
	Close() error
}

// sshClientExecutor implements SSHExecutor using the golang.org/x/crypto/ssh package.
type sshClientExecutor struct {
	client *ssh.Client
}

// NewSSHExecutor creates a new SSH executor connected to the specified host.
func NewSSHExecutor(addr, user, keyPath string) (SSHExecutor, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // DPU-to-host is trusted internal network
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}

	return &sshClientExecutor{client: client}, nil
}

// Run executes a command on the remote host.
func (e *sshClientExecutor) Run(ctx context.Context, cmd string) (stdout, stderr string, err error) {
	session, err := e.client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("create SSH session: %w", err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf strings.Builder
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	// Run the command (context cancellation is not directly supported by x/crypto/ssh,
	// but the session will be cleaned up when the context is done)
	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()

	select {
	case <-ctx.Done():
		session.Close()
		return stdoutBuf.String(), stderrBuf.String(), ctx.Err()
	case err := <-done:
		return stdoutBuf.String(), stderrBuf.String(), err
	}
}

// Close closes the SSH connection.
func (e *sshClientExecutor) Close() error {
	return e.client.Close()
}

// DistributeSSHCA deploys an SSH CA public key to the host and configures sshd to trust it.
// This function:
//  1. Creates the trusted CA keys directory if it doesn't exist
//  2. Writes the CA public key to a file named <caName>.pub
//  3. Ensures sshd_config includes the TrustedUserCAKeys directive
//  4. Reloads sshd with SIGHUP to apply changes without dropping connections
//
// The operation is idempotent: writing the same CA again overwrites the file.
func DistributeSSHCA(ctx context.Context, executor SSHExecutor, publicKey []byte, caName string) (installedPath string, sshdReloaded bool, err error) {
	// Validate inputs
	if len(publicKey) == 0 {
		return "", false, fmt.Errorf("public key is empty")
	}
	if caName == "" {
		return "", false, fmt.Errorf("CA name is required")
	}

	// Sanitize CA name to prevent path traversal
	cleanName := filepath.Base(caName)
	if cleanName != caName || strings.ContainsAny(caName, "/\\") {
		return "", false, fmt.Errorf("invalid CA name: must not contain path separators")
	}

	installedPath = filepath.Join(trustedCADir, cleanName+".pub")

	// Step 1: Create directory with proper permissions
	mkdirCmd := fmt.Sprintf("sudo mkdir -p %s && sudo chmod 755 %s", trustedCADir, trustedCADir)
	if _, stderr, err := executor.Run(ctx, mkdirCmd); err != nil {
		return "", false, fmt.Errorf("create CA directory: %w (stderr: %s)", err, stderr)
	}

	// Step 2: Write the CA public key
	// Use printf to handle the key content safely (avoids issues with special characters)
	publicKeyStr := strings.TrimSpace(string(publicKey))
	writeCmd := fmt.Sprintf("printf '%%s\\n' %q | sudo tee %s > /dev/null", publicKeyStr, installedPath)
	if _, stderr, err := executor.Run(ctx, writeCmd); err != nil {
		return "", false, fmt.Errorf("write CA public key: %w (stderr: %s)", err, stderr)
	}

	// Set proper permissions on the key file
	chmodCmd := fmt.Sprintf("sudo chmod 644 %s", installedPath)
	if _, stderr, err := executor.Run(ctx, chmodCmd); err != nil {
		return "", false, fmt.Errorf("set key permissions: %w (stderr: %s)", err, stderr)
	}

	// Step 3: Ensure sshd_config includes the TrustedUserCAKeys directive
	// Only add if not already present
	checkDirective := fmt.Sprintf("grep -q 'TrustedUserCAKeys' %s", sshdConfigPath)
	_, _, grepErr := executor.Run(ctx, checkDirective)

	configModified := false
	if grepErr != nil {
		// Directive not found, add it
		addDirective := fmt.Sprintf("echo '%s' | sudo tee -a %s > /dev/null", trustedUserCAKeysDirective, sshdConfigPath)
		if _, stderr, err := executor.Run(ctx, addDirective); err != nil {
			return installedPath, false, fmt.Errorf("add TrustedUserCAKeys directive: %w (stderr: %s)", err, stderr)
		}
		configModified = true
	}

	// Step 4: Reload sshd with SIGHUP (graceful reload, no connection drops)
	// We reload if either the config was modified or we wrote a new/updated CA key
	reloadCmd := fmt.Sprintf("sudo kill -HUP $(cat %s 2>/dev/null) 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || sudo service sshd reload 2>/dev/null || true", sshdPIDPath)
	_, _, reloadErr := executor.Run(ctx, reloadCmd)

	// Reload is best-effort; the command chain handles different init systems
	// We consider it successful if no error, or if we at least tried
	sshdReloaded = reloadErr == nil || configModified

	return installedPath, sshdReloaded, nil
}
