package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// mockSSHExecutor implements SSHExecutor for testing.
type mockSSHExecutor struct {
	// commands records all commands that were executed
	commands []string

	// responses maps command prefixes to (stdout, stderr, error) tuples
	responses map[string]mockResponse

	// closed tracks whether Close was called
	closed bool
}

type mockResponse struct {
	stdout string
	stderr string
	err    error
}

func newMockSSHExecutor() *mockSSHExecutor {
	return &mockSSHExecutor{
		responses: make(map[string]mockResponse),
	}
}

// Run implements SSHExecutor.
func (m *mockSSHExecutor) Run(ctx context.Context, cmd string) (string, string, error) {
	m.commands = append(m.commands, cmd)

	// Check for context cancellation
	if ctx.Err() != nil {
		return "", "", ctx.Err()
	}

	// Look for a matching response
	for prefix, resp := range m.responses {
		if strings.HasPrefix(cmd, prefix) {
			return resp.stdout, resp.stderr, resp.err
		}
	}

	// Default: success with empty output
	return "", "", nil
}

// Close implements SSHExecutor.
func (m *mockSSHExecutor) Close() error {
	m.closed = true
	return nil
}

// setResponse configures a response for commands starting with the given prefix.
func (m *mockSSHExecutor) setResponse(cmdPrefix string, stdout, stderr string, err error) {
	m.responses[cmdPrefix] = mockResponse{stdout: stdout, stderr: stderr, err: err}
}

// hasCommand checks if a command matching the prefix was executed.
func (m *mockSSHExecutor) hasCommand(prefix string) bool {
	for _, cmd := range m.commands {
		if strings.Contains(cmd, prefix) {
			return true
		}
	}
	return false
}

func TestDistributeSSHCA_Success(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	// Simulate grep not finding the directive (exit code 1)
	executor.setResponse("grep -q 'TrustedUserCAKeys'", "", "", errors.New("exit code 1"))

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")
	caName := "test-ca"

	installedPath, sshdReloaded, err := DistributeSSHCA(ctx, executor, publicKey, caName)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if installedPath != "/etc/ssh/trusted-user-ca-keys.d/test-ca.pub" {
		t.Errorf("unexpected installed path: %s", installedPath)
	}

	if !sshdReloaded {
		t.Error("expected sshd to be reloaded")
	}

	// Verify commands were executed
	if !executor.hasCommand("mkdir -p /etc/ssh/trusted-user-ca-keys.d") {
		t.Error("expected mkdir command")
	}

	if !executor.hasCommand("tee /etc/ssh/trusted-user-ca-keys.d/test-ca.pub") {
		t.Error("expected tee command for CA key")
	}

	if !executor.hasCommand("chmod 644 /etc/ssh/trusted-user-ca-keys.d/test-ca.pub") {
		t.Error("expected chmod command")
	}

	if !executor.hasCommand("TrustedUserCAKeys") {
		t.Error("expected TrustedUserCAKeys directive to be added")
	}

	if !executor.hasCommand("kill -HUP") {
		t.Error("expected sshd reload command")
	}
}

func TestDistributeSSHCA_DirectoryCreation(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")
	caName := "production-ca"

	_, _, err := DistributeSSHCA(ctx, executor, publicKey, caName)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the directory creation command
	found := false
	for _, cmd := range executor.commands {
		if strings.Contains(cmd, "mkdir -p /etc/ssh/trusted-user-ca-keys.d") &&
			strings.Contains(cmd, "chmod 755 /etc/ssh/trusted-user-ca-keys.d") {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected mkdir command with correct permissions")
	}
}

func TestDistributeSSHCA_DirectoryCreationError(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	// Simulate mkdir failure
	executor.setResponse("sudo mkdir", "", "permission denied", errors.New("exit code 1"))

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")
	caName := "test-ca"

	_, _, err := DistributeSSHCA(ctx, executor, publicKey, caName)

	if err == nil {
		t.Fatal("expected error for mkdir failure")
	}

	if !strings.Contains(err.Error(), "create CA directory") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDistributeSSHCA_SshdReload(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	// Simulate grep finding the directive (already configured)
	executor.setResponse("grep -q 'TrustedUserCAKeys'", "", "", nil)

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")
	caName := "test-ca"

	_, sshdReloaded, err := DistributeSSHCA(ctx, executor, publicKey, caName)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// sshd should still be reloaded to pick up the new CA key
	if !sshdReloaded {
		t.Error("expected sshd to be reloaded")
	}

	// Verify reload command was issued
	if !executor.hasCommand("kill -HUP") {
		t.Error("expected sshd reload command")
	}
}

func TestDistributeSSHCA_EmptyPublicKey(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	_, _, err := DistributeSSHCA(ctx, executor, nil, "test-ca")

	if err == nil {
		t.Fatal("expected error for empty public key")
	}

	if !strings.Contains(err.Error(), "public key is empty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDistributeSSHCA_EmptyCAName(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")

	_, _, err := DistributeSSHCA(ctx, executor, publicKey, "")

	if err == nil {
		t.Fatal("expected error for empty CA name")
	}

	if !strings.Contains(err.Error(), "CA name is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDistributeSSHCA_InvalidCAName(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")

	// Test path traversal attempts
	testCases := []string{
		"../evil",
		"/etc/passwd",
		"foo/bar",
		"..\\..\\evil",
	}

	for _, name := range testCases {
		_, _, err := DistributeSSHCA(ctx, executor, publicKey, name)

		if err == nil {
			t.Errorf("expected error for invalid CA name: %s", name)
			continue
		}

		if !strings.Contains(err.Error(), "invalid CA name") {
			t.Errorf("unexpected error message for %s: %v", name, err)
		}
	}
}

func TestDistributeSSHCA_WriteKeyError(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	// Simulate write failure
	executor.setResponse("printf", "", "disk full", errors.New("exit code 1"))

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")
	caName := "test-ca"

	_, _, err := DistributeSSHCA(ctx, executor, publicKey, caName)

	if err == nil {
		t.Fatal("expected error for write failure")
	}

	if !strings.Contains(err.Error(), "write CA public key") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDistributeSSHCA_Idempotent(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")
	caName := "test-ca"

	// First distribution
	path1, _, err1 := DistributeSSHCA(ctx, executor, publicKey, caName)
	if err1 != nil {
		t.Fatalf("first distribution failed: %v", err1)
	}

	// Reset commands to track second call
	executor.commands = nil

	// Second distribution (should work identically)
	path2, _, err2 := DistributeSSHCA(ctx, executor, publicKey, caName)
	if err2 != nil {
		t.Fatalf("second distribution failed: %v", err2)
	}

	if path1 != path2 {
		t.Errorf("paths should match: %s vs %s", path1, path2)
	}

	// Verify same commands were executed (idempotent behavior)
	if len(executor.commands) == 0 {
		t.Error("expected commands to be executed on second call")
	}
}

func TestDistributeSSHCA_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	executor := newMockSSHExecutor()

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")
	caName := "test-ca"

	_, _, err := DistributeSSHCA(ctx, executor, publicKey, caName)

	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context cancellation error, got: %v", err)
	}
}

func TestDistributeSSHCA_DirectiveAlreadyPresent(t *testing.T) {
	ctx := context.Background()
	executor := newMockSSHExecutor()

	// Simulate grep finding the directive (already configured)
	executor.setResponse("grep -q 'TrustedUserCAKeys'", "", "", nil)

	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey test-ca")
	caName := "test-ca"

	_, _, err := DistributeSSHCA(ctx, executor, publicKey, caName)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the directive was NOT added (grep succeeded, so it exists)
	for _, cmd := range executor.commands {
		if strings.Contains(cmd, "echo 'TrustedUserCAKeys") && strings.Contains(cmd, "tee -a") {
			t.Error("should not add directive when already present")
		}
	}
}

func TestMockSSHExecutor_Close(t *testing.T) {
	executor := newMockSSHExecutor()

	if executor.closed {
		t.Error("executor should not be closed initially")
	}

	err := executor.Close()
	if err != nil {
		t.Errorf("unexpected error on close: %v", err)
	}

	if !executor.closed {
		t.Error("executor should be closed after Close()")
	}
}
