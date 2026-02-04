//go:build !integration && !windows

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gobeyondidentity/cobalt/pkg/sshca"
)

// generateUserKeypair creates an ed25519 keypair for SSH authentication.
// Returns the private key and the public key in OpenSSH authorized_keys format.
func generateUserKeypair(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate user keypair: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create SSH public key: %v", err)
	}

	authorized := ssh.MarshalAuthorizedKey(sshPub)
	// Remove trailing newline
	return priv, string(authorized[:len(authorized)-1])
}

// getCurrentUsername returns the current OS username for certificate principals.
func getCurrentUsername(t *testing.T) string {
	t.Helper()

	u, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}
	return u.Username
}

// sshTestHarness manages an isolated sshd instance for SSH certificate testing.
// Unlike the general testutil.SSHdHarness, this uses a single TrustedUserCAKeys file
// which is the correct format for OpenSSH (TrustedUserCAKeys doesn't support globs).
type sshTestHarness struct {
	dataDir     string
	port        int
	configPath  string
	hostKeyPath string
	trustedCA   string // single file containing CA public keys
	cmd         *exec.Cmd
	started     bool
}

// newSSHTestHarness creates a new SSH test harness in the given temp directory.
// The trustedCAKey should be in OpenSSH authorized_keys format.
func newSSHTestHarness(t *testing.T, dataDir string, trustedCAKey []byte) *sshTestHarness {
	t.Helper()

	h := &sshTestHarness{
		dataDir:     dataDir,
		configPath:  filepath.Join(dataDir, "sshd_config"),
		hostKeyPath: filepath.Join(dataDir, "ssh_host_ed25519_key"),
		trustedCA:   filepath.Join(dataDir, "trusted_user_ca"),
	}

	// Find an available port
	port, err := findFreePort()
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	h.port = port

	// Generate host key
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", h.hostKeyPath, "-N", "")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to generate host key: %v: %s", err, output)
	}

	// Write trusted CA file (single file, one CA per line)
	caData := trustedCAKey
	if len(caData) > 0 && caData[len(caData)-1] != '\n' {
		caData = append(caData, '\n')
	}
	if err := os.WriteFile(h.trustedCA, caData, 0644); err != nil {
		t.Fatalf("failed to write trusted CA file: %v", err)
	}

	// Write sshd_config
	config := []byte(`# sshd_config for SSH certificate E2E testing
Port ` + itoa(h.port) + `
ListenAddress 127.0.0.1
HostKey ` + h.hostKeyPath + `
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedPrincipalsFile none
TrustedUserCAKeys ` + h.trustedCA + `
LogLevel DEBUG
PidFile ` + filepath.Join(dataDir, "sshd.pid") + `
`)
	if err := os.WriteFile(h.configPath, config, 0644); err != nil {
		t.Fatalf("failed to write sshd_config: %v", err)
	}

	return h
}

// start launches sshd.
func (h *sshTestHarness) start(t *testing.T) {
	t.Helper()

	if h.started {
		t.Fatal("sshd already started")
	}

	sshdPath := findSSHdPath()
	if sshdPath == "" {
		t.Skip("sshd not found, skipping test")
	}

	h.cmd = exec.Command(sshdPath, "-D", "-e", "-f", h.configPath)
	h.cmd.Stdout = os.Stdout
	h.cmd.Stderr = os.Stderr

	if err := h.cmd.Start(); err != nil {
		t.Fatalf("failed to start sshd: %v", err)
	}
	h.started = true
}

// stop terminates sshd.
func (h *sshTestHarness) stop() {
	if !h.started || h.cmd == nil || h.cmd.Process == nil {
		return
	}

	h.cmd.Process.Signal(os.Interrupt)

	done := make(chan error, 1)
	go func() { done <- h.cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		h.cmd.Process.Kill()
	}

	h.started = false
}

// addr returns the address to connect to.
func (h *sshTestHarness) addr() string {
	return "127.0.0.1:" + itoa(h.port)
}

// waitReady blocks until sshd is accepting connections.
func (h *sshTestHarness) waitReady(t *testing.T, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).Dial("tcp", h.addr())
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("sshd not ready after %v", timeout)
}

// Helper functions
func findFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port, nil
}

func findSSHdPath() string {
	paths := []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/opt/homebrew/sbin/sshd"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if path, err := exec.LookPath("sshd"); err == nil {
		return path
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf) - 1
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	if neg {
		buf[i] = '-'
		i--
	}
	return string(buf[i+1:])
}

// TestSSHAccessE2E_ValidCertificate verifies that SSH access succeeds with a valid certificate
// signed by a trusted CA.
func TestSSHAccessE2E_ValidCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	t.Log("Generating CA keypair")
	ca, err := sshca.GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	t.Log("Getting CA public key")
	caPubKey, err := ca.PublicKeyString()
	if err != nil {
		t.Fatalf("failed to get CA public key: %v", err)
	}

	t.Log("Creating sshd harness with trusted CA")
	harness := newSSHTestHarness(t, t.TempDir(), []byte(caPubKey))
	t.Cleanup(func() {
		t.Log("Stopping sshd harness")
		harness.stop()
	})

	t.Log("Starting sshd")
	harness.start(t)

	t.Log("Waiting for sshd to become ready")
	harness.waitReady(t, 5*time.Second)

	t.Log("Generating user keypair")
	userPrivKey, userPubKeyStr := generateUserKeypair(t)

	username := getCurrentUsername(t)
	t.Logf("Signing certificate for user %q", username)

	certStr, err := ca.SignCertificate(userPubKeyStr, sshca.CertOptions{
		Principal:   username,
		ValidBefore: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}

	t.Log("Parsing signed certificate")
	certPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	cert, ok := certPubKey.(*ssh.Certificate)
	if !ok {
		t.Fatal("parsed key is not a certificate")
	}

	t.Log("Creating SSH client with certificate authentication")
	userSigner, err := ssh.NewSignerFromKey(userPrivKey)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatalf("failed to create cert signer: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	t.Logf("Connecting to sshd at %s", harness.addr())
	client, err := ssh.Dial("tcp", harness.addr(), config)
	if err != nil {
		t.Fatalf("SSH connection failed: %v", err)
	}
	defer client.Close()

	t.Log("Opening session and executing 'whoami' command")
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput("whoami")
	if err != nil {
		t.Fatalf("failed to execute command: %v", err)
	}

	// Trim trailing newline from output
	result := string(output)
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}

	t.Logf("Command output: %q", result)
	if result != username {
		t.Errorf("expected whoami to return %q, got %q", username, result)
	}

	t.Log("TestSSHAccessE2E_ValidCertificate passed: SSH access with valid certificate succeeded")
}

// TestSSHAccessE2E_NoCertificate verifies that SSH access fails when attempting
// to authenticate with just a key (no certificate).
func TestSSHAccessE2E_NoCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	t.Log("Generating CA keypair")
	ca, err := sshca.GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	t.Log("Getting CA public key")
	caPubKey, err := ca.PublicKeyString()
	if err != nil {
		t.Fatalf("failed to get CA public key: %v", err)
	}

	t.Log("Creating sshd harness with trusted CA")
	harness := newSSHTestHarness(t, t.TempDir(), []byte(caPubKey))
	t.Cleanup(func() {
		t.Log("Stopping sshd harness")
		harness.stop()
	})

	t.Log("Starting sshd")
	harness.start(t)

	t.Log("Waiting for sshd to become ready")
	harness.waitReady(t, 5*time.Second)

	t.Log("Generating user keypair (without certificate)")
	userPrivKey, _ := generateUserKeypair(t)

	username := getCurrentUsername(t)
	t.Logf("Attempting SSH as user %q with only public key (no certificate)", username)

	userSigner, err := ssh.NewSignerFromKey(userPrivKey)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(userSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	t.Logf("Connecting to sshd at %s (expecting failure)", harness.addr())
	client, err := ssh.Dial("tcp", harness.addr(), config)
	if err == nil {
		client.Close()
		t.Fatal("SSH connection should have failed without certificate, but it succeeded")
	}

	t.Logf("SSH connection correctly failed: %v", err)
	t.Log("TestSSHAccessE2E_NoCertificate passed: SSH access without certificate correctly denied")
}

// TestSSHAccessE2E_ExpiredCertificate verifies that SSH access fails when the certificate
// has expired.
func TestSSHAccessE2E_ExpiredCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	t.Log("Generating CA keypair")
	ca, err := sshca.GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	t.Log("Getting CA public key")
	caPubKey, err := ca.PublicKeyString()
	if err != nil {
		t.Fatalf("failed to get CA public key: %v", err)
	}

	t.Log("Creating sshd harness with trusted CA")
	harness := newSSHTestHarness(t, t.TempDir(), []byte(caPubKey))
	t.Cleanup(func() {
		t.Log("Stopping sshd harness")
		harness.stop()
	})

	t.Log("Starting sshd")
	harness.start(t)

	t.Log("Waiting for sshd to become ready")
	harness.waitReady(t, 5*time.Second)

	t.Log("Generating user keypair")
	userPrivKey, userPubKeyStr := generateUserKeypair(t)

	username := getCurrentUsername(t)
	t.Logf("Signing EXPIRED certificate for user %q", username)

	// Create an expired certificate: valid from 1 hour ago to 30 minutes ago
	certStr, err := ca.SignCertificate(userPubKeyStr, sshca.CertOptions{
		Principal:   username,
		ValidAfter:  time.Now().Add(-1 * time.Hour),
		ValidBefore: time.Now().Add(-30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}

	t.Log("Parsing signed certificate")
	certPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	cert, ok := certPubKey.(*ssh.Certificate)
	if !ok {
		t.Fatal("parsed key is not a certificate")
	}

	t.Log("Creating SSH client with expired certificate")
	userSigner, err := ssh.NewSignerFromKey(userPrivKey)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatalf("failed to create cert signer: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	t.Logf("Connecting to sshd at %s (expecting failure due to expired certificate)", harness.addr())
	client, err := ssh.Dial("tcp", harness.addr(), config)
	if err == nil {
		client.Close()
		t.Fatal("SSH connection should have failed with expired certificate, but it succeeded")
	}

	t.Logf("SSH connection correctly failed: %v", err)
	t.Log("TestSSHAccessE2E_ExpiredCertificate passed: SSH access with expired certificate correctly denied")
}

// TestSSHAccessE2E_WrongCACertificate verifies that SSH access fails when the certificate
// is signed by a CA that is not trusted by the server.
func TestSSHAccessE2E_WrongCACertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	t.Log("Generating trusted CA keypair (CA-1)")
	trustedCA, err := sshca.GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("failed to generate trusted CA: %v", err)
	}

	t.Log("Generating untrusted CA keypair (CA-2)")
	untrustedCA, err := sshca.GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("failed to generate untrusted CA: %v", err)
	}

	t.Log("Getting trusted CA public key")
	trustedCAPubKey, err := trustedCA.PublicKeyString()
	if err != nil {
		t.Fatalf("failed to get trusted CA public key: %v", err)
	}

	t.Log("Creating sshd harness with ONLY trusted CA (CA-1)")
	harness := newSSHTestHarness(t, t.TempDir(), []byte(trustedCAPubKey))
	t.Cleanup(func() {
		t.Log("Stopping sshd harness")
		harness.stop()
	})

	t.Log("Starting sshd")
	harness.start(t)

	t.Log("Waiting for sshd to become ready")
	harness.waitReady(t, 5*time.Second)

	t.Log("Generating user keypair")
	userPrivKey, userPubKeyStr := generateUserKeypair(t)

	username := getCurrentUsername(t)
	t.Logf("Signing certificate with UNTRUSTED CA (CA-2) for user %q", username)

	// Sign with the untrusted CA
	certStr, err := untrustedCA.SignCertificate(userPubKeyStr, sshca.CertOptions{
		Principal:   username,
		ValidBefore: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}

	t.Log("Parsing signed certificate")
	certPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	cert, ok := certPubKey.(*ssh.Certificate)
	if !ok {
		t.Fatal("parsed key is not a certificate")
	}

	t.Log("Creating SSH client with certificate signed by untrusted CA")
	userSigner, err := ssh.NewSignerFromKey(userPrivKey)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatalf("failed to create cert signer: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	t.Logf("Connecting to sshd at %s (expecting failure due to untrusted CA)", harness.addr())
	client, err := ssh.Dial("tcp", harness.addr(), config)
	if err == nil {
		client.Close()
		t.Fatal("SSH connection should have failed with certificate from untrusted CA, but it succeeded")
	}

	t.Logf("SSH connection correctly failed: %v", err)
	t.Log("TestSSHAccessE2E_WrongCACertificate passed: SSH access with untrusted CA certificate correctly denied")
}
