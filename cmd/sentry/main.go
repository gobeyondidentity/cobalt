// Fabric Console Host Agent
// Lightweight agent that runs on Linux hosts, collects security posture,
// and reports to the DPU Agent's local API.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nmelo/secure-infra/internal/hostagent"
	"github.com/nmelo/secure-infra/internal/version"
	"github.com/nmelo/secure-infra/pkg/posture"
	"github.com/nmelo/secure-infra/pkg/transport"
	"golang.org/x/crypto/ssh"
)

func main() {
	dpuAgent := flag.String("dpu-agent", "http://localhost:9443", "DPU Agent local API URL")
	interval := flag.Duration("interval", 5*time.Minute, "Posture refresh interval")
	oneshot := flag.Bool("oneshot", false, "Collect and report once, then exit")
	requestCertFlag := flag.Bool("request-cert", false, "Request and install host SSH certificate")
	keyType := flag.String("key-type", "ed25519", "SSH key type for certificate request")
	certDir := flag.String("cert-dir", "/etc/ssh", "Directory for SSH host certificates")
	showVersion := flag.Bool("version", false, "Show version and exit")
	forceTmfifo := flag.Bool("force-tmfifo", false, "Fail if tmfifo is not available (no network fallback)")
	forceNetwork := flag.Bool("force-network", false, "Use network enrollment even if tmfifo is available")
	forceComCh := flag.Bool("force-comch", false, "Force DOCA ComCh transport (requires BlueField PCIe connection)")
	docaPCIAddr := flag.String("doca-pci-addr", "", "PCI address of BlueField device (e.g., \"0000:01:00.0\")")
	docaServerName := flag.String("doca-server-name", "secure-infra", "ComCh server name to connect to")
	authKeyPath := flag.String("auth-key", "/etc/secureinfra/host-agent.key", "Path to host authentication key")
	pollInterval := flag.Duration("poll-interval", 30*time.Second, "Credential polling interval (HTTP transport only)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("host-agent v%s\n", version.Version)
		os.Exit(0)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	log.Printf("Host Agent v%s starting...", version.Version)

	// Handle certificate request mode (uses network)
	if *requestCertFlag {
		log.Printf("DPU Agent: %s", *dpuAgent)
		log.Printf("Hostname: %s", hostname)
		if err := requestCert(*dpuAgent, hostname, *keyType, *certDir); err != nil {
			log.Fatalf("Certificate request failed: %v", err)
		}
		log.Println("Host certificate installed successfully")
		return
	}

	// Build transport configuration
	transportCfg := &transport.Config{
		TmfifoPath:     "", // Use default
		DPUAddr:        *dpuAgent,
		Hostname:       hostname,
		ForceTmfifo:    *forceTmfifo,
		ForceNetwork:   *forceNetwork,
		ForceComCh:     *forceComCh,
		DOCAPCIAddr:    *docaPCIAddr,
		DOCAServerName: *docaServerName,
	}

	// Select transport via NewHostTransport
	t, err := transport.NewHostTransport(transportCfg)
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	log.Printf("Transport: %s", t.Type())
	if t.Type() == transport.TransportNetwork {
		log.Printf("DPU Agent: %s", *dpuAgent)
	}

	// Collect initial posture
	p := posture.Collect()
	log.Printf("Initial posture collected: hash=%s", p.Hash())

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	stopCh := make(chan struct{})

	// Run with the selected transport
	runWithTransport(t, hostname, p, *interval, *oneshot, *dpuAgent, *authKeyPath, *pollInterval, sigCh, stopCh)
}

// runWithTransport runs the Host Agent using the provided transport.
// This unified function handles both tmfifo and network transports.
func runWithTransport(t transport.Transport, hostname string, p *posture.Posture, interval time.Duration, oneshot bool, dpuAgentURL string, authKeyPath string, pollInterval time.Duration, sigCh <-chan os.Signal, stopCh chan struct{}) {
	ctx := context.Background()

	// For network transport, we use the legacy HTTP-based enrollment
	// until the full Transport-based protocol is implemented on the server side.
	if t.Type() == transport.TransportNetwork {
		runNetworkModeLegacy(dpuAgentURL, hostname, p, interval, oneshot, pollInterval, sigCh, stopCh)
		return
	}

	// Create client using the transport
	client := hostagent.NewClient(t, hostname, authKeyPath)

	// Connect the transport
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect transport: %v", err)
	}

	log.Printf("Enrolling with DPU Agent...")
	log.Printf("  Hostname: %s", hostname)
	log.Printf("  Transport: %s", t.Type())

	// Convert posture to JSON for enrollment
	postureJSON, err := json.Marshal(postureToPayload(p))
	if err != nil {
		log.Fatalf("Failed to marshal posture: %v", err)
	}

	// Enroll via transport
	hostID, dpuName, err := client.Enroll(ctx, postureJSON)
	if err != nil {
		log.Fatalf("Enrollment failed: %v", err)
	}

	log.Printf("Enrolled via %s", t.Type())
	log.Printf("Host ID: %s", hostID)
	if dpuName != "" {
		log.Printf("Paired with DPU: %s", dpuName)
	}

	// If oneshot mode, we're done
	if oneshot {
		log.Println("Oneshot mode: exiting after successful enrollment")
		client.Close()
		return
	}

	// Start listener for credential pushes
	client.StartListener()
	log.Printf("Listening for credential pushes via %s", t.Type())

	log.Printf("Host Agent running. Posture reports every %s.", interval)

	// Run posture loop
	go func() {
		collectPosture := func() json.RawMessage {
			p := posture.Collect()
			data, _ := json.Marshal(postureToPayload(p))
			return data
		}
		client.PostureLoop(interval, collectPosture, stopCh)
	}()

	// Wait for shutdown signal
	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)
	close(stopCh)
	client.Close()
}

// runNetworkModeLegacy runs the Host Agent using legacy HTTP for DPU communication.
// This preserves the existing network mode behavior until the Transport-based
// protocol is fully implemented on the server side.
func runNetworkModeLegacy(dpuAgent, hostname string, p *posture.Posture, interval time.Duration, oneshot bool, pollInterval time.Duration, sigCh <-chan os.Signal, stopCh chan struct{}) {
	log.Printf("Hostname: %s", hostname)

	// Register with DPU Agent via HTTP
	hostID, err := register(dpuAgent, hostname, p)
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	log.Printf("Registered as host %s via DPU Agent", hostID)

	// If oneshot mode, we're done
	if oneshot {
		log.Println("Oneshot mode: exiting after successful registration")
		return
	}

	// Create ticker for periodic posture collection
	postureTicker := time.NewTicker(interval)
	defer postureTicker.Stop()

	// Create ticker for credential polling (fallback when ComCh unavailable)
	credentialTicker := time.NewTicker(pollInterval)
	defer credentialTicker.Stop()

	log.Printf("Host Agent running. Posture reports every %s, credential polling every %s.", interval, pollInterval)

	for {
		select {
		case <-postureTicker.C:
			p := posture.Collect()
			if err := reportPosture(dpuAgent, hostname, p); err != nil {
				log.Printf("Warning: posture report failed: %v", err)
			} else {
				log.Printf("Posture reported: hash=%s", p.Hash())
			}

		case <-credentialTicker.C:
			if err := pollAndInstallCredentials(dpuAgent); err != nil {
				log.Printf("Warning: credential poll failed: %v", err)
			}

		case sig := <-sigCh:
			log.Printf("Received signal %v, shutting down...", sig)
			close(stopCh)
			return
		}
	}
}

// registerRequest is the JSON body for POST /local/v1/register
type registerRequest struct {
	Hostname string          `json:"hostname"`
	Posture  *posturePayload `json:"posture,omitempty"`
}

// registerResponse is the JSON response from POST /local/v1/register
type registerResponse struct {
	HostID          string `json:"host_id"`
	DPUName         string `json:"dpu_name"`
	RefreshInterval string `json:"refresh_interval,omitempty"`
}

// postureRequest is the JSON body for POST /local/v1/posture
type postureRequest struct {
	Hostname string          `json:"hostname"`
	Posture  *posturePayload `json:"posture"`
}

// posturePayload is the JSON structure for posture data
type posturePayload struct {
	SecureBoot     *bool  `json:"secure_boot"`
	DiskEncryption string `json:"disk_encryption"`
	OSVersion      string `json:"os_version"`
	KernelVersion  string `json:"kernel_version"`
	TPMPresent     *bool  `json:"tpm_present"`
}

// certRequest is the JSON body for POST /local/v1/cert
type certRequest struct {
	Hostname   string   `json:"hostname"`
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals,omitempty"`
	KeyType    string   `json:"key_type"`
}

// certResponse is the JSON response from POST /local/v1/cert
type certResponse struct {
	Certificate string `json:"certificate"`
	ValidUntil  string `json:"valid_until,omitempty"`
}

// errorResponse is the JSON structure for API errors
type errorResponse struct {
	Error string `json:"error"`
}

// register sends a registration request to the DPU Agent's local API.
// Returns the assigned host ID on success.
func register(dpuAgent, hostname string, p *posture.Posture) (string, error) {
	url := dpuAgent + "/local/v1/register"

	req := registerRequest{
		Hostname: hostname,
		Posture:  postureToPayload(p),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp errorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return "", fmt.Errorf("registration failed: %s", errResp.Error)
		}
		return "", fmt.Errorf("registration failed: HTTP %d", resp.StatusCode)
	}

	var regResp registerResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if regResp.DPUName != "" {
		log.Printf("Paired with DPU: %s", regResp.DPUName)
	}

	return regResp.HostID, nil
}

// reportPosture sends a posture update to the DPU Agent's local API.
func reportPosture(dpuAgent, hostname string, p *posture.Posture) error {
	url := dpuAgent + "/local/v1/posture"

	req := postureRequest{
		Hostname: hostname,
		Posture:  postureToPayload(p),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal posture: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp errorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("posture update failed: %s", errResp.Error)
		}
		return fmt.Errorf("posture update failed: HTTP %d", resp.StatusCode)
	}

	return nil
}

// requestCert requests a host SSH certificate from the DPU Agent.
// It generates an SSH keypair if needed, requests signing from the DPU Agent,
// and installs the returned certificate.
func requestCert(dpuAgent, hostname, keyType, certDir string) error {
	if keyType != "ed25519" {
		return fmt.Errorf("unsupported key type: %s (only ed25519 is supported)", keyType)
	}

	// Key and cert file paths
	keyPath := filepath.Join(certDir, "ssh_host_ed25519_key")
	pubKeyPath := keyPath + ".pub"
	certPath := keyPath + "-cert.pub"

	// Check if key exists, generate if not
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read public key: %w", err)
		}
		// Generate new keypair
		log.Printf("Generating new %s host keypair...", keyType)
		pubKeyBytes, err = generateHostKey(keyPath, keyType)
		if err != nil {
			return fmt.Errorf("failed to generate host key: %w", err)
		}
	}

	pubKeyStr := string(bytes.TrimSpace(pubKeyBytes))
	log.Printf("Requesting certificate for host: %s", hostname)

	// Request certificate from DPU Agent
	url := dpuAgent + "/local/v1/cert"
	req := certRequest{
		Hostname:   hostname,
		PublicKey:  pubKeyStr,
		Principals: []string{hostname},
		KeyType:    keyType,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp errorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("certificate request failed: %s", errResp.Error)
		}
		return fmt.Errorf("certificate request failed: HTTP %d", resp.StatusCode)
	}

	var certResp certResponse
	if err := json.Unmarshal(respBody, &certResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Write certificate to file
	certData := []byte(certResp.Certificate + "\n")
	if err := os.WriteFile(certPath, certData, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	log.Printf("Certificate installed: %s", certPath)
	if certResp.ValidUntil != "" {
		log.Printf("Valid until: %s", certResp.ValidUntil)
	}

	return nil
}

// generateHostKey generates a new SSH host keypair.
// Returns the public key in OpenSSH format.
func generateHostKey(keyPath, keyType string) ([]byte, error) {
	if keyType != "ed25519" {
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Generate ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Convert to SSH format
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}

	// Marshal private key to OpenSSH format
	privPEMBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Write private key with restrictive permissions
	privKeyBytes := pem.EncodeToMemory(privPEMBlock)
	if err := os.WriteFile(keyPath, privKeyBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPub)
	pubKeyPath := keyPath + ".pub"
	if err := os.WriteFile(pubKeyPath, pubKeyBytes, 0644); err != nil {
		return nil, fmt.Errorf("failed to write public key: %w", err)
	}

	log.Printf("Generated host keypair: %s", keyPath)
	return pubKeyBytes, nil
}

// postureToPayload converts a posture.Posture to the API payload format.
func postureToPayload(p *posture.Posture) *posturePayload {
	return &posturePayload{
		SecureBoot:     p.SecureBoot,
		DiskEncryption: p.DiskEncryption,
		OSVersion:      p.OSVersion,
		KernelVersion:  p.KernelVersion,
		TPMPresent:     p.TPMPresent,
	}
}

// credentialsPendingResponse is the JSON response from GET /local/v1/credentials/pending
type credentialsPendingResponse struct {
	Credentials []pendingCredential `json:"credentials"`
}

// pendingCredential represents a credential from the pending queue
type pendingCredential struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Data []byte `json:"data"`
}

// pollAndInstallCredentials polls for pending credentials and installs them locally.
func pollAndInstallCredentials(dpuAgent string) error {
	url := dpuAgent + "/local/v1/credentials/pending"

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to poll credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp errorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("credential poll failed: %s", errResp.Error)
		}
		return fmt.Errorf("credential poll failed: HTTP %d", resp.StatusCode)
	}

	var credsResp credentialsPendingResponse
	if err := json.NewDecoder(resp.Body).Decode(&credsResp); err != nil {
		return fmt.Errorf("failed to parse credentials response: %w", err)
	}

	if len(credsResp.Credentials) == 0 {
		return nil // No pending credentials
	}

	log.Printf("Received %d pending credential(s)", len(credsResp.Credentials))

	for _, cred := range credsResp.Credentials {
		if err := installCredential(cred.Type, cred.Name, cred.Data); err != nil {
			log.Printf("Warning: failed to install credential %s (%s): %v", cred.Name, cred.Type, err)
		} else {
			log.Printf("Installed credential: %s (%s)", cred.Name, cred.Type)
		}
	}

	return nil
}

// installCredential installs a credential based on its type.
func installCredential(credType, credName string, data []byte) error {
	switch credType {
	case "ssh-ca":
		return installSSHCA(credName, data)
	default:
		return fmt.Errorf("unsupported credential type: %s", credType)
	}
}

// installSSHCA installs an SSH CA public key for host authentication.
func installSSHCA(name string, data []byte) error {
	// Install to /etc/ssh/trusted_user_ca_keys.d/<name>.pub
	caDir := "/etc/ssh/trusted_user_ca_keys.d"
	if err := os.MkdirAll(caDir, 0755); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}

	caPath := filepath.Join(caDir, name+".pub")
	if err := os.WriteFile(caPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	log.Printf("SSH CA installed: %s", caPath)
	return nil
}
