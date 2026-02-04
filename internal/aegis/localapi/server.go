package localapi

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
	"github.com/gobeyondidentity/cobalt/pkg/transport"
)

// Config holds configuration for the local API server.
type Config struct {
	// ListenAddr is the address to listen on (e.g., "localhost:9443" or "unix:///var/run/dpu-agent.sock")
	ListenAddr string

	// ServerURL is the Nexus server URL for proxied requests
	ServerURL string

	// DPUName is this DPU's registered name
	DPUName string

	// DPUID is this DPU's unique identifier
	DPUID string

	// DPUSerial is this DPU's serial number (for attestation binding)
	DPUSerial string

	// TLSConfig for HTTPS (optional, recommended for TCP listeners)
	TLSConfig *tls.Config

	// AllowedHostnames restricts which hostnames can register (empty = allow all)
	AllowedHostnames []string

	// AllowTmfifoNet permits connections from tmfifo_net subnet (192.168.100.0/30).
	// Enable this when using IP-over-PCIe via rshim's tmfifo_net0 interface.
	AllowTmfifoNet bool

	// AttestationFetcher is a function to get current attestation status
	AttestationFetcher func(ctx context.Context) (*AttestationInfo, error)

	// HTTPClient for Control Plane communication (allows mocking, deprecated)
	// Deprecated: Use DPoPClient instead for authenticated requests.
	HTTPClient *http.Client

	// DPoPClient is the DPoP-enabled HTTP client for authenticated nexus API requests.
	// If set, this takes precedence over HTTPClient.
	DPoPClient *dpop.Client

	// Store is the SQLite store for state persistence (optional).
	// If provided, pairing state and credential queue are persisted across restarts.
	Store *store.Store
}

// Server is the local HTTP API server for Host Agent communication.
type Server struct {
	config   *Config
	server   *http.Server
	listener net.Listener

	// pairedHost tracks the hostname that has registered with this DPU
	// Only one host can be paired at a time
	pairedHost   string
	pairedHostID string
	pairedMu     sync.RWMutex

	// controlPlane is the client for proxying requests
	controlPlane *ControlPlaneClient

	// hostListener is the optional transport listener for host communication.
	// Used for credential push when a direct transport connection is available.
	hostListener transport.TransportListener

	// activeTransport is the current transport connection to the host.
	// Set when a host connects via the transport listener.
	activeTransport          transport.Transport
	transportAuthenticated   bool
	transportMu              sync.RWMutex

	// credentialQueue holds credentials waiting to be retrieved by the Host Agent
	credentialQueue []*QueuedCredential
	credentialMu    sync.RWMutex

	// pendingAcks tracks credential pushes waiting for acknowledgment.
	// Key is the message ID, value is a channel that receives the ack result.
	pendingAcks   map[string]chan *CredentialAckResult
	pendingAcksMu sync.Mutex

	// store is the SQLite store for state persistence (optional)
	store *store.Store
}

// CredentialAckResult contains the result of a credential installation from sentry.
type CredentialAckResult struct {
	Success       bool
	InstalledPath string
	Error         string
}

// NewServer creates a new local API server.
func NewServer(cfg *Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "localhost:9443"
	}
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("server URL is required")
	}
	if cfg.DPUName == "" {
		return nil, fmt.Errorf("DPU name is required")
	}

	// Build control plane client
	cpClient := &ControlPlaneClient{
		baseURL: strings.TrimSuffix(cfg.ServerURL, "/"),
	}

	// Prefer DPoP client if available, otherwise fall back to plain HTTP client
	if cfg.DPoPClient != nil {
		cpClient.dpopClient = cfg.DPoPClient
		log.Printf("localapi: using DPoP-authenticated HTTP client for nexus API")
	} else if cfg.HTTPClient != nil {
		cpClient.httpClient = cfg.HTTPClient
		log.Printf("localapi: WARNING: using unauthenticated HTTP client (no DPoP)")
	} else {
		cpClient.httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
		log.Printf("localapi: WARNING: using default unauthenticated HTTP client (no DPoP)")
	}

	s := &Server{
		config:       cfg,
		controlPlane: cpClient,
		store:        cfg.Store,
		pendingAcks:  make(map[string]chan *CredentialAckResult),
	}

	// Restore state from store if available
	if err := s.restoreState(); err != nil {
		return nil, fmt.Errorf("failed to restore state: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /local/v1/health", s.handleHealth)
	mux.HandleFunc("POST /local/v1/register", s.handleRegister)
	mux.HandleFunc("POST /local/v1/posture", s.handlePosture)
	mux.HandleFunc("POST /local/v1/cert", s.handleCert)
	mux.HandleFunc("POST /local/v1/credential", s.handleCredentialPush)
	mux.HandleFunc("GET /local/v1/credentials/pending", s.handleCredentialsPending)

	s.server = &http.Server{
		Handler:      s.loggingMiddleware(s.localhostMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// Start starts the local API server.
func (s *Server) Start() error {
	addr := s.config.ListenAddr

	var err error
	if strings.HasPrefix(addr, "unix://") {
		socketPath := strings.TrimPrefix(addr, "unix://")
		// Remove existing socket file if present
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove existing socket: %w", err)
		}
		s.listener, err = net.Listen("unix", socketPath)
		if err != nil {
			return fmt.Errorf("failed to listen on unix socket %s: %w", socketPath, err)
		}
		// Set socket permissions (only owner can access)
		if err := os.Chmod(socketPath, 0600); err != nil {
			s.listener.Close()
			return fmt.Errorf("failed to set socket permissions: %w", err)
		}
		log.Printf("Local API listening on unix://%s", socketPath)
	} else {
		s.listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		log.Printf("Local API listening on %s", addr)
	}

	go func() {
		var serveErr error
		if s.config.TLSConfig != nil {
			s.listener = tls.NewListener(s.listener, s.config.TLSConfig)
			serveErr = s.server.Serve(s.listener)
		} else {
			serveErr = s.server.Serve(s.listener)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("Local API server error: %v", serveErr)
		}
	}()

	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// loggingMiddleware logs all requests.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Local API: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("Local API: %s %s completed in %v", r.Method, r.URL.Path, time.Since(start))
	})
}

// tmfifoNetSubnet is the IP range used by rshim's tmfifo_net0 interface (IP-over-PCIe).
var tmfifoNetSubnet = mustParseCIDR("192.168.100.0/30")

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

// localhostMiddleware ensures requests only come from localhost or allowed subnets (for TCP listeners).
func (s *Server) localhostMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Unix sockets are inherently local, skip check
		if strings.HasPrefix(s.config.ListenAddr, "unix://") {
			next.ServeHTTP(w, r)
			return
		}

		// For TCP, verify the connection is from localhost or allowed subnet
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			s.writeError(w, http.StatusForbidden, "invalid remote address")
			return
		}

		ip := net.ParseIP(host)
		if ip == nil {
			s.writeError(w, http.StatusForbidden, "invalid remote IP")
			return
		}

		// Allow loopback
		if ip.IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}

		// Allow tmfifo_net subnet if configured (IP-over-PCIe via rshim)
		if s.config.AllowTmfifoNet && tmfifoNetSubnet.Contains(ip) {
			next.ServeHTTP(w, r)
			return
		}

		log.Printf("Local API: rejected non-local request from %s", r.RemoteAddr)
		s.writeError(w, http.StatusForbidden, "local API only accepts connections from localhost")
	})
}

// writeJSON writes a JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Local API: failed to encode response: %v", err)
	}
}

// writeError writes a JSON error response.
func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, ErrorResponse{Error: message})
}

// getAttestation fetches current DPU attestation status.
func (s *Server) getAttestation(ctx context.Context) *AttestationInfo {
	if s.config.AttestationFetcher == nil {
		return &AttestationInfo{
			Status:      "unavailable",
			LastChecked: time.Now(),
		}
	}

	info, err := s.config.AttestationFetcher(ctx)
	if err != nil {
		log.Printf("Local API: attestation fetch failed: %v", err)
		return &AttestationInfo{
			Status:      "unavailable",
			LastChecked: time.Now(),
		}
	}

	return info
}

// isHostnameAllowed checks if a hostname is in the allowlist.
func (s *Server) isHostnameAllowed(hostname string) bool {
	if len(s.config.AllowedHostnames) == 0 {
		return true
	}
	for _, allowed := range s.config.AllowedHostnames {
		if allowed == hostname {
			return true
		}
	}
	return false
}

// isPairedHost checks if the hostname matches the paired host.
func (s *Server) isPairedHost(hostname string) bool {
	s.pairedMu.RLock()
	defer s.pairedMu.RUnlock()
	return s.pairedHost == "" || s.pairedHost == hostname
}

// setPairedHost sets the paired host (only if not already paired).
// Persists the pairing to the store if configured.
func (s *Server) setPairedHost(hostname, hostID string) bool {
	s.pairedMu.Lock()
	defer s.pairedMu.Unlock()

	if s.pairedHost != "" && s.pairedHost != hostname {
		return false
	}

	s.pairedHost = hostname
	s.pairedHostID = hostID

	// Persist pairing to store
	if err := s.persistPairing(hostname, hostID); err != nil {
		log.Printf("localapi: warning: failed to persist pairing: %v", err)
	}

	return true
}

// getPairedHostID returns the paired host ID.
func (s *Server) getPairedHostID() string {
	s.pairedMu.RLock()
	defer s.pairedMu.RUnlock()
	return s.pairedHostID
}

// SetHostListener sets the transport listener for credential push operations.
// The listener is used to accept connections from Host Agents.
func (s *Server) SetHostListener(listener transport.TransportListener) {
	s.hostListener = listener
}

// GetHostListener returns the configured transport listener.
func (s *Server) GetHostListener() transport.TransportListener {
	return s.hostListener
}

// SetActiveTransport sets the active transport connection to the host.
// This is called after authentication completes successfully.
// The transport is marked as authenticated, enabling credential push.
func (s *Server) SetActiveTransport(t transport.Transport) {
	s.transportMu.Lock()
	defer s.transportMu.Unlock()
	s.activeTransport = t
	s.transportAuthenticated = true
}

// ClearActiveTransport clears the active transport and resets authentication state,
// but only if the provided transport matches the current active transport.
// This prevents a race where an old connection's cleanup clears a newer connection's state.
// This must be called when a connection closes or errors to prevent sending
// credentials on an unauthenticated or dead connection.
func (s *Server) ClearActiveTransport(t transport.Transport) {
	s.transportMu.Lock()
	defer s.transportMu.Unlock()
	// Only clear if this is the current active transport
	// This prevents old connection cleanup from clearing newer connections
	if s.activeTransport == t {
		s.activeTransport = nil
		s.transportAuthenticated = false
	}
}

// IsTransportAuthenticated returns whether the active transport has completed authentication.
func (s *Server) IsTransportAuthenticated() bool {
	s.transportMu.RLock()
	defer s.transportMu.RUnlock()
	return s.transportAuthenticated
}

// GetActiveTransport returns the active transport connection, if any.
func (s *Server) GetActiveTransport() transport.Transport {
	s.transportMu.RLock()
	defer s.transportMu.RUnlock()
	return s.activeTransport
}

// credentialAckTimeout is how long to wait for a CREDENTIAL_ACK from sentry.
const credentialAckTimeout = 10 * time.Second

// PushCredential sends a credential to the paired Host Agent.
// Uses the active transport if available, otherwise queues for Host Agent retrieval on next poll.
// When using transport, waits for CREDENTIAL_ACK to confirm installation.
func (s *Server) PushCredential(ctx context.Context, credType, credName string, data []byte) (*CredentialPushResult, error) {
	log.Printf("[CRED-DELIVERY] localapi: pushing credential type=%s name=%s", credType, credName)

	// Check if host is paired
	s.pairedMu.RLock()
	hostname := s.pairedHost
	s.pairedMu.RUnlock()

	if hostname == "" {
		log.Printf("[CRED-DELIVERY] localapi: no host paired with this DPU")
		return nil, fmt.Errorf("localapi: no host paired with this DPU")
	}

	// If we have an active AND authenticated transport connection, use it for direct push.
	// Both conditions must be true to prevent sending on an unauthenticated connection
	// (e.g., during the window between Accept() and auth completion).
	s.transportMu.RLock()
	activeTransport := s.activeTransport
	isAuthenticated := s.transportAuthenticated
	s.transportMu.RUnlock()

	if activeTransport != nil && isAuthenticated {
		log.Printf("[CRED-DELIVERY] localapi: using active transport (%s) for push", activeTransport.Type())
		result, err := s.pushCredentialViaTransportSync(ctx, activeTransport, credType, credName, data)
		if err == nil {
			return result, nil
		}
		// Transport push failed, fall through to queue
		log.Printf("[CRED-DELIVERY] localapi: transport push failed, queueing for retrieval: %v", err)
	} else if activeTransport != nil && !isAuthenticated {
		log.Printf("[CRED-DELIVERY] localapi: transport exists but not authenticated yet, queueing credential")
	}

	// Queue the credential for Host Agent retrieval on next poll
	return s.queueCredentialForHost(hostname, credType, credName, data)
}

// pushCredentialViaTransportSync sends a credential push message over the transport
// and waits for the CREDENTIAL_ACK from sentry to confirm installation.
func (s *Server) pushCredentialViaTransportSync(ctx context.Context, t transport.Transport, credType, credName string, data []byte) (*CredentialPushResult, error) {
	log.Printf("[CRED-DELIVERY] localapi: sending CREDENTIAL_PUSH message via %s transport", t.Type())

	payload, err := json.Marshal(map[string]interface{}{
		"credential_type": credType,
		"credential_name": credName,
		"data":            data,
	})
	if err != nil {
		return nil, fmt.Errorf("localapi: marshal credential payload: %w", err)
	}

	msgID := generateNonce()
	msg := &transport.Message{
		Type:    transport.MessageCredentialPush,
		Payload: payload,
		ID:      msgID,
	}

	// Register for ack before sending to avoid race
	ackCh := make(chan *CredentialAckResult, 1)
	s.pendingAcksMu.Lock()
	s.pendingAcks[msgID] = ackCh
	s.pendingAcksMu.Unlock()

	// Clean up on exit
	defer func() {
		s.pendingAcksMu.Lock()
		delete(s.pendingAcks, msgID)
		s.pendingAcksMu.Unlock()
	}()

	// Send the message
	if err := t.Send(msg); err != nil {
		return nil, fmt.Errorf("localapi: transport send failed: %w", err)
	}

	log.Printf("[CRED-DELIVERY] localapi: credential sent, waiting for ack (msgID=%s)", msgID)

	// Wait for ack with timeout
	timeout := credentialAckTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	select {
	case ack := <-ackCh:
		if ack.Success {
			log.Printf("[CRED-DELIVERY] localapi: credential installed at %s", ack.InstalledPath)
			return &CredentialPushResult{
				Success:       true,
				Message:       fmt.Sprintf("Credential installed at %s", ack.InstalledPath),
				InstalledPath: ack.InstalledPath,
				SshdReloaded:  true, // Sentry always reloads sshd on success
			}, nil
		}
		log.Printf("[CRED-DELIVERY] localapi: credential installation failed: %s", ack.Error)
		return &CredentialPushResult{
			Success: false,
			Message: fmt.Sprintf("Credential installation failed: %s", ack.Error),
		}, nil
	case <-time.After(timeout):
		log.Printf("[CRED-DELIVERY] localapi: timeout waiting for ack (msgID=%s)", msgID)
		return nil, fmt.Errorf("localapi: timeout waiting for credential ack")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// HandleCredentialAck processes a CREDENTIAL_ACK message from sentry.
// This should be called by the transport message handler when an ack is received.
func (s *Server) HandleCredentialAck(msgID string, success bool, installedPath, errMsg string) {
	s.pendingAcksMu.Lock()
	ackCh, exists := s.pendingAcks[msgID]
	s.pendingAcksMu.Unlock()

	if !exists {
		log.Printf("[CRED-DELIVERY] localapi: received ack for unknown msgID=%s (may have timed out)", msgID)
		return
	}

	// Non-blocking send in case the waiter already timed out
	select {
	case ackCh <- &CredentialAckResult{
		Success:       success,
		InstalledPath: installedPath,
		Error:         errMsg,
	}:
		log.Printf("[CRED-DELIVERY] localapi: ack delivered to waiter (msgID=%s)", msgID)
	default:
		log.Printf("[CRED-DELIVERY] localapi: ack channel full or closed (msgID=%s)", msgID)
	}
}

// generateNonce creates a random nonce for message replay protection.
func generateNonce() string {
	b := make([]byte, 16)
	// Note: ignoring error since rand.Read always succeeds on supported platforms
	_, _ = cryptoRand.Read(b)
	return fmt.Sprintf("%x", b)
}

// queueCredentialForHost stores a credential for later retrieval by the Host Agent.
// This is used when tmfifo is not available or not connected.
// Persists the credential to the store if configured.
func (s *Server) queueCredentialForHost(hostname, credType, credName string, data []byte) (*CredentialPushResult, error) {
	s.credentialMu.Lock()
	defer s.credentialMu.Unlock()

	// Add to in-memory queue
	s.credentialQueue = append(s.credentialQueue, &QueuedCredential{
		CredType: credType,
		CredName: credName,
		Data:     data,
	})

	// Persist to store
	if err := s.persistCredential(credType, credName, data); err != nil {
		log.Printf("localapi: warning: failed to persist credential: %v", err)
	}

	log.Printf("Queued %s credential '%s' for host '%s' (queue size: %d)",
		credType, credName, hostname, len(s.credentialQueue))

	return &CredentialPushResult{
		Success: true,
		Message: fmt.Sprintf("Credential queued for host '%s'. Host Agent will install on next poll.", hostname),
	}, nil
}

// GetQueuedCredentials returns and clears all queued credentials for the paired host.
// Clears the credentials from the persistent store as well.
func (s *Server) GetQueuedCredentials() []*QueuedCredential {
	s.credentialMu.Lock()
	defer s.credentialMu.Unlock()

	creds := s.credentialQueue
	s.credentialQueue = nil

	// Clear from persistent store
	if err := s.clearPersistedCredentials(); err != nil {
		log.Printf("localapi: warning: failed to clear persisted credentials: %v", err)
	}

	return creds
}

// RegisterViaTransport handles host registration received via ComCh or other transport.
// This replicates the logic from handleRegister but accepts parameters directly
// instead of parsing from an HTTP request.
func (s *Server) RegisterViaTransport(ctx context.Context, hostname string, posture *PosturePayload) (*RegisterResponse, error) {
	// Validate request
	if hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}

	// Check hostname allowlist
	if !s.isHostnameAllowed(hostname) {
		log.Printf("Transport: registration rejected for hostname %s (not in allowlist)", hostname)
		return nil, fmt.Errorf("hostname not allowed to register with this DPU")
	}

	// Check if another host is already paired
	if !s.isPairedHost(hostname) {
		log.Printf("Transport: registration rejected for %s (DPU already paired with different host)", hostname)
		return nil, fmt.Errorf("DPU is already paired with a different host")
	}

	// Get current attestation status
	attestation := s.getAttestation(ctx)
	log.Printf("Transport: registering host %s with attestation status %s", hostname, attestation.Status)

	// Build proxied request with DPU identity
	proxiedReq := ProxiedRegisterRequest{
		Hostname:          hostname,
		Posture:           posture,
		DPUName:           s.config.DPUName,
		DPUID:             s.config.DPUID,
		DPUSerial:         s.config.DPUSerial,
		AttestationStatus: attestation.Status,
	}

	// Proxy to Control Plane
	resp, err := s.controlPlane.RegisterHost(ctx, &proxiedReq)
	if err != nil {
		log.Printf("Transport: Control Plane registration failed: %v", err)
		return nil, fmt.Errorf("Control Plane registration failed: %w", err)
	}

	// Record the pairing
	if !s.setPairedHost(hostname, resp.HostID) {
		// Race condition: another registration succeeded first
		return nil, fmt.Errorf("DPU was paired with different host during registration")
	}

	log.Printf("Transport: host %s registered successfully as %s", hostname, resp.HostID)

	return &RegisterResponse{
		HostID:  resp.HostID,
		DPUName: s.config.DPUName,
	}, nil
}

// restoreState restores pairing and credential queue state from the store.
func (s *Server) restoreState() error {
	if s.store == nil {
		return nil
	}

	// Restore paired host from store
	host, err := s.store.GetAgentHostByDPU(s.config.DPUName)
	if err == nil && host != nil {
		s.pairedHost = host.Hostname
		s.pairedHostID = host.ID
		log.Printf("localapi: restored pairing with host '%s' (ID: %s)", host.Hostname, host.ID)
	}

	// Restore credential queue from store
	creds, err := s.store.GetQueuedCredentials(s.config.DPUName)
	if err != nil {
		return fmt.Errorf("failed to restore credential queue: %w", err)
	}
	if len(creds) > 0 {
		s.credentialMu.Lock()
		for _, c := range creds {
			s.credentialQueue = append(s.credentialQueue, &QueuedCredential{
				CredType: c.CredType,
				CredName: c.CredName,
				Data:     c.Data,
			})
		}
		s.credentialMu.Unlock()
		log.Printf("localapi: restored %d queued credentials from store", len(creds))
	}

	return nil
}

// persistPairing saves the pairing state to the store.
func (s *Server) persistPairing(hostname, hostID string) error {
	if s.store == nil {
		return nil
	}
	return s.store.UpdateAgentHostByDPU(s.config.DPUName, s.config.DPUID, hostname, hostID)
}

// persistCredential adds a credential to the persistent queue.
func (s *Server) persistCredential(credType, credName string, data []byte) error {
	if s.store == nil {
		return nil
	}
	return s.store.QueueCredential(s.config.DPUName, credType, credName, data)
}

// clearPersistedCredentials removes all credentials from the persistent queue.
func (s *Server) clearPersistedCredentials() error {
	if s.store == nil {
		return nil
	}
	return s.store.ClearQueuedCredentials(s.config.DPUName)
}
