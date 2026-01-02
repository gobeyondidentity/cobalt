package localapi

import (
	"context"
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

	"github.com/nmelo/secure-infra/internal/agent/tmfifo"
)

// Config holds configuration for the local API server.
type Config struct {
	// ListenAddr is the address to listen on (e.g., "localhost:9443" or "unix:///var/run/dpu-agent.sock")
	ListenAddr string

	// ControlPlaneURL is the Control Plane API endpoint
	ControlPlaneURL string

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

	// AttestationFetcher is a function to get current attestation status
	AttestationFetcher func(ctx context.Context) (*AttestationInfo, error)

	// HTTPClient for Control Plane communication (allows mocking)
	HTTPClient *http.Client
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

	// tmfifoListener is the optional tmfifo listener for host communication
	tmfifoListener *tmfifo.Listener

	// credentialQueue holds credentials waiting to be retrieved by the Host Agent
	credentialQueue []*QueuedCredential
	credentialMu    sync.RWMutex
}

// NewServer creates a new local API server.
func NewServer(cfg *Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "localhost:9443"
	}
	if cfg.ControlPlaneURL == "" {
		return nil, fmt.Errorf("control plane URL is required")
	}
	if cfg.DPUName == "" {
		return nil, fmt.Errorf("DPU name is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	s := &Server{
		config: cfg,
		controlPlane: &ControlPlaneClient{
			baseURL:    strings.TrimSuffix(cfg.ControlPlaneURL, "/"),
			httpClient: httpClient,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /local/v1/health", s.handleHealth)
	mux.HandleFunc("POST /local/v1/register", s.handleRegister)
	mux.HandleFunc("POST /local/v1/posture", s.handlePosture)
	mux.HandleFunc("POST /local/v1/cert", s.handleCert)
	mux.HandleFunc("POST /local/v1/credential", s.handleCredentialPush)

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

// localhostMiddleware ensures requests only come from localhost (for TCP listeners).
func (s *Server) localhostMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Unix sockets are inherently local, skip check
		if strings.HasPrefix(s.config.ListenAddr, "unix://") {
			next.ServeHTTP(w, r)
			return
		}

		// For TCP, verify the connection is from localhost
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

		if !ip.IsLoopback() {
			log.Printf("Local API: rejected non-local request from %s", r.RemoteAddr)
			s.writeError(w, http.StatusForbidden, "local API only accepts connections from localhost")
			return
		}

		next.ServeHTTP(w, r)
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
func (s *Server) setPairedHost(hostname, hostID string) bool {
	s.pairedMu.Lock()
	defer s.pairedMu.Unlock()

	if s.pairedHost != "" && s.pairedHost != hostname {
		return false
	}

	s.pairedHost = hostname
	s.pairedHostID = hostID
	return true
}

// getPairedHostID returns the paired host ID.
func (s *Server) getPairedHostID() string {
	s.pairedMu.RLock()
	defer s.pairedMu.RUnlock()
	return s.pairedHostID
}

// SetTmfifoListener sets the tmfifo listener for credential push operations.
func (s *Server) SetTmfifoListener(listener *tmfifo.Listener) {
	s.tmfifoListener = listener
}

// GetTmfifoListener returns the configured tmfifo listener.
func (s *Server) GetTmfifoListener() *tmfifo.Listener {
	return s.tmfifoListener
}

// PushCredential sends a credential to the paired Host Agent.
// Uses tmfifo if available, otherwise queues for Host Agent retrieval on next poll.
func (s *Server) PushCredential(ctx context.Context, credType, credName string, data []byte) (*CredentialPushResult, error) {
	// Check if host is paired
	s.pairedMu.RLock()
	hostname := s.pairedHost
	s.pairedMu.RUnlock()

	if hostname == "" {
		return nil, fmt.Errorf("no host paired with this DPU")
	}

	// If tmfifo listener is available and connected, use it for direct push
	if s.tmfifoListener != nil {
		result, err := s.tmfifoListener.PushCredential(credType, credName, data)
		if err == nil {
			return &CredentialPushResult{
				Success:       result.Success,
				Message:       result.Message,
				InstalledPath: result.InstalledPath,
				SshdReloaded:  result.SshdReloaded,
			}, nil
		}
		// tmfifo push failed, fall through to queue
		log.Printf("tmfifo push failed, queueing for retrieval: %v", err)
	}

	// Queue the credential for Host Agent retrieval on next poll
	return s.queueCredentialForHost(hostname, credType, credName, data)
}

// queueCredentialForHost stores a credential for later retrieval by the Host Agent.
// This is used when tmfifo is not available or not connected.
func (s *Server) queueCredentialForHost(hostname, credType, credName string, data []byte) (*CredentialPushResult, error) {
	s.credentialMu.Lock()
	defer s.credentialMu.Unlock()

	// Add to queue
	s.credentialQueue = append(s.credentialQueue, &QueuedCredential{
		CredType: credType,
		CredName: credName,
		Data:     data,
	})

	log.Printf("Queued %s credential '%s' for host '%s' (queue size: %d)",
		credType, credName, hostname, len(s.credentialQueue))

	return &CredentialPushResult{
		Success: true,
		Message: fmt.Sprintf("Credential queued for host '%s'. Host Agent will install on next poll.", hostname),
	}, nil
}

// GetQueuedCredentials returns and clears all queued credentials for the paired host.
func (s *Server) GetQueuedCredentials() []*QueuedCredential {
	s.credentialMu.Lock()
	defer s.credentialMu.Unlock()

	creds := s.credentialQueue
	s.credentialQueue = nil
	return creds
}
