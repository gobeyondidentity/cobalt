// Package localapi provides the HTTP REST API for host-agent communication.
// This enables the dpuemu to accept registrations and posture reports from
// host-agent instances during development and testing.
package localapi

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gobeyondidentity/secure-infra/dpuemu/internal/fixture"
	"github.com/gobeyondidentity/secure-infra/internal/version"
)

// Server is the HTTP server for the local API.
type Server struct {
	fixture         *fixture.Fixture
	controlPlaneURL string
	httpClient      *http.Client
	mux             *http.ServeMux

	mu    sync.RWMutex
	hosts map[string]*hostInfo // hostname -> host info
}

// hostInfo stores registered host information.
type hostInfo struct {
	HostID    string
	Hostname  string
	Posture   *posturePayload
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Request/response types matching host-agent expectations.

type registerRequest struct {
	Hostname string          `json:"hostname"`
	Posture  *posturePayload `json:"posture,omitempty"`
}

type registerResponse struct {
	HostID          string `json:"host_id"`
	DPUName         string `json:"dpu_name"`
	RefreshInterval string `json:"refresh_interval,omitempty"`
}

type postureRequest struct {
	Hostname string          `json:"hostname"`
	Posture  *posturePayload `json:"posture"`
}

type certRequest struct {
	Hostname   string   `json:"hostname"`
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals,omitempty"`
	KeyType    string   `json:"key_type"`
}

type certResponse struct {
	Certificate string `json:"certificate"`
	ValidUntil  string `json:"valid_until,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type posturePayload struct {
	SecureBoot     *bool  `json:"secure_boot"`
	DiskEncryption string `json:"disk_encryption"`
	OSVersion      string `json:"os_version"`
	KernelVersion  string `json:"kernel_version"`
	TPMPresent     *bool  `json:"tpm_present"`
}

// New creates a new local API server.
// If controlPlaneURL is non-empty, host registrations will be forwarded to the control plane.
func New(fix *fixture.Fixture, controlPlaneURL string) *Server {
	s := &Server{
		fixture:         fix,
		controlPlaneURL: controlPlaneURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		mux:   http.NewServeMux(),
		hosts: make(map[string]*hostInfo),
	}

	s.mux.HandleFunc("/local/v1/register", s.handleRegister)
	s.mux.HandleFunc("/local/v1/posture", s.handlePosture)
	s.mux.HandleFunc("/local/v1/cert", s.handleCert)

	// Health endpoint (no auth required, consistent with nexus)
	s.mux.HandleFunc("/health", s.handleHealth)

	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// handleHealth returns 200 OK when the server is running.
// No auth required, consistent with nexus health endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version.Version,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if host already exists
	existing, exists := s.hosts[req.Hostname]
	if exists {
		// Update posture if provided
		if req.Posture != nil {
			existing.Posture = req.Posture
			existing.UpdatedAt = time.Now()
		}

		resp := registerResponse{
			HostID:          existing.HostID,
			DPUName:         s.getDPUName(),
			RefreshInterval: "5m",
		}

		log.Printf("[localapi] register: existing host %s (id=%s)", req.Hostname, existing.HostID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Create new host
	hostID := generateHostID()
	now := time.Now()
	s.hosts[req.Hostname] = &hostInfo{
		HostID:    hostID,
		Hostname:  req.Hostname,
		Posture:   req.Posture,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Relay registration to control plane (fire-and-forget)
	if s.controlPlaneURL != "" {
		go s.relayRegistration(req.Hostname, req.Posture)
	}

	resp := registerResponse{
		HostID:          hostID,
		DPUName:         s.getDPUName(),
		RefreshInterval: "5m",
	}

	log.Printf("[localapi] register: new host %s (id=%s)", req.Hostname, hostID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req postureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Update posture for host (create if not exists for flexibility)
	host, exists := s.hosts[req.Hostname]
	if !exists {
		hostID := generateHostID()
		now := time.Now()
		s.hosts[req.Hostname] = &hostInfo{
			HostID:    hostID,
			Hostname:  req.Hostname,
			Posture:   req.Posture,
			CreatedAt: now,
			UpdatedAt: now,
		}
		log.Printf("[localapi] posture: auto-registered host %s (id=%s)", req.Hostname, hostID)
	} else {
		host.Posture = req.Posture
		host.UpdatedAt = time.Now()
		log.Printf("[localapi] posture: updated host %s", req.Hostname)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req certRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "public_key is required")
		return
	}

	// Generate mock certificate response
	validUntil := time.Now().Add(8 * time.Hour)

	resp := certResponse{
		Certificate: "ssh-ed25519-cert-v01@openssh.com MOCK_CERTIFICATE_DATA",
		ValidUntil:  validUntil.Format(time.RFC3339),
	}

	log.Printf("[localapi] cert: issued mock certificate for host %s", req.Hostname)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// getDPUName returns the DPU name from the fixture or a default.
func (s *Server) getDPUName() string {
	if s.fixture != nil && s.fixture.SystemInfo != nil && s.fixture.SystemInfo.Hostname != "" {
		return s.fixture.SystemInfo.Hostname
	}
	return "dpuemu"
}

// generateHostID generates a random host ID.
func generateHostID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return "host_" + hex.EncodeToString(b)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{Error: message})
}

// controlPlaneRegisterRequest matches the control plane's hostRegisterRequest format.
type controlPlaneRegisterRequest struct {
	DPUName  string          `json:"dpu_name"`
	Hostname string          `json:"hostname"`
	Posture  *posturePayload `json:"posture,omitempty"`
}

// relayRegistration forwards a host registration to the control plane.
// This is fire-and-forget; errors are logged but don't affect local registration.
func (s *Server) relayRegistration(hostname string, posture *posturePayload) {
	dpuName := s.getDPUName()

	reqBody := controlPlaneRegisterRequest{
		DPUName:  dpuName,
		Hostname: hostname,
		Posture:  posture,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("[localapi] relay: failed to marshal request: %v", err)
		return
	}

	url := s.controlPlaneURL + "/api/v1/hosts/register"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[localapi] relay: failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("[localapi] relay: failed to forward registration for %s to control plane: %v", hostname, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[localapi] relay: forwarded registration for host %s (dpu=%s) to control plane", hostname, dpuName)
	} else {
		log.Printf("[localapi] relay: control plane returned %d for host %s registration", resp.StatusCode, hostname)
	}
}
