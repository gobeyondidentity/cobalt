package localapi

import (
	"encoding/json"
	"log"
	"net/http"
)

// handleHealth returns the local API and DPU health status.
// GET /local/v1/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	attestation := s.getAttestation(ctx)

	// Check Control Plane connectivity
	cpStatus := "connected"
	if err := s.controlPlane.Ping(ctx); err != nil {
		cpStatus = "disconnected"
	}

	status := "healthy"
	if attestation.Status == "invalid" || cpStatus == "disconnected" {
		status = "degraded"
	}
	if attestation.Status == "invalid" && cpStatus == "disconnected" {
		status = "unhealthy"
	}

	s.writeJSON(w, http.StatusOK, HealthResponse{
		Status:            status,
		DPUName:           s.config.DPUName,
		AttestationStatus: attestation.Status,
		ControlPlane:      cpStatus,
	})
}

// handleRegister handles Host Agent registration.
// POST /local/v1/register
// The DPU Agent proxies this to the Control Plane, adding its identity.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Validate request
	if req.Hostname == "" {
		s.writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}

	// Check hostname allowlist
	if !s.isHostnameAllowed(req.Hostname) {
		log.Printf("Local API: registration rejected for hostname %s (not in allowlist)", req.Hostname)
		s.writeError(w, http.StatusForbidden, "hostname not allowed to register with this DPU")
		return
	}

	// Check if another host is already paired
	if !s.isPairedHost(req.Hostname) {
		log.Printf("Local API: registration rejected for %s (DPU already paired with different host)", req.Hostname)
		s.writeError(w, http.StatusConflict, "DPU is already paired with a different host")
		return
	}

	// Get current attestation status
	attestation := s.getAttestation(ctx)
	log.Printf("Local API: registering host %s with attestation status %s", req.Hostname, attestation.Status)

	// Build proxied request with DPU identity
	proxiedReq := ProxiedRegisterRequest{
		Hostname:          req.Hostname,
		Posture:           req.Posture,
		DPUName:           s.config.DPUName,
		DPUID:             s.config.DPUID,
		DPUSerial:         s.config.DPUSerial,
		AttestationStatus: attestation.Status,
	}

	// Proxy to Control Plane
	resp, err := s.controlPlane.RegisterHost(ctx, &proxiedReq)
	if err != nil {
		log.Printf("Local API: Control Plane registration failed: %v", err)
		s.writeError(w, http.StatusBadGateway, "Control Plane registration failed: "+err.Error())
		return
	}

	// Record the pairing
	if !s.setPairedHost(req.Hostname, resp.HostID) {
		// Race condition: another registration succeeded first
		s.writeError(w, http.StatusConflict, "DPU was paired with different host during registration")
		return
	}

	log.Printf("Local API: host %s registered successfully as %s", req.Hostname, resp.HostID)

	s.writeJSON(w, http.StatusOK, RegisterResponse{
		HostID:  resp.HostID,
		DPUName: s.config.DPUName,
	})
}

// handlePosture handles posture updates from the Host Agent.
// POST /local/v1/posture
func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req PostureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Validate request
	if req.Hostname == "" {
		s.writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}
	if req.Posture == nil {
		s.writeError(w, http.StatusBadRequest, "posture data is required")
		return
	}

	// Verify this is the paired host
	if !s.isPairedHost(req.Hostname) {
		log.Printf("Local API: posture update rejected for %s (not the paired host)", req.Hostname)
		s.writeError(w, http.StatusForbidden, "hostname does not match paired host")
		return
	}

	hostID := s.getPairedHostID()
	if hostID == "" {
		s.writeError(w, http.StatusPreconditionFailed, "host not registered; call /local/v1/register first")
		return
	}

	// Get current attestation status
	attestation := s.getAttestation(ctx)

	// Build proxied request
	proxiedReq := ProxiedPostureRequest{
		HostID:            hostID,
		Posture:           req.Posture,
		DPUName:           s.config.DPUName,
		AttestationStatus: attestation.Status,
	}

	// Proxy to Control Plane
	if err := s.controlPlane.UpdatePosture(ctx, &proxiedReq); err != nil {
		log.Printf("Local API: Control Plane posture update failed: %v", err)
		s.writeError(w, http.StatusBadGateway, "Control Plane posture update failed: "+err.Error())
		return
	}

	log.Printf("Local API: posture update accepted for host %s", req.Hostname)

	s.writeJSON(w, http.StatusOK, PostureResponse{
		Accepted: true,
	})
}

// handleCert handles certificate requests from the Host Agent.
// POST /local/v1/cert
// The DPU Agent validates the request, fetches attestation, and proxies to Control Plane.
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Validate request
	if req.Hostname == "" {
		s.writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}
	if req.PublicKey == "" {
		s.writeError(w, http.StatusBadRequest, "public_key is required")
		return
	}
	if len(req.Principals) == 0 {
		s.writeError(w, http.StatusBadRequest, "at least one principal is required")
		return
	}

	// Verify this is the paired host
	if !s.isPairedHost(req.Hostname) {
		log.Printf("Local API: cert request rejected for %s (not the paired host)", req.Hostname)
		s.writeError(w, http.StatusForbidden, "hostname does not match paired host")
		return
	}

	hostID := s.getPairedHostID()
	if hostID == "" {
		s.writeError(w, http.StatusPreconditionFailed, "host not registered; call /local/v1/register first")
		return
	}

	// Get current attestation status
	attestation := s.getAttestation(ctx)
	log.Printf("Local API: cert request for host %s, attestation status %s", req.Hostname, attestation.Status)

	// The Control Plane may reject cert requests if attestation is invalid.
	// We still forward the request; policy enforcement is at the Control Plane.

	// Build proxied request with DPU attestation info
	proxiedReq := ProxiedCertRequest{
		Hostname:          req.Hostname,
		PublicKey:         req.PublicKey,
		Principals:        req.Principals,
		DPUName:           s.config.DPUName,
		DPUSerial:         s.config.DPUSerial,
		AttestationStatus: attestation.Status,
		Measurements:      attestation.Measurements,
		HostID:            hostID,
	}

	// Proxy to Control Plane
	resp, err := s.controlPlane.RequestCertificate(ctx, &proxiedReq)
	if err != nil {
		log.Printf("Local API: Control Plane cert request failed: %v", err)
		s.writeError(w, http.StatusBadGateway, "Control Plane cert request failed: "+err.Error())
		return
	}

	log.Printf("Local API: certificate issued for host %s, serial %d", req.Hostname, resp.Serial)

	s.writeJSON(w, http.StatusOK, CertResponse{
		Certificate: resp.Certificate,
		Serial:      resp.Serial,
		ValidBefore: resp.ValidBefore,
	})
}

// handleCredentialsPending returns queued credentials for the Host Agent.
// GET /local/v1/credentials/pending
// Used as fallback when ComCh/tmfifo push is unavailable.
func (s *Server) handleCredentialsPending(w http.ResponseWriter, r *http.Request) {
	// Verify a host is paired
	hostID := s.getPairedHostID()
	if hostID == "" {
		s.writeError(w, http.StatusPreconditionFailed, "host not registered; call /local/v1/register first")
		return
	}

	// Get and clear queued credentials
	creds := s.GetQueuedCredentials()

	log.Printf("Local API: returning %d pending credentials to host", len(creds))

	s.writeJSON(w, http.StatusOK, CredentialsPendingResponse{
		Credentials: creds,
	})
}

// handleCredentialPush handles credential distribution to the Host Agent.
// POST /local/v1/credential
// This endpoint is called by the DPU Agent gRPC handler when km distribute triggers.
// The credential is forwarded to the paired host via tmfifo or the Host Agent HTTP API.
func (s *Server) handleCredentialPush(w http.ResponseWriter, r *http.Request) {
	var req CredentialPushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Validate request
	if req.CredentialType == "" {
		s.writeError(w, http.StatusBadRequest, "credential_type is required")
		return
	}
	if req.CredentialName == "" {
		s.writeError(w, http.StatusBadRequest, "credential_name is required")
		return
	}
	if len(req.Data) == 0 {
		s.writeError(w, http.StatusBadRequest, "data is required")
		return
	}

	// Check if a host is paired
	hostID := s.getPairedHostID()
	if hostID == "" {
		s.writeError(w, http.StatusPreconditionFailed, "no host registered; cannot distribute credentials")
		return
	}

	log.Printf("Local API: credential push request type=%s name=%s size=%d bytes",
		req.CredentialType, req.CredentialName, len(req.Data))

	// Try active transport first if available
	activeTransport := s.GetActiveTransport()
	if activeTransport != nil {
		if err := s.pushCredentialViaTransport(activeTransport, req.CredentialType, req.CredentialName, req.Data); err != nil {
			log.Printf("Local API: transport credential push failed: %v", err)
			s.writeJSON(w, http.StatusOK, CredentialPushResponse{
				Success: false,
				Error:   "transport send failed: " + err.Error(),
			})
			return
		}

		// Transport send is async; we can't wait for the ack in a synchronous HTTP response
		log.Printf("Local API: credential pushed via %s transport", activeTransport.Type())
		s.writeJSON(w, http.StatusOK, CredentialPushResponse{
			Success: true,
		})
		return
	}

	// No transport available; credential push requires host-side handling
	// The Host Agent must be configured to receive credentials via its own mechanism
	log.Printf("Local API: no active transport, credential push deferred to host agent")
	s.writeJSON(w, http.StatusOK, CredentialPushResponse{
		Success: false,
		Error:   "no active transport; host agent must poll for credentials",
	})
}
