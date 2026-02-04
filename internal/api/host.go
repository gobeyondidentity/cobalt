// This file contains Host Agent API endpoints for Phase 5.
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// ----- Host Agent Types (Phase 5) -----

// hostRegisterRequest is the request body for registering a host agent.
type hostRegisterRequest struct {
	DPUName  string                  `json:"dpu_name"`
	Hostname string                  `json:"hostname"`
	Posture  *postureRequest         `json:"posture,omitempty"`
}

// postureRequest is the posture data in registration and update requests.
type postureRequest struct {
	SecureBoot     *bool  `json:"secure_boot"`
	DiskEncryption string `json:"disk_encryption"`
	OSVersion      string `json:"os_version"`
	KernelVersion  string `json:"kernel_version"`
	TPMPresent     *bool  `json:"tpm_present"`
}

// hostRegisterResponse is the response for host registration.
type hostRegisterResponse struct {
	HostID          string `json:"host_id"`
	RefreshInterval string `json:"refresh_interval"`
}

// agentHostResponse is the response for host agent endpoints.
type agentHostResponse struct {
	ID           string                 `json:"id"`
	DPUName      string                 `json:"dpu_name"`
	Hostname     string                 `json:"hostname"`
	TenantID     string                 `json:"tenant_id,omitempty"`
	RegisteredAt string                 `json:"registered_at"`
	LastSeenAt   string                 `json:"last_seen_at"`
	Posture      *agentPostureResponse  `json:"posture,omitempty"`
}

// agentPostureResponse is the posture data in responses.
type agentPostureResponse struct {
	SecureBoot     *bool  `json:"secure_boot"`
	DiskEncryption string `json:"disk_encryption"`
	OSVersion      string `json:"os_version"`
	KernelVersion  string `json:"kernel_version"`
	TPMPresent     *bool  `json:"tpm_present"`
	PostureHash    string `json:"posture_hash"`
	CollectedAt    string `json:"collected_at"`
}

// listHostsResponse wraps the hosts list for consistent API response format.
type listHostsResponse struct {
	Hosts []agentHostResponse `json:"hosts"`
}

// ----- Host Agent Handlers -----

// handleHostRegister handles POST /api/v1/hosts/register
func (s *Server) handleHostRegister(w http.ResponseWriter, r *http.Request) {
	var req hostRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if req.DPUName == "" {
		writeError(w, r, http.StatusBadRequest, "dpu_name is required")
		return
	}
	if req.Hostname == "" {
		writeError(w, r, http.StatusBadRequest, "hostname is required")
		return
	}

	// Look up DPU by name
	dpu, err := s.store.Get(req.DPUName)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found: "+req.DPUName)
		return
	}

	// Check if host already exists for this DPU
	existingHost, err := s.store.GetAgentHostByDPU(dpu.Name)
	if err == nil && existingHost != nil {
		// Host already registered, update last seen and return existing ID
		s.store.UpdateAgentHostLastSeen(existingHost.ID)

		// Update posture if provided
		if req.Posture != nil {
			hash := computePostureHash(req.Posture)
			posture := &store.AgentHostPosture{
				HostID:         existingHost.ID,
				SecureBoot:     req.Posture.SecureBoot,
				DiskEncryption: req.Posture.DiskEncryption,
				OSVersion:      req.Posture.OSVersion,
				KernelVersion:  req.Posture.KernelVersion,
				TPMPresent:     req.Posture.TPMPresent,
				PostureHash:    hash,
			}
			s.store.UpdateAgentHostPosture(posture)
		}

		writeJSON(w, http.StatusOK, hostRegisterResponse{
			HostID:          existingHost.ID,
			RefreshInterval: "5m",
		})
		return
	}

	// Determine tenant from DPU
	var tenantID string
	if dpu.TenantID != nil {
		tenantID = *dpu.TenantID
	}

	// Register new host
	host := &store.AgentHost{
		DPUName:  dpu.Name,
		DPUID:    dpu.ID,
		Hostname: req.Hostname,
		TenantID: tenantID,
	}

	if err := s.store.RegisterAgentHost(host); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeError(w, r, http.StatusConflict, "Host with this hostname already registered")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "Failed to register host: "+err.Error())
		return
	}

	// Update posture if provided
	if req.Posture != nil {
		hash := computePostureHash(req.Posture)
		posture := &store.AgentHostPosture{
			HostID:         host.ID,
			SecureBoot:     req.Posture.SecureBoot,
			DiskEncryption: req.Posture.DiskEncryption,
			OSVersion:      req.Posture.OSVersion,
			KernelVersion:  req.Posture.KernelVersion,
			TPMPresent:     req.Posture.TPMPresent,
			PostureHash:    hash,
		}
		if err := s.store.UpdateAgentHostPosture(posture); err != nil {
			// Log but don't fail registration
			fmt.Printf("Warning: failed to update posture for host %s: %v\n", host.ID, err)
		}
	}

	writeJSON(w, http.StatusCreated, hostRegisterResponse{
		HostID:          host.ID,
		RefreshInterval: "5m",
	})
}

// handleHostPostureUpdate handles POST /api/v1/hosts/{id}/posture
func (s *Server) handleHostPostureUpdate(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")

	// Verify host exists
	host, err := s.store.GetAgentHost(hostID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Host not found")
		return
	}

	var req postureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Update last seen
	if err := s.store.UpdateAgentHostLastSeen(host.ID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to update last seen: "+err.Error())
		return
	}

	// Compute posture hash
	hash := computePostureHash(&req)

	// Update posture
	posture := &store.AgentHostPosture{
		HostID:         host.ID,
		SecureBoot:     req.SecureBoot,
		DiskEncryption: req.DiskEncryption,
		OSVersion:      req.OSVersion,
		KernelVersion:  req.KernelVersion,
		TPMPresent:     req.TPMPresent,
		PostureHash:    hash,
	}

	if err := s.store.UpdateAgentHostPosture(posture); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to update posture: "+err.Error())
		return
	}

	// Fetch updated posture
	updatedPosture, err := s.store.GetAgentHostPosture(host.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to fetch updated posture: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, agentPostureToResponse(updatedPosture))
}

// handleListAgentHosts handles GET /api/v1/hosts
func (s *Server) handleListAgentHosts(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant")

	hosts, err := s.store.ListAgentHosts(tenantID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to list hosts: "+err.Error())
		return
	}

	result := make([]agentHostResponse, 0, len(hosts))
	for _, h := range hosts {
		resp := agentHostToResponse(h)
		// Fetch posture for each host
		posture, err := s.store.GetAgentHostPosture(h.ID)
		if err == nil {
			resp.Posture = agentPostureToResponse(posture)
		}
		result = append(result, resp)
	}

	writeJSON(w, http.StatusOK, listHostsResponse{Hosts: result})
}

// handleGetAgentHost handles GET /api/v1/hosts/{id}
func (s *Server) handleGetAgentHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	host, err := s.store.GetAgentHost(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Host not found")
		return
	}

	resp := agentHostToResponse(host)

	// Fetch posture
	posture, err := s.store.GetAgentHostPosture(host.ID)
	if err == nil {
		resp.Posture = agentPostureToResponse(posture)
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleGetHostPostureByDPU handles GET /api/v1/hosts/{dpuName}/posture
// Returns the posture data for the host paired with the specified DPU.
func (s *Server) handleGetHostPostureByDPU(w http.ResponseWriter, r *http.Request) {
	dpuName := r.PathValue("dpuName")

	// Look up host by DPU name
	host, err := s.store.GetAgentHostByDPU(dpuName)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Host not found for DPU: "+dpuName)
		return
	}

	// Get posture for this host
	posture, err := s.store.GetAgentHostPosture(host.ID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "No posture data available for host")
		return
	}

	writeJSON(w, http.StatusOK, agentPostureToResponse(posture))
}

// handleDeleteAgentHost handles DELETE /api/v1/hosts/{id}
func (s *Server) handleDeleteAgentHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if err := s.store.DeleteAgentHost(id); err != nil {
		writeError(w, r, http.StatusNotFound, "Host not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ----- Helper Functions -----

// computePostureHash computes SHA256 hash of sorted posture fields.
func computePostureHash(p *postureRequest) string {
	var secureBoot, tpmPresent bool
	if p.SecureBoot != nil {
		secureBoot = *p.SecureBoot
	}
	if p.TPMPresent != nil {
		tpmPresent = *p.TPMPresent
	}

	data := fmt.Sprintf("disk_encryption=%s,kernel_version=%s,os_version=%s,secure_boot=%v,tpm_present=%v",
		p.DiskEncryption, p.KernelVersion, p.OSVersion, secureBoot, tpmPresent)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// agentHostToResponse converts a store.AgentHost to an API response.
func agentHostToResponse(h *store.AgentHost) agentHostResponse {
	return agentHostResponse{
		ID:           h.ID,
		DPUName:      h.DPUName,
		Hostname:     h.Hostname,
		TenantID:     h.TenantID,
		RegisteredAt: h.RegisteredAt.Format(time.RFC3339),
		LastSeenAt:   h.LastSeenAt.Format(time.RFC3339),
	}
}

// agentPostureToResponse converts a store.AgentHostPosture to an API response.
func agentPostureToResponse(p *store.AgentHostPosture) *agentPostureResponse {
	return &agentPostureResponse{
		SecureBoot:     p.SecureBoot,
		DiskEncryption: p.DiskEncryption,
		OSVersion:      p.OSVersion,
		KernelVersion:  p.KernelVersion,
		TPMPresent:     p.TPMPresent,
		PostureHash:    p.PostureHash,
		CollectedAt:    p.CollectedAt.Format(time.RFC3339),
	}
}

// ----- Host Scan Types -----

// sshKeyInfo represents a single SSH key discovered on a host.
type sshKeyInfo struct {
	User        string `json:"user"`
	KeyType     string `json:"key_type"`
	KeyBits     int    `json:"key_bits"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
	FilePath    string `json:"file_path"`
}

// hostScanResponse is the response for the host scan endpoint.
type hostScanResponse struct {
	Host      string       `json:"host"`
	Method    string       `json:"method"`
	Keys      []sshKeyInfo `json:"keys"`
	ScannedAt string       `json:"scanned_at"`
}

// ----- Host Scan Handler -----

// handleHostScan handles POST /api/v1/hosts/{hostname}/scan
// Triggers an SSH key scan on the host-agent and returns discovered keys.
func (s *Server) handleHostScan(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeError(w, r, http.StatusBadRequest, "hostname is required in path")
		return
	}

	// Look up host by hostname in store
	host, err := s.store.GetAgentHostByHostname(hostname)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Host not found: "+hostname)
		return
	}

	// TODO: Connect to host-agent via gRPC and call ScanSSHKeys RPC
	// For now, return a stub response with empty keys array.
	// The actual host-agent connection will be wired up during integration.
	_ = host // Will be used to determine host-agent address

	response := hostScanResponse{
		Host:      hostname,
		Method:    "agent",
		Keys:      []sshKeyInfo{},
		ScannedAt: time.Now().Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, response)
}
