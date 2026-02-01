// Package api implements the HTTP API server for the dashboard.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/attestation"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
)

// ----- Trust Types -----

// CreateTrustRequest is the request body for creating a trust relationship.
type CreateTrustRequest struct {
	SourceDPU     string `json:"source_dpu"`
	TargetDPU     string `json:"target_dpu"`
	TrustType     string `json:"trust_type"`
	Bidirectional bool   `json:"bidirectional"`
}

// UpdateTrustStatusRequest is the request body for updating trust status.
type UpdateTrustStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// TrustResponse is the response for a trust relationship.
type TrustResponse struct {
	ID            string `json:"id"`
	Source        string `json:"source"`
	Target        string `json:"target"`
	TrustType     string `json:"trust_type"`
	Bidirectional bool   `json:"bidirectional"`
	Status        string `json:"status"`
	SuspendReason string `json:"suspend_reason,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// ----- Trust Handlers -----

// handleCreateTrust handles POST /api/v1/trust
func (s *Server) handleCreateTrust(w http.ResponseWriter, r *http.Request) {
	var req CreateTrustRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if req.SourceDPU == "" {
		writeError(w, r, http.StatusBadRequest, "source_dpu is required")
		return
	}
	if req.TargetDPU == "" {
		writeError(w, r, http.StatusBadRequest, "target_dpu is required")
		return
	}
	if req.TrustType == "" {
		writeError(w, r, http.StatusBadRequest, "trust_type is required")
		return
	}

	// Validate trust type
	trustType := store.TrustType(req.TrustType)
	if trustType != store.TrustTypeSSHHost && trustType != store.TrustTypeMTLS {
		writeError(w, r, http.StatusBadRequest, "trust_type must be 'ssh_host' or 'mtls'")
		return
	}

	// Look up source DPU by name
	sourceDPU, err := s.store.Get(req.SourceDPU)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "source DPU not found: "+req.SourceDPU)
		return
	}

	// Look up target DPU by name
	targetDPU, err := s.store.Get(req.TargetDPU)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "target DPU not found: "+req.TargetDPU)
		return
	}

	// Verify both DPUs are assigned to the same tenant
	if sourceDPU.TenantID == nil {
		writeError(w, r, http.StatusBadRequest, "source DPU is not assigned to any tenant")
		return
	}
	if targetDPU.TenantID == nil {
		writeError(w, r, http.StatusBadRequest, "target DPU is not assigned to any tenant")
		return
	}
	if *sourceDPU.TenantID != *targetDPU.TenantID {
		writeError(w, r, http.StatusBadRequest, "source and target DPUs must be in the same tenant")
		return
	}

	// Check if trust relationship already exists
	exists, err := s.store.TrustRelationshipExists(sourceDPU.ID, targetDPU.ID, trustType)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to check trust relationship existence: "+err.Error())
		return
	}
	if exists {
		writeError(w, r, http.StatusConflict, "trust relationship already exists between these DPUs for this trust type")
		return
	}

	// Check attestation status for both DPUs (Phase 4: M2M Trust attestation gate)
	if err := s.checkAttestationForTrust(req.SourceDPU); err != nil {
		writeErrorWithHint(w, http.StatusPreconditionFailed, err.Error(),
			fmt.Sprintf("Run 'bluectl attestation %s' to verify device attestation", req.SourceDPU))
		return
	}
	if err := s.checkAttestationForTrust(req.TargetDPU); err != nil {
		writeErrorWithHint(w, http.StatusPreconditionFailed, err.Error(),
			fmt.Sprintf("Run 'bluectl attestation %s' to verify device attestation", req.TargetDPU))
		return
	}

	// Create the trust relationship
	tr := &store.TrustRelationship{
		SourceDPUID:   sourceDPU.ID,
		SourceDPUName: sourceDPU.Name,
		TargetDPUID:   targetDPU.ID,
		TargetDPUName: targetDPU.Name,
		TenantID:      *sourceDPU.TenantID,
		TrustType:     trustType,
		Bidirectional: req.Bidirectional,
		Status:        store.TrustStatusActive,
	}

	if err := s.store.CreateTrustRelationship(tr); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to create trust relationship: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, trustRelationshipToResponse(tr))
}

// handleListTrust handles GET /api/v1/trust
func (s *Server) handleListTrust(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant")

	var trusts []*store.TrustRelationship
	var err error

	if tenantID != "" {
		trusts, err = s.store.ListTrustRelationships(tenantID)
	} else {
		trusts, err = s.store.ListAllTrustRelationships()
	}

	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list trust relationships: "+err.Error())
		return
	}

	result := make([]TrustResponse, 0, len(trusts))
	for _, tr := range trusts {
		result = append(result, trustRelationshipToResponse(tr))
	}

	writeJSON(w, http.StatusOK, result)
}

// handleGetTrust handles GET /api/v1/trust/{id}
func (s *Server) handleGetTrust(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	tr, err := s.store.GetTrustRelationship(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "trust relationship not found")
		return
	}

	writeJSON(w, http.StatusOK, trustRelationshipToResponse(tr))
}

// handleDeleteTrust handles DELETE /api/v1/trust/{id}
func (s *Server) handleDeleteTrust(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if err := s.store.DeleteTrustRelationship(id); err != nil {
		writeError(w, r, http.StatusNotFound, "trust relationship not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleUpdateTrustStatus handles PATCH /api/v1/trust/{id}/status
func (s *Server) handleUpdateTrustStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check if trust relationship exists
	_, err := s.store.GetTrustRelationship(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "trust relationship not found")
		return
	}

	var req UpdateTrustStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate status
	if req.Status == "" {
		writeError(w, r, http.StatusBadRequest, "status is required")
		return
	}

	status := store.TrustStatus(req.Status)
	if status != store.TrustStatusActive && status != store.TrustStatusSuspended {
		writeError(w, r, http.StatusBadRequest, "status must be 'active' or 'suspended'")
		return
	}

	// Set reason pointer
	var reason *string
	if req.Reason != "" {
		reason = &req.Reason
	}

	if err := s.store.UpdateTrustStatus(id, status, reason); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to update trust status: "+err.Error())
		return
	}

	// Fetch updated trust relationship
	tr, err := s.store.GetTrustRelationship(id)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to fetch updated trust relationship: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, trustRelationshipToResponse(tr))
}

// ----- Helper Functions -----

// trustRelationshipToResponse converts a store.TrustRelationship to an API response.
func trustRelationshipToResponse(tr *store.TrustRelationship) TrustResponse {
	resp := TrustResponse{
		ID:            tr.ID,
		Source:        tr.SourceDPUName,
		Target:        tr.TargetDPUName,
		TrustType:     string(tr.TrustType),
		Bidirectional: tr.Bidirectional,
		Status:        string(tr.Status),
		CreatedAt:     tr.CreatedAt.Format(time.RFC3339),
	}
	if tr.SuspendReason != nil {
		resp.SuspendReason = *tr.SuspendReason
	}
	return resp
}

// checkAttestationForTrust verifies that a DPU has valid attestation for trust creation.
// Returns nil if attestation is verified and fresh, otherwise returns an error with a
// descriptive message suitable for display to users.
func (s *Server) checkAttestationForTrust(dpuName string) error {
	gate := attestation.NewGate(s.store)
	decision, err := gate.CanDistribute(dpuName)
	if err != nil {
		return fmt.Errorf("Cannot create trust: '%s' attestation check failed", dpuName)
	}
	if !decision.Allowed {
		return fmt.Errorf("Cannot create trust: '%s' attestation not verified", dpuName)
	}
	return nil
}

// writeErrorWithHint writes an error response with an optional hint for the CLI.
func writeErrorWithHint(w http.ResponseWriter, status int, message, hint string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]string{
		"error": message,
		"hint":  hint,
	}
	json.NewEncoder(w).Encode(resp)
}
