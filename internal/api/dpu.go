package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// Constants for DPU lifecycle operations.
const (
	// MinReactivationReasonLength is the minimum character length for DPU reactivation reasons.
	// Reactivation is a high-severity security event that requires documented justification.
	MinReactivationReasonLength = 20

	// ReactivationEnrollmentWindow is how long a reactivated DPU has to re-enroll.
	ReactivationEnrollmentWindow = 24 * time.Hour
)

// DecommissionDPURequest is the request body for decommissioning a DPU.
type DecommissionDPURequest struct {
	Reason           string `json:"reason"`
	ScrubCredentials bool   `json:"scrub_credentials"`
}

// DecommissionDPUResponse is the response for a successful DPU decommissioning.
type DecommissionDPUResponse struct {
	ID                  string `json:"id"`
	Status              string `json:"status"`
	DecommissionedAt    string `json:"decommissioned_at"`
	CredentialsScrubbed int    `json:"credentials_scrubbed"`
}

// handleDecommissionDPU handles DELETE /api/v1/dpus/{id}
// Requires JSON body with reason field.
// Authorization: tenant:admin for own tenant, super:admin for any.
func (s *Server) handleDecommissionDPU(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Parse request body
	var req DecommissionDPURequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate reason is non-empty
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		writeError(w, r, http.StatusBadRequest, "reason is required")
		return
	}

	// Get DPU to check existence and tenant
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	// Check if already decommissioned
	if dpu.Status == "decommissioned" {
		writeError(w, r, http.StatusConflict, "DPU already decommissioned")
		return
	}

	// Get caller identity
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	// Authorization check
	authorized, authzErr := s.authorizeDPUDecommission(identity, dpu)
	if authzErr != nil {
		writeError(w, r, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !authorized {
		writeError(w, r, http.StatusForbidden, "not authorized to decommission this DPU")
		return
	}

	// Atomically decommission (handles concurrent decommission with 409)
	credentialsScrubbed, err := s.store.DecommissionDPUAtomic(id, identity.KID, req.Reason, req.ScrubCredentials)
	if err != nil {
		if err == store.ErrAlreadyDecommissioned {
			writeError(w, r, http.StatusConflict, "DPU already decommissioned")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "Failed to decommission DPU: "+err.Error())
		return
	}

	// Re-fetch to get updated timestamps
	dpu, err = s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to fetch decommissioned DPU")
		return
	}

	// Audit log the decommissioning
	auditEntry := &store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "dpu.decommission",
		Target:    dpu.ID,
		Decision:  "allowed",
		Details: map[string]string{
			"actor":               identity.KID,
			"reason":              req.Reason,
			"credentials_scrubbed": strconv.Itoa(credentialsScrubbed),
		},
	}
	if dpu.TenantID != nil {
		auditEntry.Details["tenant_id"] = *dpu.TenantID
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for DPU decommission: %v", err)
		// Don't fail the request, audit logging is non-critical
	}

	log.Printf("DPU decommissioned: id=%s name=%s by=%s reason=%s credentials_scrubbed=%d",
		dpu.ID, dpu.Name, identity.KID, req.Reason, credentialsScrubbed)

	// Build response
	resp := DecommissionDPUResponse{
		ID:                  dpu.ID,
		Status:              dpu.Status,
		CredentialsScrubbed: credentialsScrubbed,
	}
	if dpu.DecommissionedAt != nil {
		resp.DecommissionedAt = dpu.DecommissionedAt.Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, resp)
}

// authorizeDPUDecommission checks if the caller can decommission a DPU.
// Rules per security-architecture.md:
// - super:admin can decommission any DPU
// - tenant:admin can decommission DPUs in own tenant
func (s *Server) authorizeDPUDecommission(identity *dpop.Identity, dpu *store.DPU) (bool, error) {
	// Check if caller is super:admin (can decommission any DPU)
	isSuperAdmin, err := s.store.IsSuperAdmin(identity.OperatorID)
	if err != nil {
		return false, err
	}
	if isSuperAdmin {
		return true, nil
	}

	// If DPU has no tenant, only super:admin can decommission it
	if dpu.TenantID == nil {
		return false, nil
	}

	// Check if caller is tenant:admin in the DPU's tenant
	callerTenants, err := s.store.GetOperatorTenants(identity.OperatorID)
	if err != nil {
		return false, err
	}

	for _, membership := range callerTenants {
		if membership.Role == "tenant:admin" && membership.TenantID == *dpu.TenantID {
			return true, nil
		}
	}

	// Not authorized
	return false, nil
}

// ReactivateDPURequest is the request body for reactivating a decommissioned DPU.
type ReactivateDPURequest struct {
	Reason string `json:"reason"`
}

// ReactivateDPUResponse is the response for a successful DPU reactivation.
type ReactivateDPUResponse struct {
	ID                  string `json:"id"`
	Status              string `json:"status"`
	ReactivatedAt       string `json:"reactivated_at"`
	ReactivatedBy       string `json:"reactivated_by"`
	EnrollmentExpiresAt string `json:"enrollment_expires_at"`
}

// handleReactivateDPU handles POST /api/v1/dpus/{id}/reactivate
// Re-activates a decommissioned DPU for RMA scenarios.
// Authorization: super:admin ONLY (LC-5)
func (s *Server) handleReactivateDPU(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Parse request body
	var req ReactivateDPURequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate reason has minimum length
	req.Reason = strings.TrimSpace(req.Reason)
	if len(req.Reason) < MinReactivationReasonLength {
		writeError(w, r, http.StatusBadRequest, fmt.Sprintf("reason must be at least %d characters", MinReactivationReasonLength))
		return
	}

	// Get DPU to check existence
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	// Get caller identity
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	// Authorization: super:admin ONLY
	isSuperAdmin, err := s.store.IsSuperAdmin(identity.OperatorID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !isSuperAdmin {
		writeError(w, r, http.StatusForbidden, "only super:admin can reactivate DPUs")
		return
	}

	// Set enrollment window
	enrollmentExpiresAt := time.Now().Add(ReactivationEnrollmentWindow)

	// Atomically reactivate
	err = s.store.ReactivateDPUAtomic(id, enrollmentExpiresAt)
	if err != nil {
		if err == store.ErrNotDecommissioned {
			writeError(w, r, http.StatusConflict, "DPU is not decommissioned")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "Failed to reactivate DPU: "+err.Error())
		return
	}

	// Audit log the reactivation (high-severity security event)
	now := time.Now()
	auditEntry := &store.AuditEntry{
		Timestamp: now,
		Action:    "dpu.reactivate",
		Target:    dpu.ID,
		Decision:  "allowed",
		Details: map[string]string{
			"actor":    identity.KID,
			"reason":   req.Reason,
			"severity": "high",
		},
	}
	if dpu.TenantID != nil {
		auditEntry.Details["tenant_id"] = *dpu.TenantID
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for DPU reactivation: %v", err)
		// Don't fail the request, audit logging is non-critical
	}

	log.Printf("DPU reactivated: id=%s name=%s by=%s reason=%s",
		dpu.ID, dpu.Name, identity.KID, req.Reason)

	// Build response
	resp := ReactivateDPUResponse{
		ID:                  dpu.ID,
		Status:              "pending",
		ReactivatedAt:       now.Format(time.RFC3339),
		ReactivatedBy:       identity.KID,
		EnrollmentExpiresAt: enrollmentExpiresAt.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, resp)
}
