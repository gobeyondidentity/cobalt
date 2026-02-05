package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// ----- Admin Key Types -----

// RevokeAdminKeyRequest is the request body for revoking an admin key.
type RevokeAdminKeyRequest struct {
	Reason string `json:"reason"`
}

// AdminKeyResponse is the response for admin key endpoints.
type AdminKeyResponse struct {
	ID            string  `json:"id"`
	OperatorID    string  `json:"operator_id"`
	Name          string  `json:"name,omitempty"`
	Kid           string  `json:"kid"`
	KeyFingerprint string `json:"key_fingerprint"`
	Status        string  `json:"status"`
	BoundAt       string  `json:"bound_at"`
	LastSeen      *string `json:"last_seen,omitempty"`
	RevokedAt     *string `json:"revoked_at,omitempty"`
	RevokedBy     *string `json:"revoked_by,omitempty"`
	RevokedReason *string `json:"revoked_reason,omitempty"`
}

// adminKeyToResponse converts a store.AdminKey to an API response.
func adminKeyToResponse(ak *store.AdminKey) AdminKeyResponse {
	resp := AdminKeyResponse{
		ID:            ak.ID,
		OperatorID:    ak.OperatorID,
		Name:          ak.Name,
		Kid:           ak.Kid,
		KeyFingerprint: ak.KeyFingerprint,
		Status:        ak.Status,
		BoundAt:       ak.BoundAt.Format(time.RFC3339),
	}

	if ak.LastSeen != nil {
		t := ak.LastSeen.Format(time.RFC3339)
		resp.LastSeen = &t
	}
	if ak.RevokedAt != nil {
		t := ak.RevokedAt.Format(time.RFC3339)
		resp.RevokedAt = &t
	}
	if ak.RevokedBy != nil {
		resp.RevokedBy = ak.RevokedBy
	}
	if ak.RevokedReason != nil {
		resp.RevokedReason = ak.RevokedReason
	}
	return resp
}

// handleRevokeAdminKey handles DELETE /api/v1/admin-keys/{id}
// Only super:admin can revoke admin keys. Returns 403 for tenant:admin.
func (s *Server) handleRevokeAdminKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Parse request body
	var req RevokeAdminKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate reason is non-empty
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		writeError(w, r, http.StatusBadRequest, "reason is required and cannot be empty")
		return
	}

	// Get caller identity from context
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil || identity.OperatorID == "" {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	// Only super:admin can revoke admin keys
	isSuperAdmin, err := s.store.IsSuperAdmin(identity.OperatorID)
	if err != nil {
		writeInternalError(w, r, err, "failed to check caller permissions")
		return
	}
	if !isSuperAdmin {
		writeError(w, r, http.StatusForbidden, "only super:admin can revoke admin keys")
		return
	}

	// Check if admin key exists (needed for self-revocation check and audit)
	ak, err := s.store.GetAdminKey(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, r, http.StatusNotFound, "admin key not found")
			return
		}
		writeInternalError(w, r, err, "failed to retrieve admin key")
		return
	}

	// Check if this is the last active super:admin key
	isLastSuperAdmin, err := s.store.IsAdminKeyLastActiveSuperAdmin(id)
	if err != nil {
		writeInternalError(w, r, err, "failed to check admin key status")
		return
	}
	if isLastSuperAdmin {
		writeError(w, r, http.StatusConflict, "cannot revoke the last active super:admin key (would cause system lockout)")
		return
	}

	// Determine if this is self-revocation
	isSelfRevocation := ak.OperatorID == identity.OperatorID

	// Revoke the admin key atomically (prevents race condition)
	if err := s.store.RevokeAdminKeyAtomic(id, identity.KID, req.Reason); err != nil {
		if errors.Is(err, store.ErrAdminKeyAlreadyRevoked) {
			writeError(w, r, http.StatusConflict, "admin key is already revoked")
			return
		}
		writeInternalError(w, r, err, "failed to revoke admin key")
		return
	}

	// Create audit log entry
	auditAction := "admin_key.revoke"
	if isSelfRevocation {
		auditAction = "admin_key.self_revoke"
	}

	auditEntry := &store.AuditEntry{
		Timestamp: time.Now(),
		Action:    auditAction,
		Target:    id,
		Decision:  "allowed",
		Details: map[string]string{
			"admin_id":        identity.KID,
			"operator_id":     ak.OperatorID,
			"reason":          req.Reason,
			"self_revocation": boolToString(isSelfRevocation),
		},
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for admin key revocation: %v", err)
		// Don't fail the request, audit logging is non-critical
	}

	if isSelfRevocation {
		log.Printf("WARNING: Admin self-revocation: admin_key=%s operator_id=%s reason=%s", id, ak.OperatorID, req.Reason)
	} else {
		log.Printf("Admin key revoked: admin_key=%s operator_id=%s by=%s reason=%s", id, ak.OperatorID, identity.KID, req.Reason)
	}

	w.WriteHeader(http.StatusNoContent)
}

// boolToString converts a bool to "true" or "false" string for audit logs.
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
