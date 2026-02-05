package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
	"github.com/google/uuid"
)

// ----- Operator Invite Types -----

// InviteOperatorRequest is the request body for inviting an operator.
type InviteOperatorRequest struct {
	Email      string `json:"email"`
	TenantName string `json:"tenant_name"`
	Role       string `json:"role"`
}

// InviteOperatorResponse is the response for an operator invite.
type InviteOperatorResponse struct {
	Status     string `json:"status"`
	InviteCode string `json:"invite_code,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Operator   struct {
		ID     string `json:"id"`
		Email  string `json:"email"`
		Status string `json:"status"`
	} `json:"operator"`
}

// handleInviteOperator handles POST /api/v1/operators/invite
// It creates an invite code for an operator to join a tenant.
func (s *Server) handleInviteOperator(w http.ResponseWriter, r *http.Request) {
	var req InviteOperatorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if req.Email == "" {
		writeError(w, r, http.StatusBadRequest, "email is required")
		return
	}
	if req.TenantName == "" {
		writeError(w, r, http.StatusBadRequest, "tenant_name is required")
		return
	}

	// Default role to operator if not specified
	if req.Role == "" {
		req.Role = "operator"
	}

	// Validate role - role privilege levels for authorization checks
	rolePrivilege := map[string]int{
		"operator":     1, // lowest privilege
		"tenant:admin": 2,
		"super:admin":  3, // highest privilege
	}
	requestedPrivilege, ok := rolePrivilege[req.Role]
	if !ok {
		writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid role: %s (must be 'operator', 'tenant:admin', or 'super:admin')", req.Role))
		return
	}

	// Get tenant (needed for both validation and authorization check)
	tenant, err := s.store.GetTenant(req.TenantName)
	if err != nil {
		writeError(w, r, http.StatusNotFound, fmt.Sprintf("tenant not found: %s", req.TenantName))
		return
	}

	// Authorization check: caller cannot invite with role higher than their own
	identity := dpop.IdentityFromContext(r.Context())
	if identity != nil && identity.OperatorID != "" {
		// Check if caller is super:admin in any tenant (grants global access per ADR-011)
		isSuperAdmin, err := s.store.IsSuperAdmin(identity.OperatorID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "failed to check caller permissions")
			return
		}

		if isSuperAdmin {
			// Super-admin can assign any role
		} else {
			// Not super-admin: check caller's role in the target tenant
			callerRole, err := s.store.GetOperatorRole(identity.OperatorID, tenant.ID)
			if err != nil {
				writeError(w, r, http.StatusForbidden, "you do not have permission to invite operators to this tenant")
				return
			}

			callerPrivilege := rolePrivilege[callerRole]
			if callerPrivilege == 0 {
				// Unknown role defaults to operator (lowest)
				callerPrivilege = 1
			}

			// Caller cannot invite with role higher than their own
			if requestedPrivilege > callerPrivilege {
				writeError(w, r, http.StatusForbidden, fmt.Sprintf("cannot invite with role '%s': your role '%s' does not have sufficient privileges", req.Role, callerRole))
				return
			}
		}
	}

	// Get admin identity from auth context for audit logging (reuse identity from authorization check)
	adminKID := "unknown"
	if identity != nil {
		adminKID = identity.KID
	}

	// Check if operator exists
	var operator *store.Operator
	var isAdditionalDevice bool
	op, err := s.store.GetOperatorByEmail(req.Email)
	if err == nil && op != nil {
		operator = op
		// Operator exists - for active/suspended, generate new invite for additional device
		if op.Status != "pending_invite" {
			isAdditionalDevice = true
		}
	} else {
		// Create new operator with pending status
		opID := "op_" + uuid.New().String()[:UUIDShortLength]
		if err := s.store.CreateOperator(opID, req.Email, ""); err != nil {
			writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to create operator: %v", err))
			return
		}
		operator, _ = s.store.GetOperator(opID)
	}

	// Add operator to tenant if not already a member
	_, existingRoleErr := s.store.GetOperatorRole(operator.ID, tenant.ID)
	if existingRoleErr != nil {
		// Not a member yet, add them
		if err := s.store.AddOperatorToTenant(operator.ID, tenant.ID, req.Role); err != nil {
			// Ignore duplicate key errors
			if !strings.Contains(err.Error(), "UNIQUE constraint") {
				writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to add operator to tenant: %v", err))
				return
			}
		}
	}

	// Generate invite code
	prefix := tenant.Name
	if len(prefix) > InviteCodePrefixMaxLength {
		prefix = prefix[:InviteCodePrefixMaxLength]
	}
	code := store.GenerateInviteCode(strings.ToUpper(prefix))

	// Store invite (hashed)
	invite := &store.InviteCode{
		ID:            "inv_" + uuid.New().String()[:UUIDShortLength],
		CodeHash:      store.HashInviteCode(code),
		OperatorEmail: req.Email,
		TenantID:      tenant.ID,
		Role:          req.Role,
		CreatedBy:     adminKID,
		ExpiresAt:     time.Now().Add(InviteDefaultTTL),
		Status:        "pending",
	}

	if err := s.store.CreateInviteCode(invite); err != nil {
		writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to create invite: %v", err))
		return
	}

	// Audit log the invite generation
	inviteType := "new"
	if isAdditionalDevice {
		inviteType = "additional_device"
	}
	auditEntry := &store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "operator.invite",
		Target:    operator.ID,
		Decision:  "allowed",
		Details: map[string]string{
			"admin_id":       adminKID,
			"operator_email": req.Email,
			"invite_type":    inviteType,
			"tenant_id":      tenant.ID,
		},
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for invite: %v", err)
		// Don't fail the request, audit logging is non-critical
	}

	// Return response
	status := "invited"
	if isAdditionalDevice {
		status = "additional_device"
	}
	response := InviteOperatorResponse{
		Status:     status,
		InviteCode: code,
		ExpiresAt:  invite.ExpiresAt.Format(time.RFC3339),
	}
	response.Operator.ID = operator.ID
	response.Operator.Email = operator.Email
	response.Operator.Status = operator.Status

	writeJSON(w, http.StatusCreated, response)
}

// handleDeleteInvite handles DELETE /api/v1/invites/{code}
func (s *Server) handleDeleteInvite(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")

	// Hash the code and lookup
	codeHash := store.HashInviteCode(code)
	invite, err := s.store.GetInviteCodeByHash(codeHash)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Invite code not found")
		return
	}

	// Delete invite
	if err := s.store.DeleteInviteCode(invite.ID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to delete invite: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
