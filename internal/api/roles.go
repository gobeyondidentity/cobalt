package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// ----- Role Management -----

// AssignRoleRequest is the request body for assigning a role.
type AssignRoleRequest struct {
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

// handleAssignRole handles POST /api/v1/operators/{id}/roles
// It assigns or updates a role for an operator in a tenant.
func (s *Server) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	operatorID := r.PathValue("id")

	var req AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if req.TenantID == "" {
		writeError(w, r, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if req.Role == "" {
		writeError(w, r, http.StatusBadRequest, "role is required")
		return
	}

	// Validate role
	rolePrivilege := map[string]int{
		"operator":     1,
		"tenant:admin": 2,
		"super:admin":  3,
	}
	requestedPrivilege, ok := rolePrivilege[req.Role]
	if !ok {
		writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid role: %s (must be 'operator', 'tenant:admin', or 'super:admin')", req.Role))
		return
	}

	// Verify target operator exists
	targetOp, err := s.store.GetOperator(operatorID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Operator not found")
		return
	}

	// Verify tenant exists
	_, err = s.store.GetTenant(req.TenantID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Tenant not found")
		return
	}

	// Get caller identity for authorization checks
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil || identity.OperatorID == "" {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	// Prevent self-modification (use separate endpoint for that)
	if identity.OperatorID == targetOp.ID {
		writeError(w, r, http.StatusForbidden, "cannot modify your own roles (use self-management endpoints)")
		return
	}

	// Check caller authorization
	isSuperAdmin, err := s.store.IsSuperAdmin(identity.OperatorID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to check caller permissions")
		return
	}

	if isSuperAdmin {
		// Super-admin can assign any role
	} else {
		// Check caller's role in the target tenant
		callerRole, err := s.store.GetOperatorRole(identity.OperatorID, req.TenantID)
		if err != nil {
			writeError(w, r, http.StatusForbidden, "you do not have permission to manage roles in this tenant")
			return
		}

		callerPrivilege := rolePrivilege[callerRole]
		if callerPrivilege == 0 {
			callerPrivilege = 1 // Default to operator (lowest)
		}

		// Operators cannot assign any role
		if callerPrivilege < 2 {
			writeError(w, r, http.StatusForbidden, "operators cannot assign roles")
			return
		}

		// Cannot grant role higher than caller's own
		if requestedPrivilege > callerPrivilege {
			writeError(w, r, http.StatusForbidden, fmt.Sprintf("cannot assign role '%s': your role '%s' does not have sufficient privileges", req.Role, callerRole))
			return
		}
	}

	// Assign the role (upsert)
	if err := s.store.UpdateOperatorRole(operatorID, req.TenantID, req.Role); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to assign role: "+err.Error())
		return
	}

	// Audit log the role assignment
	auditEntry := &store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "operator.role_assign",
		Target:    operatorID,
		Decision:  "allowed",
		Details: map[string]string{
			"admin_id":  identity.KID,
			"tenant_id": req.TenantID,
			"role":      req.Role,
		},
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for role assignment: %v", err)
		// Don't fail the request, audit logging is non-critical
	}

	// Return updated operator
	operator, _ := s.store.GetOperator(operatorID)
	writeJSON(w, http.StatusOK, operatorToResponse(operator))
}

// handleRemoveRole handles DELETE /api/v1/operators/{id}/roles/{tenant_id}
// It removes an operator's role in a specific tenant.
func (s *Server) handleRemoveRole(w http.ResponseWriter, r *http.Request) {
	operatorID := r.PathValue("id")
	tenantID := r.PathValue("tenant_id")

	// Verify target operator exists
	targetOp, err := s.store.GetOperator(operatorID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Operator not found")
		return
	}

	// Get caller identity for authorization checks
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil || identity.OperatorID == "" {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	// Prevent self-lockout
	if identity.OperatorID == targetOp.ID {
		writeError(w, r, http.StatusForbidden, "cannot remove your own roles (prevents self-lockout)")
		return
	}

	// Get target's current role (to check privileges)
	targetRole, err := s.store.GetOperatorRole(operatorID, tenantID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Operator does not have a role in this tenant")
		return
	}

	// Check caller authorization
	rolePrivilege := map[string]int{
		"operator":     1,
		"tenant:admin": 2,
		"super:admin":  3,
	}
	targetPrivilege := rolePrivilege[targetRole]

	isSuperAdmin, err := s.store.IsSuperAdmin(identity.OperatorID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to check caller permissions")
		return
	}

	if isSuperAdmin {
		// Super-admin can remove any role
	} else {
		// Check caller's role in the target tenant
		callerRole, err := s.store.GetOperatorRole(identity.OperatorID, tenantID)
		if err != nil {
			writeError(w, r, http.StatusForbidden, "you do not have permission to manage roles in this tenant")
			return
		}

		callerPrivilege := rolePrivilege[callerRole]
		if callerPrivilege == 0 {
			callerPrivilege = 1
		}

		// Operators cannot remove any role
		if callerPrivilege < 2 {
			writeError(w, r, http.StatusForbidden, "operators cannot remove roles")
			return
		}

		// Cannot remove role higher than or equal to caller's own
		if targetPrivilege >= callerPrivilege {
			writeError(w, r, http.StatusForbidden, fmt.Sprintf("cannot remove role '%s': your role '%s' does not have sufficient privileges", targetRole, callerRole))
			return
		}
	}

	// Remove the role
	if err := s.store.RemoveOperatorFromTenant(operatorID, tenantID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to remove role: "+err.Error())
		return
	}

	// Audit log the role removal
	auditEntry := &store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "operator.role_remove",
		Target:    operatorID,
		Decision:  "allowed",
		Details: map[string]string{
			"admin_id":     identity.KID,
			"tenant_id":    tenantID,
			"removed_role": targetRole,
		},
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for role removal: %v", err)
		// Don't fail the request, audit logging is non-critical
	}

	w.WriteHeader(http.StatusNoContent)
}
