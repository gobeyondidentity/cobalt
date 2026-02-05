package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/audit"
	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// ----- Operator Management Types -----

// operatorResponse is the response for operator endpoints.
type operatorResponse struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	TenantID        string  `json:"tenant_id,omitempty"`
	TenantName      string  `json:"tenant_name,omitempty"`
	Role            string  `json:"role,omitempty"`
	Status          string  `json:"status"`
	CreatedAt       string  `json:"created_at"`
	SuspendedAt     *string `json:"suspended_at,omitempty"`
	SuspendedBy     *string `json:"suspended_by,omitempty"`
	SuspendedReason *string `json:"suspended_reason,omitempty"`
}

// OperatorListResponse is the paginated response for listing operators.
type OperatorListResponse struct {
	Operators []operatorResponse `json:"operators"`
	Total     int                `json:"total"`
	Limit     int                `json:"limit"`
	Offset    int                `json:"offset"`
}

// updateOperatorStatusRequest is the request body for updating operator status.
type updateOperatorStatusRequest struct {
	Status string `json:"status"` // "active" or "suspended"
}

// SuspendOperatorRequest is the request body for suspending an operator.
type SuspendOperatorRequest struct {
	Reason string `json:"reason"`
}

// UnsuspendOperatorRequest is the request body for unsuspending an operator.
type UnsuspendOperatorRequest struct {
	Reason string `json:"reason"`
}

func operatorToResponse(op *store.Operator) operatorResponse {
	resp := operatorResponse{
		ID:        op.ID,
		Email:     op.Email,
		Status:    op.Status,
		CreatedAt: op.CreatedAt.Format(time.RFC3339),
	}
	if op.SuspendedAt != nil {
		t := op.SuspendedAt.Format(time.RFC3339)
		resp.SuspendedAt = &t
	}
	if op.SuspendedBy != nil {
		resp.SuspendedBy = op.SuspendedBy
	}
	if op.SuspendedReason != nil {
		resp.SuspendedReason = op.SuspendedReason
	}
	return resp
}

func operatorToResponseWithTenant(op *store.Operator, tenantID, tenantName, role string) operatorResponse {
	resp := operatorResponse{
		ID:         op.ID,
		Email:      op.Email,
		TenantID:   tenantID,
		TenantName: tenantName,
		Role:       role,
		Status:     op.Status,
		CreatedAt:  op.CreatedAt.Format(time.RFC3339),
	}
	if op.SuspendedAt != nil {
		t := op.SuspendedAt.Format(time.RFC3339)
		resp.SuspendedAt = &t
	}
	if op.SuspendedBy != nil {
		resp.SuspendedBy = op.SuspendedBy
	}
	if op.SuspendedReason != nil {
		resp.SuspendedReason = op.SuspendedReason
	}
	return resp
}

// handleListOperators handles GET /api/v1/operators
// Supports query parameters:
//   - ?status=<status> - Filter by status (active, suspended, pending)
//   - ?tenant=<name> - Filter by tenant name
//   - ?limit=<n> - Maximum number of results (default: 100)
//   - ?offset=<n> - Number of results to skip (default: 0)
//
// Authorization:
//   - tenant:admin sees only operators in their tenant
//   - super:admin sees all operators
func (s *Server) handleListOperators(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	tenantName := r.URL.Query().Get("tenant")
	statusFilter := r.URL.Query().Get("status")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	// Validate status filter
	validStatuses := map[string]bool{"active": true, "suspended": true, "pending": true, "": true}
	if !validStatuses[statusFilter] {
		writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid status: %s (must be 'active', 'suspended', or 'pending')", statusFilter))
		return
	}

	// Parse pagination with defaults
	limit := 100
	offset := 0
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil || l < 0 {
			writeError(w, r, http.StatusBadRequest, "invalid limit: must be a non-negative integer")
			return
		}
		limit = l
	}
	if offsetStr != "" {
		o, err := strconv.Atoi(offsetStr)
		if err != nil || o < 0 {
			writeError(w, r, http.StatusBadRequest, "invalid offset: must be a non-negative integer")
			return
		}
		offset = o
	}

	// Get caller identity for authorization
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil || identity.OperatorID == "" {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	// Determine authorized tenant(s)
	isSuperAdmin, err := s.store.IsSuperAdmin(identity.OperatorID)
	if err != nil {
		writeInternalError(w, r, err, "failed to check permissions")
		return
	}

	var authorizedTenantID string

	if tenantName != "" {
		// Explicit tenant filter requested
		tenant, terr := s.store.GetTenant(tenantName)
		if terr != nil {
			writeError(w, r, http.StatusNotFound, fmt.Sprintf("tenant not found: %s", tenantName))
			return
		}
		// Check if caller can access this tenant
		if !isSuperAdmin {
			callerRole, err := s.store.GetOperatorRole(identity.OperatorID, tenant.ID)
			if err != nil || (callerRole != "tenant:admin" && callerRole != "super:admin") {
				writeError(w, r, http.StatusForbidden, "not authorized to list operators in this tenant")
				return
			}
		}
		authorizedTenantID = tenant.ID
	} else if !isSuperAdmin {
		// No tenant filter and not super:admin: limit to caller's admin tenant(s)
		callerTenants, err := s.store.GetOperatorTenants(identity.OperatorID)
		if err != nil {
			writeInternalError(w, r, err, "failed to get caller tenants")
			return
		}
		// Find first tenant where caller is admin
		for _, t := range callerTenants {
			if t.Role == "tenant:admin" || t.Role == "super:admin" {
				authorizedTenantID = t.TenantID
				break
			}
		}
		if authorizedTenantID == "" {
			writeError(w, r, http.StatusForbidden, "not authorized to list operators (must be tenant:admin or super:admin)")
			return
		}
	}
	// If super:admin with no tenant filter, authorizedTenantID stays empty (sees all)

	// Build list options
	opts := store.ListOptions{
		Status:   statusFilter,
		TenantID: authorizedTenantID,
		Limit:    limit,
		Offset:   offset,
	}

	// Fetch operators
	operators, total, err := s.store.ListOperatorsFiltered(opts)
	if err != nil {
		writeInternalError(w, r, err, "failed to list operators")
		return
	}

	// Build response with tenant info
	result := make([]operatorResponse, 0, len(operators))

	if authorizedTenantID != "" {
		// Single tenant filter: cache tenant name lookup (was N queries, now 1)
		tenant, err := s.store.GetTenant(authorizedTenantID)
		tenantNameStr := authorizedTenantID
		if err == nil {
			tenantNameStr = tenant.Name
		}
		for _, op := range operators {
			role, _ := s.store.GetOperatorRole(op.ID, authorizedTenantID)
			result = append(result, operatorToResponseWithTenant(op, authorizedTenantID, tenantNameStr, role))
		}
	} else {
		// Super-admin view without tenant filter: batch lookup all memberships
		// Collect operator IDs for batch query
		operatorIDs := make([]string, len(operators))
		for i, op := range operators {
			operatorIDs[i] = op.ID
		}

		// Batch fetch all memberships with tenant names (was N+M queries, now 1)
		membershipMap, err := s.store.GetOperatorTenantsForOperators(operatorIDs)
		if err != nil {
			writeInternalError(w, r, err, "failed to get operator tenants")
			return
		}

		for _, op := range operators {
			memberships := membershipMap[op.ID]
			if len(memberships) == 0 {
				result = append(result, operatorToResponse(op))
				continue
			}
			for _, m := range memberships {
				result = append(result, operatorToResponseWithTenant(op, m.TenantID, m.TenantName, m.Role))
			}
		}
	}

	writeJSON(w, http.StatusOK, OperatorListResponse{
		Operators: result,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
	})
}

// handleGetOperator handles GET /api/v1/operators/{email}
// Authorization: tenant:admin (same tenant) or super:admin
func (s *Server) handleGetOperator(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")

	// Get caller identity for authorization
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil || identity.OperatorID == "" {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	operator, err := s.store.GetOperatorByEmail(email)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Operator not found")
		return
	}

	// Authorization check: caller must be able to manage this operator
	canManage, err := s.canManageOperator(identity.OperatorID, operator.ID)
	if err != nil {
		writeInternalError(w, r, err, "failed to check permissions")
		return
	}
	if !canManage {
		writeError(w, r, http.StatusForbidden, "you do not have permission to view this operator")
		return
	}

	writeJSON(w, http.StatusOK, operatorToResponse(operator))
}

// handleUpdateOperatorStatus handles PATCH /api/v1/operators/{email}/status
// Authorization: tenant:admin (same tenant) or super:admin
func (s *Server) handleUpdateOperatorStatus(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")

	// Get caller identity for authorization
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil || identity.OperatorID == "" {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	// Look up operator by email
	operator, err := s.store.GetOperatorByEmail(email)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Operator not found")
		return
	}

	// Authorization check: caller must be able to manage this operator
	canManage, err := s.canManageOperator(identity.OperatorID, operator.ID)
	if err != nil {
		writeInternalError(w, r, err, "failed to check permissions")
		return
	}
	if !canManage {
		writeError(w, r, http.StatusForbidden, "you do not have permission to modify this operator")
		return
	}

	var req updateOperatorStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate status
	if req.Status != "active" && req.Status != "suspended" {
		writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid status: %s (must be 'active' or 'suspended')", req.Status))
		return
	}

	// Update status
	if err := s.store.UpdateOperatorStatus(operator.ID, req.Status); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to update operator status: "+err.Error())
		return
	}

	// Fetch updated operator
	operator, _ = s.store.GetOperatorByEmail(email)
	writeJSON(w, http.StatusOK, operatorToResponse(operator))
}

// handleSuspendOperator handles POST /api/v1/operators/{id}/suspend
// Suspends an operator, blocking all their KeyMakers immediately.
// Requires tenant:admin (for operators in shared tenant) or super:admin.
func (s *Server) handleSuspendOperator(w http.ResponseWriter, r *http.Request) {
	operatorID := r.PathValue("id")

	// Parse request body
	var req SuspendOperatorRequest
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

	// Get target operator (for authorization check and audit log)
	operator, err := s.store.GetOperator(operatorID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "operator not found")
		return
	}

	// Authorization check
	canManage, err := s.canManageOperator(identity.OperatorID, operatorID)
	if err != nil {
		writeInternalError(w, r, err, "failed to check permissions")
		return
	}
	if !canManage {
		writeError(w, r, http.StatusForbidden, "you do not have permission to suspend this operator")
		return
	}

	// Atomically suspend the operator (handles concurrent suspension with 409)
	if err := s.store.SuspendOperatorAtomic(operatorID, identity.KID, req.Reason); err != nil {
		if err == store.ErrOperatorAlreadySuspended {
			writeError(w, r, http.StatusConflict, "operator is already suspended")
			return
		}
		writeInternalError(w, r, err, "failed to suspend operator")
		return
	}

	// Create audit log entry
	auditEntry := &store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "operator.suspend",
		Target:    operatorID,
		Decision:  "allowed",
		Details: map[string]string{
			"admin_id":       identity.KID,
			"operator_id":    operatorID,
			"operator_email": operator.Email,
			"reason":         req.Reason,
		},
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for operator suspension: %v", err)
	}

	// Emit structured lifecycle audit event (non-blocking)
	s.emitAuditEvent(audit.NewLifecycleSuspend(identity.KID, getClientIP(r), operatorID, req.Reason, ""))

	log.Printf("Operator suspended: operator_id=%s email=%s by=%s reason=%s", operatorID, operator.Email, identity.KID, req.Reason)

	// Fetch updated operator and return response
	operator, _ = s.store.GetOperator(operatorID)
	writeJSON(w, http.StatusOK, operatorToResponse(operator))
}

// handleUnsuspendOperator handles POST /api/v1/operators/{id}/unsuspend
// Restores a suspended operator, allowing all their KeyMakers to function again.
// Requires tenant:admin (for operators in shared tenant) or super:admin.
func (s *Server) handleUnsuspendOperator(w http.ResponseWriter, r *http.Request) {
	operatorID := r.PathValue("id")

	// Parse request body
	var req UnsuspendOperatorRequest
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

	// Get target operator (for authorization check and audit log)
	operator, err := s.store.GetOperator(operatorID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "operator not found")
		return
	}

	// Authorization check
	canManage, err := s.canManageOperator(identity.OperatorID, operatorID)
	if err != nil {
		writeInternalError(w, r, err, "failed to check permissions")
		return
	}
	if !canManage {
		writeError(w, r, http.StatusForbidden, "you do not have permission to unsuspend this operator")
		return
	}

	// Atomically unsuspend the operator (handles concurrent unsuspension with 409)
	if err := s.store.UnsuspendOperatorAtomic(operatorID); err != nil {
		if err == store.ErrOperatorNotSuspended {
			writeError(w, r, http.StatusConflict, "operator is not currently suspended")
			return
		}
		writeInternalError(w, r, err, "failed to unsuspend operator")
		return
	}

	// Create audit log entry
	auditEntry := &store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "operator.unsuspend",
		Target:    operatorID,
		Decision:  "allowed",
		Details: map[string]string{
			"admin_id":       identity.KID,
			"operator_id":    operatorID,
			"operator_email": operator.Email,
			"reason":         req.Reason,
		},
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for operator unsuspension: %v", err)
	}

	// Emit structured lifecycle audit event (non-blocking)
	s.emitAuditEvent(audit.NewLifecycleUnsuspend(identity.KID, getClientIP(r), operatorID, req.Reason, ""))

	log.Printf("Operator unsuspended: operator_id=%s email=%s by=%s reason=%s", operatorID, operator.Email, identity.KID, req.Reason)

	// Fetch updated operator and return response
	operator, _ = s.store.GetOperator(operatorID)
	writeJSON(w, http.StatusOK, operatorToResponse(operator))
}

// canManageOperator checks if the caller has permission to manage (suspend/unsuspend) the target operator.
// Returns true if:
// - Caller is super:admin (can manage any operator)
// - Caller is tenant:admin in at least one tenant where the target operator is also a member
func (s *Server) canManageOperator(callerOperatorID, targetOperatorID string) (bool, error) {
	// Check if caller is super:admin
	isSuperAdmin, err := s.store.IsSuperAdmin(callerOperatorID)
	if err != nil {
		return false, fmt.Errorf("failed to check super admin status: %w", err)
	}
	if isSuperAdmin {
		return true, nil
	}

	// Get caller's tenant memberships
	callerTenants, err := s.store.GetOperatorTenants(callerOperatorID)
	if err != nil {
		return false, fmt.Errorf("failed to get caller tenants: %w", err)
	}

	// Build set of tenants where caller is tenant:admin
	callerAdminTenants := make(map[string]bool)
	for _, t := range callerTenants {
		if t.Role == "tenant:admin" || t.Role == "super:admin" {
			callerAdminTenants[t.TenantID] = true
		}
	}

	// If caller is not admin in any tenant, they can't manage anyone
	if len(callerAdminTenants) == 0 {
		return false, nil
	}

	// Get target operator's tenant memberships
	targetTenants, err := s.store.GetOperatorTenants(targetOperatorID)
	if err != nil {
		return false, fmt.Errorf("failed to get target tenants: %w", err)
	}

	// Check if there's any overlap where caller is admin
	for _, t := range targetTenants {
		if callerAdminTenants[t.TenantID] {
			return true, nil
		}
	}

	return false, nil
}

// handleDeleteOperator handles DELETE /api/v1/operators/{email}
// Authorization: tenant:admin (same tenant) or super:admin
func (s *Server) handleDeleteOperator(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")

	// Get caller identity for authorization
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil || identity.OperatorID == "" {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	// Look up operator by email
	operator, err := s.store.GetOperatorByEmail(email)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Operator not found")
		return
	}

	// Authorization check: caller must be able to manage this operator
	canManage, err := s.canManageOperator(identity.OperatorID, operator.ID)
	if err != nil {
		writeInternalError(w, r, err, "failed to check permissions")
		return
	}
	if !canManage {
		writeError(w, r, http.StatusForbidden, "you do not have permission to delete this operator")
		return
	}

	// Delete operator (store method handles dependency checks)
	if err := s.store.DeleteOperator(operator.ID); err != nil {
		if strings.Contains(err.Error(), "keymaker") || strings.Contains(err.Error(), "authorization") {
			writeError(w, r, http.StatusConflict, err.Error())
			return
		}
		writeError(w, r, http.StatusInternalServerError, "Failed to delete operator: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
