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
	"github.com/google/uuid"
)

// ----- KeyMaker Types -----

// BindRequest is the request body for binding a KeyMaker.
type BindRequest struct {
	InviteCode        string `json:"invite_code"`
	PublicKey         string `json:"public_key"`
	Platform          string `json:"platform"`
	SecureElement     string `json:"secure_element"`
	DeviceFingerprint string `json:"device_fingerprint"`
	DeviceName        string `json:"device_name,omitempty"`
}

// BindResponse is the response for a successful KeyMaker binding.
type BindResponse struct {
	KeyMakerID    string       `json:"keymaker_id"`
	OperatorID    string       `json:"operator_id"`
	OperatorEmail string       `json:"operator_email"`
	Tenants       []TenantRole `json:"tenants"`
}

// TenantRole represents a tenant membership with role.
type TenantRole struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	Role       string `json:"role"`
}

// handleBindKeyMaker handles POST /api/v1/keymakers/bind
// It exchanges an invite code for a KeyMaker binding.
func (s *Server) handleBindKeyMaker(w http.ResponseWriter, r *http.Request) {
	var req BindRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Step 1: Hash incoming invite code with SHA-256
	codeHash := store.HashInviteCode(req.InviteCode)

	// Step 2: Lookup invite by hash
	invite, err := s.store.GetInviteCodeByHash(codeHash)
	if err != nil {
		// Invite code not found
		writeError(w, r, http.StatusBadRequest, "invalid invite code")
		return
	}

	// Step 3: Validate invite status and expiration
	switch invite.Status {
	case "pending":
		// fall through to expiration check
	case "used":
		writeError(w, r, http.StatusBadRequest, "invite code has already been used")
		return
	case "revoked":
		writeError(w, r, http.StatusBadRequest, "invite code has been revoked")
		return
	case "expired":
		writeError(w, r, http.StatusBadRequest, "invite code has expired")
		return
	default:
		writeError(w, r, http.StatusBadRequest, "invalid invite code")
		return
	}

	if time.Now().After(invite.ExpiresAt) {
		writeError(w, r, http.StatusBadRequest, "invite code has expired")
		return
	}

	// Step 4: Look up the operator by email from the invite
	operator, err := s.store.GetOperatorByEmail(invite.OperatorEmail)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to lookup operator: %v", err))
		return
	}

	// Step 5: Generate KeyMaker ID and name
	keymakerID := "km_" + uuid.New().String()[:UUIDShortLength]

	// Auto-generate name if not provided
	deviceName := req.DeviceName
	if deviceName == "" {
		// Extract first name from email (before @) for the auto-generated name
		emailParts := strings.Split(operator.Email, "@")
		emailUser := emailParts[0]
		// Use first part of email user (before any dots or plus signs)
		nameParts := strings.FieldsFunc(emailUser, func(r rune) bool {
			return r == '.' || r == '+' || r == '_'
		})
		firstName := nameParts[0]
		// Format: km-{platform}-{firstName}-{random4}
		random4 := uuid.New().String()[:4]
		deviceName = fmt.Sprintf("km-%s-%s-%s", req.Platform, firstName, random4)
	}

	// Step 6: Create KeyMaker record
	keymaker := &store.KeyMaker{
		ID:                keymakerID,
		OperatorID:        operator.ID,
		Name:              deviceName,
		Platform:          req.Platform,
		SecureElement:     req.SecureElement,
		DeviceFingerprint: req.DeviceFingerprint,
		PublicKey:         req.PublicKey,
		Status:            "active",
	}

	if err := s.store.CreateKeyMaker(keymaker); err != nil {
		writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to create keymaker: %v", err))
		return
	}

	// Step 7: Mark invite as used
	if err := s.store.MarkInviteCodeUsed(invite.ID, keymakerID); err != nil {
		writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to mark invite as used: %v", err))
		return
	}

	// Step 8: Update operator status to "active"
	if err := s.store.UpdateOperatorStatus(operator.ID, "active"); err != nil {
		writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to update operator status: %v", err))
		return
	}

	// Step 9: Get operator's tenants
	operatorTenants, err := s.store.GetOperatorTenants(operator.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to get operator tenants: %v", err))
		return
	}

	// Build tenant roles response
	tenantRoles := make([]TenantRole, 0, len(operatorTenants))
	for _, ot := range operatorTenants {
		// Look up tenant name
		tenant, err := s.store.GetTenant(ot.TenantID)
		tenantName := ot.TenantID // fallback to ID if lookup fails
		if err == nil {
			tenantName = tenant.Name
		}
		tenantRoles = append(tenantRoles, TenantRole{
			TenantID:   ot.TenantID,
			TenantName: tenantName,
			Role:       ot.Role,
		})
	}

	// Step 10: Return BindResponse
	response := BindResponse{
		KeyMakerID:    keymakerID,
		OperatorID:    operator.ID,
		OperatorEmail: operator.Email,
		Tenants:       tenantRoles,
	}

	writeJSON(w, http.StatusOK, response)
}

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
	if len(prefix) > 4 {
		prefix = prefix[:4]
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
		ExpiresAt:     time.Now().Add(24 * time.Hour),
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
	for _, op := range operators {
		if authorizedTenantID != "" {
			// Single tenant filter: include tenant info
			tenant, err := s.store.GetTenant(authorizedTenantID)
			tenantNameStr := authorizedTenantID
			if err == nil {
				tenantNameStr = tenant.Name
			}
			role, _ := s.store.GetOperatorRole(op.ID, authorizedTenantID)
			result = append(result, operatorToResponseWithTenant(op, authorizedTenantID, tenantNameStr, role))
		} else {
			// Super-admin view without tenant filter: include all tenant memberships
			memberships, err := s.store.GetOperatorTenants(op.ID)
			if err != nil || len(memberships) == 0 {
				result = append(result, operatorToResponse(op))
				continue
			}
			for _, m := range memberships {
				tenant, err := s.store.GetTenant(m.TenantID)
				tName := m.TenantID
				if err == nil {
					tName = tenant.Name
				}
				result = append(result, operatorToResponseWithTenant(op, m.TenantID, tName, m.Role))
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

// ----- Operator Lifecycle Endpoints (Phase 4) -----

// SuspendOperatorRequest is the request body for suspending an operator.
type SuspendOperatorRequest struct {
	Reason string `json:"reason"`
}

// UnsuspendOperatorRequest is the request body for unsuspending an operator.
type UnsuspendOperatorRequest struct {
	Reason string `json:"reason"`
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

	// Get target operator
	operator, err := s.store.GetOperator(operatorID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "operator not found")
		return
	}

	// Check if already suspended
	if operator.Status == "suspended" {
		writeError(w, r, http.StatusConflict, "operator is already suspended")
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

	// Suspend the operator
	if err := s.store.SuspendOperator(operatorID, identity.KID, req.Reason); err != nil {
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
		// Don't fail the request, audit logging is non-critical
	}

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

	// Get target operator
	operator, err := s.store.GetOperator(operatorID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "operator not found")
		return
	}

	// Check if not suspended
	if operator.Status != "suspended" {
		writeError(w, r, http.StatusConflict, "operator is not currently suspended")
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

	// Unsuspend the operator
	if err := s.store.UnsuspendOperator(operatorID); err != nil {
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
		// Don't fail the request, audit logging is non-critical
	}

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
			"admin_id":      identity.KID,
			"tenant_id":     tenantID,
			"removed_role":  targetRole,
		},
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for role removal: %v", err)
		// Don't fail the request, audit logging is non-critical
	}

	w.WriteHeader(http.StatusNoContent)
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

// ----- KeyMaker Management Types -----

// KeyMakerResponse is the response for keymaker endpoints.
type KeyMakerResponse struct {
	ID            string  `json:"id"`
	OperatorID    string  `json:"operator_id"`
	OperatorEmail string  `json:"operator_email"`
	Name          string  `json:"name"`
	Platform      string  `json:"platform"`
	SecureElement string  `json:"secure_element"`
	BoundAt       string  `json:"bound_at"`
	LastSeen      *string `json:"last_seen,omitempty"`
	Status        string  `json:"status"`
	RevokedAt     *string `json:"revoked_at,omitempty"`
	RevokedBy     *string `json:"revoked_by,omitempty"`
	RevokedReason *string `json:"revoked_reason,omitempty"`
}

// KeyMakerListResponse is the paginated response for listing keymakers.
type KeyMakerListResponse struct {
	KeyMakers []KeyMakerResponse `json:"keymakers"`
	Total     int                `json:"total"`
	Limit     int                `json:"limit"`
	Offset    int                `json:"offset"`
}

// keymakerToResponse converts a store.KeyMaker to an API response.
// It resolves the operator email from the operator ID.
func (s *Server) keymakerToResponse(km *store.KeyMaker) KeyMakerResponse {
	resp := KeyMakerResponse{
		ID:            km.ID,
		OperatorID:    km.OperatorID,
		Name:          km.Name,
		Platform:      km.Platform,
		SecureElement: km.SecureElement,
		BoundAt:       km.BoundAt.Format(time.RFC3339),
		Status:        km.Status,
	}

	// Resolve operator email (graceful degradation: use ID if lookup fails)
	if op, err := s.store.GetOperator(km.OperatorID); err == nil {
		resp.OperatorEmail = op.Email
	} else {
		resp.OperatorEmail = km.OperatorID
	}

	if km.LastSeen != nil {
		t := km.LastSeen.Format(time.RFC3339)
		resp.LastSeen = &t
	}
	if km.RevokedAt != nil {
		t := km.RevokedAt.Format(time.RFC3339)
		resp.RevokedAt = &t
	}
	if km.RevokedBy != nil {
		resp.RevokedBy = km.RevokedBy
	}
	if km.RevokedReason != nil {
		resp.RevokedReason = km.RevokedReason
	}
	return resp
}

// handleListKeyMakers handles GET /api/v1/keymakers
// Supports query parameters:
//   - ?status=<status> - Filter by status (active, revoked)
//   - ?tenant=<id> - Filter by tenant ID
//   - ?operator_id=<id> - Filter by operator ID (legacy, still supported)
//   - ?limit=<n> - Maximum number of results (default: 100)
//   - ?offset=<n> - Number of results to skip (default: 0)
//
// Authorization:
//   - tenant:admin sees only keymakers for operators in their tenant
//   - super:admin sees all keymakers
func (s *Server) handleListKeyMakers(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	tenantID := r.URL.Query().Get("tenant")
	statusFilter := r.URL.Query().Get("status")
	operatorID := r.URL.Query().Get("operator_id")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	// Validate status filter
	validStatuses := map[string]bool{"active": true, "revoked": true, "": true}
	if !validStatuses[statusFilter] {
		writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid status: %s (must be 'active' or 'revoked')", statusFilter))
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

	// Determine authorized tenant
	isSuperAdmin, err := s.store.IsSuperAdmin(identity.OperatorID)
	if err != nil {
		writeInternalError(w, r, err, "failed to check permissions")
		return
	}

	var authorizedTenantID string

	if tenantID != "" {
		// Explicit tenant filter requested
		_, terr := s.store.GetTenant(tenantID)
		if terr != nil {
			writeError(w, r, http.StatusNotFound, fmt.Sprintf("tenant not found: %s", tenantID))
			return
		}
		// Check if caller can access this tenant
		if !isSuperAdmin {
			callerRole, err := s.store.GetOperatorRole(identity.OperatorID, tenantID)
			if err != nil || (callerRole != "tenant:admin" && callerRole != "super:admin") {
				writeError(w, r, http.StatusForbidden, "not authorized to list keymakers in this tenant")
				return
			}
		}
		authorizedTenantID = tenantID
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
			writeError(w, r, http.StatusForbidden, "not authorized to list keymakers (must be tenant:admin or super:admin)")
			return
		}
	}
	// If super:admin with no tenant filter, authorizedTenantID stays empty (sees all)

	// Legacy support: if operator_id provided and caller has access, use it
	// (this maintains backward compatibility while still enforcing auth)
	if operatorID != "" && authorizedTenantID == "" {
		// Super-admin can filter by any operator
		keymakers, err := s.store.ListKeyMakersByOperator(operatorID)
		if err != nil {
			writeInternalError(w, r, err, "failed to list keymakers")
			return
		}
		result := make([]KeyMakerResponse, 0, len(keymakers))
		for _, km := range keymakers {
			if statusFilter == "" || km.Status == statusFilter {
				result = append(result, s.keymakerToResponse(km))
			}
		}
		// Apply pagination manually for legacy operator_id filter
		total := len(result)
		start := offset
		end := offset + limit
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}
		writeJSON(w, http.StatusOK, KeyMakerListResponse{
			KeyMakers: result[start:end],
			Total:     total,
			Limit:     limit,
			Offset:    offset,
		})
		return
	}

	// Build list options
	opts := store.ListOptions{
		Status:   statusFilter,
		TenantID: authorizedTenantID,
		Limit:    limit,
		Offset:   offset,
	}

	// Fetch keymakers
	keymakers, total, err := s.store.ListKeyMakersFiltered(opts)
	if err != nil {
		writeInternalError(w, r, err, "failed to list keymakers")
		return
	}

	result := make([]KeyMakerResponse, 0, len(keymakers))
	for _, km := range keymakers {
		result = append(result, s.keymakerToResponse(km))
	}

	writeJSON(w, http.StatusOK, KeyMakerListResponse{
		KeyMakers: result,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
	})
}

// handleGetKeyMaker handles GET /api/v1/keymakers/{id}
func (s *Server) handleGetKeyMaker(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	km, err := s.store.GetKeyMaker(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "KeyMaker not found")
		return
	}

	writeJSON(w, http.StatusOK, s.keymakerToResponse(km))
}

// RevokeKeyMakerRequest is the request body for revoking a KeyMaker.
type RevokeKeyMakerRequest struct {
	Reason string `json:"reason"`
}

// RevokeKeyMakerResponse is the response for a successful KeyMaker revocation.
type RevokeKeyMakerResponse struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	RevokedAt     string `json:"revoked_at"`
	RevokedBy     string `json:"revoked_by"`
	RevokedReason string `json:"revoked_reason"`
}

// handleRevokeKeyMaker handles DELETE /api/v1/keymakers/{id}
// Requires JSON body with reason field.
// Authorization: operator can revoke own, tenant:admin for tenant, super:admin for any.
func (s *Server) handleRevokeKeyMaker(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Parse request body
	var req RevokeKeyMakerRequest
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

	// Get KeyMaker to check existence and ownership
	km, err := s.store.GetKeyMaker(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "KeyMaker not found")
		return
	}

	// Check if already revoked
	if km.Status == "revoked" {
		writeError(w, r, http.StatusConflict, "KeyMaker already revoked")
		return
	}

	// Get caller identity
	identity := dpop.IdentityFromContext(r.Context())
	if identity == nil {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	// Authorization check
	authorized, authzErr := s.authorizeKeyMakerRevocation(identity, km)
	if authzErr != nil {
		writeError(w, r, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !authorized {
		writeError(w, r, http.StatusForbidden, "not authorized to revoke this KeyMaker")
		return
	}

	// Atomically revoke (handles concurrent revocation with 409)
	if err := s.store.RevokeKeyMakerAtomic(id, identity.KID, req.Reason); err != nil {
		if err == store.ErrAlreadyRevoked {
			writeError(w, r, http.StatusConflict, "KeyMaker already revoked")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "Failed to revoke keymaker: "+err.Error())
		return
	}

	// Re-fetch to get updated timestamps
	km, err = s.store.GetKeyMaker(id)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to fetch revoked keymaker")
		return
	}

	// Audit log the revocation
	auditEntry := &store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "keymaker.revoke",
		Target:    km.ID,
		Decision:  "allowed",
		Details: map[string]string{
			"actor":       identity.KID,
			"operator_id": km.OperatorID,
			"reason":      req.Reason,
		},
	}
	if _, err := s.store.InsertAuditEntry(auditEntry); err != nil {
		log.Printf("failed to insert audit entry for keymaker revocation: %v", err)
		// Don't fail the request, audit logging is non-critical
	}

	log.Printf("KeyMaker revoked: id=%s operator_id=%s name=%s by=%s reason=%s",
		km.ID, km.OperatorID, km.Name, identity.KID, req.Reason)

	// Build response
	resp := RevokeKeyMakerResponse{
		ID:            km.ID,
		Status:        km.Status,
		RevokedReason: req.Reason,
		RevokedBy:     identity.KID,
	}
	if km.RevokedAt != nil {
		resp.RevokedAt = km.RevokedAt.Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, resp)
}

// authorizeKeyMakerRevocation checks if the caller can revoke a KeyMaker.
// Rules per security-architecture.md:
// - Operator can revoke own KeyMakers
// - tenant:admin can revoke KeyMakers for operators in own tenant
// - super:admin can revoke any KeyMaker
func (s *Server) authorizeKeyMakerRevocation(identity *dpop.Identity, km *store.KeyMaker) (bool, error) {
	// Self-revocation: operator can revoke their own KeyMakers
	if identity.OperatorID == km.OperatorID {
		return true, nil
	}

	// Check if caller is super:admin (can revoke any KeyMaker)
	isSuperAdmin, err := s.store.IsSuperAdmin(identity.OperatorID)
	if err != nil {
		return false, err
	}
	if isSuperAdmin {
		return true, nil
	}

	// Check if caller is tenant:admin in a tenant where the KeyMaker's operator is a member
	// First, get the KeyMaker's operator's tenant memberships
	targetTenants, err := s.store.GetOperatorTenants(km.OperatorID)
	if err != nil {
		return false, err
	}

	// Check if caller has tenant:admin in any of those tenants
	callerTenants, err := s.store.GetOperatorTenants(identity.OperatorID)
	if err != nil {
		return false, err
	}

	for _, callerMembership := range callerTenants {
		if callerMembership.Role != "tenant:admin" {
			continue
		}
		// Check if target operator is in this tenant
		for _, targetMembership := range targetTenants {
			if targetMembership.TenantID == callerMembership.TenantID {
				return true, nil
			}
		}
	}

	// Not authorized
	return false, nil
}
