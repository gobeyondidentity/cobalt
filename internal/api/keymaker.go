package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/store"
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

	// Validate role
	if req.Role != "admin" && req.Role != "operator" {
		writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid role: %s (must be 'admin' or 'operator')", req.Role))
		return
	}

	// Get tenant
	tenant, err := s.store.GetTenant(req.TenantName)
	if err != nil {
		writeError(w, r, http.StatusNotFound, fmt.Sprintf("tenant not found: %s", req.TenantName))
		return
	}

	// Check if operator exists
	var operator *store.Operator
	op, err := s.store.GetOperatorByEmail(req.Email)
	if err == nil && op != nil {
		operator = op
		// Operator exists - idempotent: if not pending_invite, return success
		if op.Status != "pending_invite" {
			response := InviteOperatorResponse{
				Status: "already_exists",
			}
			response.Operator.ID = op.ID
			response.Operator.Email = op.Email
			response.Operator.Status = op.Status
			writeJSON(w, http.StatusOK, response)
			return
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
		CreatedBy:     "admin", // TODO: get from auth context
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Status:        "pending",
	}

	if err := s.store.CreateInviteCode(invite); err != nil {
		writeError(w, r, http.StatusInternalServerError, fmt.Sprintf("failed to create invite: %v", err))
		return
	}

	// Return response
	response := InviteOperatorResponse{
		Status:     "invited",
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
	ID         string `json:"id"`
	Email      string `json:"email"`
	TenantID   string `json:"tenant_id,omitempty"`
	TenantName string `json:"tenant_name,omitempty"`
	Role       string `json:"role,omitempty"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
}

// updateOperatorStatusRequest is the request body for updating operator status.
type updateOperatorStatusRequest struct {
	Status string `json:"status"` // "active" or "suspended"
}

func operatorToResponse(op *store.Operator) operatorResponse {
	return operatorResponse{
		ID:        op.ID,
		Email:     op.Email,
		Status:    op.Status,
		CreatedAt: op.CreatedAt.Format(time.RFC3339),
	}
}

func operatorToResponseWithTenant(op *store.Operator, tenantID, tenantName, role string) operatorResponse {
	return operatorResponse{
		ID:         op.ID,
		Email:      op.Email,
		TenantID:   tenantID,
		TenantName: tenantName,
		Role:       role,
		Status:     op.Status,
		CreatedAt:  op.CreatedAt.Format(time.RFC3339),
	}
}

// handleListOperators handles GET /api/v1/operators
// Supports optional ?tenant=<name> query parameter to filter by tenant.
// Returns one row per operator-tenant membership.
func (s *Server) handleListOperators(w http.ResponseWriter, r *http.Request) {
	tenantName := r.URL.Query().Get("tenant")

	var result []operatorResponse

	if tenantName != "" {
		// Filtered by tenant: return operators for that specific tenant
		tenant, terr := s.store.GetTenant(tenantName)
		if terr != nil {
			writeError(w, r, http.StatusNotFound, fmt.Sprintf("tenant not found: %s", tenantName))
			return
		}
		operators, err := s.store.ListOperatorsByTenant(tenant.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "Failed to list operators: "+err.Error())
			return
		}
		result = make([]operatorResponse, 0, len(operators))
		for _, op := range operators {
			// Get role for this operator-tenant membership
			role, err := s.store.GetOperatorRole(op.ID, tenant.ID)
			if err != nil {
				role = "" // Should not happen, but degrade gracefully
			}
			result = append(result, operatorToResponseWithTenant(op, tenant.ID, tenant.Name, role))
		}
	} else {
		// No filter: return all operators with all their tenant memberships
		operators, err := s.store.ListOperators()
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "Failed to list operators: "+err.Error())
			return
		}
		result = make([]operatorResponse, 0)
		for _, op := range operators {
			// Get all tenant memberships for this operator
			memberships, err := s.store.GetOperatorTenants(op.ID)
			if err != nil || len(memberships) == 0 {
				// Operator with no tenant memberships: include without tenant info
				result = append(result, operatorToResponse(op))
				continue
			}
			// One row per tenant membership
			for _, m := range memberships {
				tenant, err := s.store.GetTenant(m.TenantID)
				tenantName := ""
				if err == nil {
					tenantName = tenant.Name
				}
				result = append(result, operatorToResponseWithTenant(op, m.TenantID, tenantName, m.Role))
			}
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// handleGetOperator handles GET /api/v1/operators/{email}
func (s *Server) handleGetOperator(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")

	operator, err := s.store.GetOperatorByEmail(email)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Operator not found")
		return
	}

	writeJSON(w, http.StatusOK, operatorToResponse(operator))
}

// handleUpdateOperatorStatus handles PATCH /api/v1/operators/{email}/status
func (s *Server) handleUpdateOperatorStatus(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")

	// Look up operator by email
	operator, err := s.store.GetOperatorByEmail(email)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Operator not found")
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

// handleDeleteOperator handles DELETE /api/v1/operators/{email}
func (s *Server) handleDeleteOperator(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")

	// Look up operator by email
	operator, err := s.store.GetOperatorByEmail(email)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Operator not found")
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
	return resp
}

// handleListKeyMakers handles GET /api/v1/keymakers
// Supports optional ?operator_id= query parameter to filter by operator.
func (s *Server) handleListKeyMakers(w http.ResponseWriter, r *http.Request) {
	operatorID := r.URL.Query().Get("operator_id")

	var keymakers []*store.KeyMaker
	var err error

	if operatorID != "" {
		keymakers, err = s.store.ListKeyMakersByOperator(operatorID)
	} else {
		keymakers, err = s.store.ListAllKeyMakers()
	}

	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to list keymakers: "+err.Error())
		return
	}

	result := make([]KeyMakerResponse, 0, len(keymakers))
	for _, km := range keymakers {
		result = append(result, s.keymakerToResponse(km))
	}

	writeJSON(w, http.StatusOK, result)
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

// handleRevokeKeyMaker handles DELETE /api/v1/keymakers/{id}
func (s *Server) handleRevokeKeyMaker(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check if keymaker exists first
	km, err := s.store.GetKeyMaker(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "KeyMaker not found")
		return
	}

	// Revoke the keymaker
	if err := s.store.RevokeKeyMaker(id); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to revoke keymaker: "+err.Error())
		return
	}

	log.Printf("KeyMaker revoked: id=%s operator_id=%s name=%s", km.ID, km.OperatorID, km.Name)

	w.WriteHeader(http.StatusNoContent)
}
