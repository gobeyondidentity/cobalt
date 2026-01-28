// Package api implements the HTTP API server for the dashboard.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nmelo/secure-infra/pkg/store"
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
	if invite.Status != "pending" {
		writeError(w, r, http.StatusBadRequest, "invite code has already been used")
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
	keymakerID := "km_" + uuid.New().String()[:8]

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
		opID := "op_" + uuid.New().String()[:8]
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
		ID:            "inv_" + uuid.New().String()[:8],
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
