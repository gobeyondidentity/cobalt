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

// Constants for KeyMaker operations.
const (
	// InviteCodePrefixMaxLength is the max length of tenant name prefix in invite codes.
	InviteCodePrefixMaxLength = 4

	// InviteDefaultTTL is how long an invite code is valid before expiring.
	InviteDefaultTTL = 24 * time.Hour
)

// ----- KeyMaker Binding Types -----

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
		// Use generic error to prevent invite code enumeration
		writeError(w, r, http.StatusBadRequest, "invalid or expired invite code")
		return
	}

	// Step 3: Validate invite status and expiration
	// Use generic error for all failure cases to prevent enumeration
	switch invite.Status {
	case "pending":
		// fall through to expiration check
	case "used", "revoked", "expired":
		writeError(w, r, http.StatusBadRequest, "invalid or expired invite code")
		return
	default:
		writeError(w, r, http.StatusBadRequest, "invalid or expired invite code")
		return
	}

	if time.Now().After(invite.ExpiresAt) {
		writeError(w, r, http.StatusBadRequest, "invalid or expired invite code")
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
