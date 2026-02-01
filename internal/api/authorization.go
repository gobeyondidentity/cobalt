// Package api implements the HTTP API server for the dashboard.
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/nmelo/secure-infra/pkg/store"
	"github.com/google/uuid"
)

// ----- Authorization Types -----

// CreateAuthorizationRequest is the request body for creating an authorization.
type CreateAuthorizationRequest struct {
	OperatorEmail string   `json:"operator_email"`
	TenantID      string   `json:"tenant_id"`
	CAIDs         []string `json:"ca_ids"`
	DeviceIDs     []string `json:"device_ids"` // ["all"] for all devices
	ExpiresAt     *string  `json:"expires_at,omitempty"` // RFC3339 format
}

// AuthorizationResponse is the response for an authorization.
type AuthorizationResponse struct {
	ID          string   `json:"id"`
	OperatorID  string   `json:"operator_id"`
	TenantID    string   `json:"tenant_id"`
	CAIDs       []string `json:"ca_ids"`
	CANames     []string `json:"ca_names"`
	DeviceIDs   []string `json:"device_ids"`
	DeviceNames []string `json:"device_names"`
	CreatedAt   string   `json:"created_at"`
	CreatedBy   string   `json:"created_by"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
}

// CheckAuthorizationRequest is the request body for checking authorization.
type CheckAuthorizationRequest struct {
	OperatorID  string `json:"operator_id"`
	CAID        string `json:"ca_id"`
	DeviceID    string `json:"device_id,omitempty"`    // Optional, only for distribution
	KeyMakerID  string `json:"keymaker_id,omitempty"`  // Optional, for revocation check
}

// CheckAuthorizationResponse is the response for checking authorization.
type CheckAuthorizationResponse struct {
	Authorized bool   `json:"authorized"`
	Reason     string `json:"reason,omitempty"` // If not authorized, why
}

// ----- Authorization Handlers -----

// handleCreateAuthorization handles POST /api/v1/authorizations
func (s *Server) handleCreateAuthorization(w http.ResponseWriter, r *http.Request) {
	var req CreateAuthorizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if req.OperatorEmail == "" {
		writeError(w, r, http.StatusBadRequest, "operator_email is required")
		return
	}
	if req.TenantID == "" {
		writeError(w, r, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if len(req.CAIDs) == 0 {
		writeError(w, r, http.StatusBadRequest, "ca_ids is required")
		return
	}
	if len(req.DeviceIDs) == 0 {
		writeError(w, r, http.StatusBadRequest, "device_ids is required")
		return
	}

	// Look up operator by email
	operator, err := s.store.GetOperatorByEmail(req.OperatorEmail)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "operator not found")
		return
	}

	// Parse expiration if provided
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid expires_at format, expected RFC3339")
			return
		}
		expiresAt = &t
	}

	// Generate authorization ID
	authID := "auth_" + uuid.New().String()[:UUIDShortLength]

	// Create authorization in store
	// For now, use "system" as created_by since we don't have JWT auth yet
	createdBy := "system"
	if err := s.store.CreateAuthorization(authID, operator.ID, req.TenantID, req.CAIDs, req.DeviceIDs, createdBy, expiresAt); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to create authorization: "+err.Error())
		return
	}

	// Fetch the created authorization
	auth, err := s.store.GetAuthorization(authID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to fetch created authorization: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, s.authorizationToResponse(auth))
}

// handleListAuthorizations handles GET /api/v1/authorizations
func (s *Server) handleListAuthorizations(w http.ResponseWriter, r *http.Request) {
	operatorID := r.URL.Query().Get("operator_id")
	tenantID := r.URL.Query().Get("tenant_id")
	keymakerID := r.URL.Query().Get("keymaker_id")

	// If keymaker_id is provided, look up the keymaker to get its operator_id
	if keymakerID != "" {
		km, err := s.store.GetKeyMaker(keymakerID)
		if err != nil {
			writeError(w, r, http.StatusNotFound, "keymaker not found")
			return
		}
		operatorID = km.OperatorID
	}

	if operatorID == "" && tenantID == "" {
		writeError(w, r, http.StatusBadRequest, "operator_id, tenant_id, or keymaker_id query parameter is required")
		return
	}

	var auths []*store.Authorization
	var err error

	if operatorID != "" {
		auths, err = s.store.ListAuthorizationsByOperator(operatorID)
	} else {
		auths, err = s.store.ListAuthorizationsByTenant(tenantID)
	}

	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to list authorizations: "+err.Error())
		return
	}

	result := make([]AuthorizationResponse, 0, len(auths))
	for _, auth := range auths {
		result = append(result, s.authorizationToResponse(auth))
	}

	writeJSON(w, http.StatusOK, result)
}

// handleGetAuthorization handles GET /api/v1/authorizations/{id}
func (s *Server) handleGetAuthorization(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	auth, err := s.store.GetAuthorization(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "authorization not found")
		return
	}

	writeJSON(w, http.StatusOK, s.authorizationToResponse(auth))
}

// handleDeleteAuthorization handles DELETE /api/v1/authorizations/{id}
func (s *Server) handleDeleteAuthorization(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if err := s.store.DeleteAuthorization(id); err != nil {
		writeError(w, r, http.StatusNotFound, "authorization not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleCheckAuthorization handles POST /api/v1/authorizations/check
func (s *Server) handleCheckAuthorization(w http.ResponseWriter, r *http.Request) {
	var req CheckAuthorizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if req.OperatorID == "" {
		writeError(w, r, http.StatusBadRequest, "operator_id is required")
		return
	}
	if req.CAID == "" {
		writeError(w, r, http.StatusBadRequest, "ca_id is required")
		return
	}

	// Check operator suspension status
	operator, err := s.store.GetOperator(req.OperatorID)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "operator not found")
		return
	}
	if operator.Status == "suspended" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "operator suspended"})
		return
	}

	// Check KeyMaker revocation status if keymaker_id is provided
	if req.KeyMakerID != "" {
		km, err := s.store.GetKeyMaker(req.KeyMakerID)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "device not found")
			return
		}
		if km.Status == "revoked" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "device revoked"})
			return
		}
	}

	var authorized bool

	if req.DeviceID != "" {
		// Full authorization check (CA + device)
		authorized, err = s.store.CheckFullAuthorization(req.OperatorID, req.CAID, req.DeviceID)
	} else {
		// CA-only authorization check
		authorized, err = s.store.CheckCAAuthorization(req.OperatorID, req.CAID)
	}

	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to check authorization: "+err.Error())
		return
	}

	response := CheckAuthorizationResponse{
		Authorized: authorized,
	}

	if !authorized {
		if req.DeviceID != "" {
			response.Reason = "operator is not authorized for this CA and device combination"
		} else {
			response.Reason = "operator is not authorized for this CA"
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// ----- Helper Functions -----

// authorizationToResponse converts a store.Authorization to an API response.
// It resolves CA IDs and device IDs to their human-readable names.
func (s *Server) authorizationToResponse(auth *store.Authorization) AuthorizationResponse {
	resp := AuthorizationResponse{
		ID:          auth.ID,
		OperatorID:  auth.OperatorID,
		TenantID:    auth.TenantID,
		CAIDs:       auth.CAIDs,
		CANames:     make([]string, 0, len(auth.CAIDs)),
		DeviceIDs:   auth.DeviceIDs,
		DeviceNames: make([]string, 0, len(auth.DeviceIDs)),
		CreatedAt:   auth.CreatedAt.Format(time.RFC3339),
		CreatedBy:   auth.CreatedBy,
	}

	// Resolve CA IDs to names (graceful degradation: use ID if name lookup fails)
	for _, caID := range auth.CAIDs {
		if ca, err := s.store.GetSSHCAByID(caID); err == nil {
			resp.CANames = append(resp.CANames, ca.Name)
		} else {
			resp.CANames = append(resp.CANames, caID)
		}
	}

	// Resolve device IDs to names (graceful degradation: use ID if name lookup fails)
	for _, deviceID := range auth.DeviceIDs {
		if deviceID == "all" {
			resp.DeviceNames = append(resp.DeviceNames, "all")
			continue
		}
		if dpu, err := s.store.Get(deviceID); err == nil {
			resp.DeviceNames = append(resp.DeviceNames, dpu.Name)
		} else {
			resp.DeviceNames = append(resp.DeviceNames, deviceID)
		}
	}

	if auth.ExpiresAt != nil {
		t := auth.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &t
	}
	return resp
}
