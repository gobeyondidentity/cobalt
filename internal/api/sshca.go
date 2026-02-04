package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/google/uuid"
)

// ----- SSH CA Registration Types -----

// createSSHCARequest is the request body for creating an SSH CA.
type createSSHCARequest struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`  // SSH public key format (ssh-ed25519 AAAA...)
	KeyType    string `json:"key_type"`    // e.g., "ed25519", "rsa", "ecdsa"
	OperatorID string `json:"operator_id"` // Operator creating the CA
}

// createSSHCAResponse is the response for a created SSH CA.
type createSSHCAResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	KeyType   string `json:"key_type"`
	CreatedAt string `json:"created_at"`
}

// ----- SSH CA Registration Handler -----

// handleCreateSSHCA handles POST /api/v1/ssh-cas
// This endpoint registers an SSH CA's public key with the nexus server.
// The private key remains on the operator's machine.
func (s *Server) handleCreateSSHCA(w http.ResponseWriter, r *http.Request) {
	var req createSSHCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if req.Name == "" {
		writeError(w, r, http.StatusBadRequest, "name is required")
		return
	}
	if req.PublicKey == "" {
		writeError(w, r, http.StatusBadRequest, "public_key is required")
		return
	}
	if req.KeyType == "" {
		writeError(w, r, http.StatusBadRequest, "key_type is required")
		return
	}

	// Get operator ID from authenticated identity (DPoP auth middleware sets this)
	identity := dpop.IdentityFromContext(r.Context())
	operatorID := ""
	if identity != nil && identity.OperatorID != "" {
		operatorID = identity.OperatorID
	} else if req.OperatorID != "" {
		// Fallback to request body for backward compatibility
		operatorID = req.OperatorID
	}

	if operatorID == "" {
		writeError(w, r, http.StatusBadRequest, "operator_id is required")
		return
	}

	// Validate operator exists
	_, err := s.store.GetOperator(operatorID)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "operator not found")
		return
	}

	// Validate public key format (should start with "ssh-" or "ecdsa-")
	if !isValidSSHPublicKeyFormat(req.PublicKey) {
		writeError(w, r, http.StatusBadRequest, "invalid public key format: must start with ssh- or ecdsa-")
		return
	}

	// Check if CA name already exists
	exists, err := s.store.SSHCAExists(req.Name)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to check CA existence: "+err.Error())
		return
	}
	if exists {
		writeError(w, r, http.StatusConflict, "SSH CA with this name already exists")
		return
	}

	// Generate CA ID with ca_ prefix
	caID := "ca_" + uuid.New().String()[:UUIDShortLength]

	// Store CA in database
	// Pass nil for private key since we only store the public key on the server
	if err := s.store.CreateSSHCA(caID, req.Name, []byte(req.PublicKey), nil, req.KeyType, nil); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to create SSH CA: "+err.Error())
		return
	}

	// Fetch the created CA to get the timestamp
	ca, err := s.store.GetSSHCA(req.Name)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to fetch created SSH CA: "+err.Error())
		return
	}

	response := createSSHCAResponse{
		ID:        ca.ID,
		Name:      ca.Name,
		KeyType:   ca.KeyType,
		CreatedAt: ca.CreatedAt.UTC().Format(time.RFC3339),
	}

	writeJSON(w, http.StatusCreated, response)
}

// isValidSSHPublicKeyFormat checks if a public key has a valid SSH format.
// Valid formats start with "ssh-" (ssh-ed25519, ssh-rsa) or "ecdsa-" (ecdsa-sha2-nistp256).
func isValidSSHPublicKeyFormat(pubKey string) bool {
	return strings.HasPrefix(pubKey, "ssh-") || strings.HasPrefix(pubKey, "ecdsa-")
}
