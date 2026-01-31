// Package api implements the HTTP API server for the dashboard.
// This file contains the bootstrap enrollment endpoints for first-admin registration.
package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nmelo/secure-infra/pkg/enrollment"
	"github.com/nmelo/secure-infra/pkg/store"
)

// Constants for bootstrap enrollment.
const (
	BootstrapWindowDuration = 10 * time.Minute
	ChallengeTTL            = 5 * time.Minute
)

// BootstrapRequest represents the request body for POST /api/v1/admin/bootstrap.
type BootstrapRequest struct {
	PublicKey string `json:"public_key"` // Base64-encoded Ed25519 public key
}

// BootstrapResponse represents the response for POST /api/v1/admin/bootstrap.
type BootstrapResponse struct {
	Challenge    string `json:"challenge"`     // Base64-encoded challenge nonce
	EnrollmentID string `json:"enrollment_id"` // Enrollment session identifier
}

// EnrollCompleteRequest represents the request body for POST /enroll/complete.
type EnrollCompleteRequest struct {
	EnrollmentID    string `json:"enrollment_id"`
	PublicKey       string `json:"public_key"`       // Base64-encoded Ed25519 public key
	SignedChallenge string `json:"signed_challenge"` // Base64-encoded signature
}

// EnrollCompleteResponse represents the response for POST /enroll/complete.
type EnrollCompleteResponse struct {
	ID          string `json:"id"`          // e.g., "adm_abc123"
	Fingerprint string `json:"fingerprint"` // SHA256 hex of public key
}

// bootstrapMu protects concurrent bootstrap attempts.
var bootstrapMu sync.Mutex

// handleAdminBootstrap handles POST /api/v1/admin/bootstrap.
// This initiates the bootstrap enrollment flow for the first admin.
func (s *Server) handleAdminBootstrap(w http.ResponseWriter, r *http.Request) {
	// Lock to prevent concurrent bootstrap attempts
	bootstrapMu.Lock()
	defer bootstrapMu.Unlock()

	// Check if first admin already exists
	hasAdmin, err := s.store.HasFirstAdmin()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to check bootstrap state: "+err.Error())
		return
	}
	if hasAdmin {
		writeEnrollmentError(w, enrollment.ErrAlreadyEnrolled())
		return
	}

	// Check if bootstrap window is still open
	state, err := s.store.GetBootstrapState()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to get bootstrap state: "+err.Error())
		return
	}

	// If no bootstrap state exists, that's an error - server should have initialized it
	if state == nil {
		writeError(w, r, http.StatusInternalServerError, "Bootstrap window not initialized")
		return
	}

	// Check if window has expired
	if time.Since(state.WindowOpenedAt) > BootstrapWindowDuration {
		writeEnrollmentError(w, enrollment.ErrWindowClosed())
		return
	}

	// Parse request body
	var req BootstrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate public key
	if req.PublicKey == "" {
		writeError(w, r, http.StatusBadRequest, "public_key is required")
		return
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid base64 encoding for public_key")
		return
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		writeError(w, r, http.StatusBadRequest, "Invalid public key: must be 32 bytes for Ed25519")
		return
	}

	// Generate challenge
	challenge, err := enrollment.GenerateChallenge()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to generate challenge: "+err.Error())
		return
	}

	// Create enrollment session
	enrollmentID := "enroll_" + uuid.New().String()[:8]
	// Store challenge as hex-encoded raw bytes (not hash) for signature verification later
	challengeHex := hex.EncodeToString(challenge)

	session := &store.EnrollmentSession{
		ID:            enrollmentID,
		SessionType:   "bootstrap",
		ChallengeHash: challengeHex, // Note: stores raw challenge, not hash, for verification
		PublicKeyB64:  &req.PublicKey,
		IPAddress:     getClientIP(r),
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(ChallengeTTL),
	}

	if err := s.store.CreateEnrollmentSession(session); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to create enrollment session: "+err.Error())
		return
	}

	// Audit log
	s.store.InsertAuditEntry(&store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "bootstrap.attempt",
		Target:    enrollmentID,
		Decision:  "challenge_issued",
		Details: map[string]string{
			"ip":            getClientIP(r),
			"enrollment_id": enrollmentID,
		},
	})

	// Return challenge
	resp := BootstrapResponse{
		Challenge:    base64.StdEncoding.EncodeToString(challenge),
		EnrollmentID: enrollmentID,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleEnrollComplete handles POST /enroll/complete.
// This completes the challenge-response enrollment flow.
func (s *Server) handleEnrollComplete(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req EnrollCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Get enrollment session
	session, err := s.store.GetEnrollmentSession(req.EnrollmentID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to get enrollment session: "+err.Error())
		return
	}
	if session == nil {
		writeEnrollmentError(w, enrollment.ErrInvalidSession(req.EnrollmentID))
		return
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		// Delete expired session
		s.store.DeleteEnrollmentSession(req.EnrollmentID)
		writeEnrollmentError(w, enrollment.ErrChallengeExpired())
		return
	}

	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid base64 encoding for public_key")
		return
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		writeError(w, r, http.StatusBadRequest, "Invalid public key: must be 32 bytes for Ed25519")
		return
	}

	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(req.SignedChallenge)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid base64 encoding for signed_challenge")
		return
	}

	// Recover the original challenge from session for signature verification.
	// Note: ChallengeHash stores the hex-encoded raw challenge bytes (not a hash)
	// to enable Ed25519 signature verification.
	challengeBytes, err := hex.DecodeString(session.ChallengeHash)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Invalid stored challenge")
		return
	}

	// Verify Ed25519 signature
	pubKey := ed25519.PublicKey(pubKeyBytes)
	if !ed25519.Verify(pubKey, challengeBytes, signatureBytes) {
		writeEnrollmentError(w, enrollment.ErrInvalidSignature())
		return
	}

	// Compute key fingerprint
	fingerprintHash := sha256.Sum256(pubKeyBytes)
	fingerprint := hex.EncodeToString(fingerprintHash[:])

	// Handle based on session type
	var adminID string
	switch session.SessionType {
	case "bootstrap":
		// Create operator and admin key for bootstrap
		adminID = "adm_" + uuid.New().String()[:8]

		// Create operator (the admin is also an operator)
		if err := s.store.CreateOperator(adminID, "admin@localhost", "Bootstrap Admin"); err != nil {
			writeError(w, r, http.StatusInternalServerError, "Failed to create operator: "+err.Error())
			return
		}

		// Activate the operator
		if err := s.store.UpdateOperatorStatus(adminID, "active"); err != nil {
			writeError(w, r, http.StatusInternalServerError, "Failed to activate operator: "+err.Error())
			return
		}

		// Create admin key
		adminKey := &store.AdminKey{
			ID:             adminID, // Use same ID for simplicity
			OperatorID:     adminID,
			Name:           "Bootstrap Key",
			PublicKey:      pubKeyBytes,
			Kid:            adminID, // DPoP key identifier
			KeyFingerprint: fingerprint,
			Status:         "active",
		}
		if err := s.store.CreateAdminKey(adminKey); err != nil {
			writeError(w, r, http.StatusInternalServerError, "Failed to create admin key: "+err.Error())
			return
		}

		// Mark bootstrap complete
		if err := s.store.CompleteBootstrap(adminID); err != nil {
			writeError(w, r, http.StatusInternalServerError, "Failed to complete bootstrap: "+err.Error())
			return
		}

	default:
		// Future session types (admin_invite, dpu) - stub for now
		writeError(w, r, http.StatusBadRequest, "Unsupported session type: "+session.SessionType)
		return
	}

	// Delete enrollment session
	if err := s.store.DeleteEnrollmentSession(req.EnrollmentID); err != nil {
		// Log but don't fail - enrollment succeeded
	}

	// Audit log
	s.store.InsertAuditEntry(&store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "bootstrap.complete",
		Target:    adminID,
		Decision:  "enrolled",
		Details: map[string]string{
			"fingerprint": fingerprint,
			"ip":          getClientIP(r),
		},
	})

	// Return response
	resp := EnrollCompleteResponse{
		ID:          adminID,
		Fingerprint: fingerprint,
	}
	writeJSON(w, http.StatusOK, resp)
}

// writeEnrollmentError writes an enrollment error response in the standard format.
func writeEnrollmentError(w http.ResponseWriter, err *enrollment.EnrollmentError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus())
	json.NewEncoder(w).Encode(map[string]string{
		"error":   err.Code,
		"message": err.Message,
	})
}

// writeEnrollmentErrorFromError writes an enrollment error response, checking if err is an EnrollmentError.
func writeEnrollmentErrorFromError(w http.ResponseWriter, r *http.Request, defaultStatus int, err error) {
	var enrollErr *enrollment.EnrollmentError
	if errors.As(err, &enrollErr) {
		writeEnrollmentError(w, enrollErr)
		return
	}
	writeError(w, r, defaultStatus, err.Error())
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}
