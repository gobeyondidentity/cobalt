// Package api implements the HTTP API server for the dashboard.
// This file contains the operator enrollment endpoints.
package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/nmelo/secure-infra/pkg/enrollment"
	"github.com/nmelo/secure-infra/pkg/store"
)

// emailRegex is a simple email validation pattern.
// It's intentionally permissive - just checks for basic structure.
var emailRegex = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// isValidEmail checks if an email address has valid basic structure.
func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// OperatorChallengeTTL is the duration an operator enrollment challenge is valid.
const OperatorChallengeTTL = 5 * time.Minute

// EnrollInitRequest represents the request body for POST /enroll/init.
type EnrollInitRequest struct {
	Code string `json:"code"` // Plaintext invite code
}

// EnrollInitResponse represents the response for POST /enroll/init.
type EnrollInitResponse struct {
	Challenge    string `json:"challenge"`     // Base64-encoded challenge nonce
	EnrollmentID string `json:"enrollment_id"` // Enrollment session identifier
}

// handleEnrollInit handles POST /enroll/init.
// This initiates the operator enrollment flow with an invite code.
func (s *Server) handleEnrollInit(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req EnrollInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required field
	if req.Code == "" {
		writeError(w, r, http.StatusBadRequest, "code is required")
		return
	}

	// Create invite service and validate code
	inviteSvc := store.NewInviteService(s.store)
	inviteCode, err := inviteSvc.ValidateInviteCode(req.Code)
	if err != nil {
		writeEnrollmentErrorFromError(w, r, http.StatusUnauthorized, err)
		return
	}

	// Generate challenge
	challenge, err := enrollment.GenerateChallenge()
	if err != nil {
		writeInternalError(w, r, err, "Failed to generate challenge")
		return
	}

	// Create enrollment session
	enrollmentID := "enroll_" + uuid.New().String()[:UUIDShortLength]
	// Store challenge as hex-encoded raw bytes for signature verification later
	challengeHex := hex.EncodeToString(challenge)

	session := &store.EnrollmentSession{
		ID:               enrollmentID,
		SessionType:      "operator",
		ChallengeBytesHex: challengeHex,
		InviteCodeID:     &inviteCode.ID,
		IPAddress:        getClientIP(r),
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(OperatorChallengeTTL),
	}

	if err := s.store.CreateEnrollmentSession(session); err != nil {
		writeInternalError(w, r, err, "Failed to create enrollment session")
		return
	}

	// Consume invite code atomically (pass enrollment_id temporarily, will be updated on complete)
	_, err = inviteSvc.ConsumeInviteCode(req.Code, enrollmentID)
	if err != nil {
		// Clean up session if consumption fails
		s.store.DeleteEnrollmentSession(enrollmentID)
		writeEnrollmentErrorFromError(w, r, http.StatusUnauthorized, err)
		return
	}

	// Audit log
	s.store.InsertAuditEntry(&store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "enroll.operator.init",
		Target:    enrollmentID,
		Decision:  "challenge_issued",
		Details: map[string]string{
			"ip":            getClientIP(r),
			"enrollment_id": enrollmentID,
			"invite_code":   inviteCode.ID,
			"operator":      inviteCode.OperatorEmail,
		},
	})

	// Return challenge
	resp := EnrollInitResponse{
		Challenge:    base64.StdEncoding.EncodeToString(challenge),
		EnrollmentID: enrollmentID,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleOperatorEnrollComplete handles the "operator" session type in handleEnrollComplete.
// This is called from bootstrap.go's handleEnrollComplete switch statement.
func (s *Server) handleOperatorEnrollComplete(w http.ResponseWriter, r *http.Request, session *store.EnrollmentSession, pubKeyBytes []byte, fingerprint string) {
	// Get invite code by ID from session's InviteCodeID
	if session.InviteCodeID == nil {
		writeError(w, r, http.StatusInternalServerError, "Enrollment session missing invite code reference")
		return
	}

	inviteCode, err := s.store.GetInviteCodeByID(*session.InviteCodeID)
	if err != nil {
		writeInternalError(w, r, err, "Failed to get invite code")
		return
	}

	// Validate operator email from invite code
	if !isValidEmail(inviteCode.OperatorEmail) {
		writeError(w, r, http.StatusBadRequest, "Invalid operator email in invite code")
		return
	}

	// Check fingerprint uniqueness in keymakers table
	// GetKeyMakerByFingerprint returns error "keymaker not found" if not found
	existingKM, err := s.store.GetKeyMakerByFingerprint(fingerprint)
	if err == nil && existingKM != nil {
		writeEnrollmentError(w, enrollment.ErrKeyExists(fingerprint))
		return
	}
	// Also check admin_keys table for duplicate fingerprints
	existingAdminKey, err := s.store.GetAdminKeyByFingerprint(fingerprint)
	if err == nil && existingAdminKey != nil {
		writeEnrollmentError(w, enrollment.ErrKeyExists(fingerprint))
		return
	}

	// Generate keymaker ID
	keymakerID := "km_" + uuid.New().String()[:UUIDShortLength]

	// Get or create operator from invite code metadata
	operator, err := s.store.GetOperatorByEmail(inviteCode.OperatorEmail)
	if err != nil {
		// Operator doesn't exist, create new one
		operatorID := "op_" + uuid.New().String()[:UUIDShortLength]
		if err := s.store.CreateOperator(operatorID, inviteCode.OperatorEmail, ""); err != nil {
			writeInternalError(w, r, err, "Failed to create operator")
			return
		}
		operator, _ = s.store.GetOperator(operatorID)
	}

	// Activate the operator if pending
	if operator.Status == "pending" {
		if err := s.store.UpdateOperatorStatus(operator.ID, "active"); err != nil {
			writeInternalError(w, r, err, "Failed to activate operator")
			return
		}
	}

	// Add operator to tenant with role from invite
	// Ignore errors - operator might already be a member of this tenant
	_ = s.store.AddOperatorToTenant(operator.ID, inviteCode.TenantID, inviteCode.Role)

	// Create KeyMaker record
	km := &store.KeyMaker{
		ID:                keymakerID,
		OperatorID:        operator.ID,
		Name:              "Enrolled Device",
		Platform:          "unknown",      // Client should provide in future
		SecureElement:     "unknown",      // Client should provide in future
		DeviceFingerprint: fingerprint,    // Use key fingerprint as device fingerprint for now
		PublicKey:         base64.StdEncoding.EncodeToString(pubKeyBytes),
		Status:            "active",
		Kid:               keymakerID,
		KeyFingerprint:    fingerprint,
	}
	if err := s.store.CreateKeyMaker(km); err != nil {
		writeInternalError(w, r, err, "Failed to create keymaker")
		return
	}

	// Update invite code's UsedByKeyMaker to keymaker ID
	if err := s.store.MarkInviteCodeUsed(inviteCode.ID, keymakerID); err != nil {
		// Log but don't fail - enrollment succeeded
	}

	// Delete enrollment session
	if err := s.store.DeleteEnrollmentSession(session.ID); err != nil {
		// Log but don't fail - enrollment succeeded
	}

	// Audit log entry
	s.store.InsertAuditEntry(&store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "enroll.operator.complete",
		Target:    keymakerID,
		Decision:  "enrolled",
		Details: map[string]string{
			"fingerprint":    fingerprint,
			"ip":             getClientIP(r),
			"operator_id":    operator.ID,
			"operator_email": inviteCode.OperatorEmail,
			"tenant_id":      inviteCode.TenantID,
			"role":           inviteCode.Role,
		},
	})

	// Return response
	resp := EnrollCompleteResponse{
		ID:          keymakerID,
		Fingerprint: fingerprint,
	}
	writeJSON(w, http.StatusOK, resp)
}
