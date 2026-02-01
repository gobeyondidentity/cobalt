// Package api implements the HTTP API server for the dashboard.
// This file contains the DPU enrollment endpoints.
package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nmelo/secure-infra/pkg/enrollment"
	"github.com/nmelo/secure-infra/pkg/store"
)

// DPUChallengeTTL is the duration a DPU enrollment challenge is valid.
const DPUChallengeTTL = 5 * time.Minute

// DPUEnrollInitRequest represents the request body for POST /enroll/dpu/init.
type DPUEnrollInitRequest struct {
	Serial string `json:"serial"` // DPU serial number
}

// DPUEnrollInitResponse represents the response for POST /enroll/dpu/init.
type DPUEnrollInitResponse struct {
	Challenge    string `json:"challenge"`     // Base64-encoded challenge nonce
	EnrollmentID string `json:"enrollment_id"` // Enrollment session identifier
}

// handleDPUEnrollInit handles POST /enroll/dpu/init.
// This initiates the DPU enrollment flow with a serial number.
func (s *Server) handleDPUEnrollInit(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req DPUEnrollInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate serial is not empty
	if req.Serial == "" {
		writeError(w, r, http.StatusBadRequest, "serial is required")
		return
	}

	// Look up DPU by serial
	dpu, err := s.store.GetDPUBySerial(req.Serial)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to look up DPU: "+err.Error())
		return
	}
	if dpu == nil {
		writeError(w, r, http.StatusNotFound, "DPU not registered")
		return
	}

	// Validate DPU status is 'pending'
	if dpu.Status != "pending" {
		writeError(w, r, http.StatusConflict, "DPU already enrolled or decommissioned")
		return
	}

	// Validate enrollment_expires_at > now
	if dpu.EnrollmentExpiresAt == nil || time.Now().After(*dpu.EnrollmentExpiresAt) {
		writeEnrollmentError(w, enrollment.ErrExpiredCode())
		return
	}

	// Generate challenge
	challenge, err := enrollment.GenerateChallenge()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to generate challenge: "+err.Error())
		return
	}

	// Create enrollment session with SessionType="dpu", DPUID=dpu.ID
	enrollmentID := "enroll_" + uuid.New().String()[:UUIDShortLength]
	// Store challenge as hex-encoded raw bytes for signature verification later
	challengeHex := hex.EncodeToString(challenge)

	session := &store.EnrollmentSession{
		ID:               enrollmentID,
		SessionType:      "dpu",
		ChallengeBytesHex: challengeHex,
		DPUID:            &dpu.ID,
		IPAddress:        getClientIP(r),
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(DPUChallengeTTL),
	}

	if err := s.store.CreateEnrollmentSession(session); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to create enrollment session: "+err.Error())
		return
	}

	// Audit log
	s.store.InsertAuditEntry(&store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "enroll.dpu.init",
		Target:    enrollmentID,
		Decision:  "challenge_issued",
		Details: map[string]string{
			"ip":            getClientIP(r),
			"enrollment_id": enrollmentID,
			"dpu_id":        dpu.ID,
			"dpu_serial":    req.Serial,
		},
	})

	// Return challenge (base64) and enrollment_id
	resp := DPUEnrollInitResponse{
		Challenge:    base64.StdEncoding.EncodeToString(challenge),
		EnrollmentID: enrollmentID,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDPUEnrollComplete handles DPU enrollment completion.
// This is called from bootstrap.go's handleEnrollComplete switch statement.
func (s *Server) handleDPUEnrollComplete(w http.ResponseWriter, r *http.Request, session *store.EnrollmentSession, pubKeyBytes []byte, fingerprint string) {
	// Validate session has DPUID
	if session.DPUID == nil {
		writeError(w, r, http.StatusInternalServerError, "Enrollment session missing DPU reference")
		return
	}

	// Get DPU by ID from session.DPUID
	dpu, err := s.store.Get(*session.DPUID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to get DPU: "+err.Error())
		return
	}

	// Check fingerprint uniqueness across all enrolled DPUs
	existingDPU, err := s.store.GetDPUByFingerprint(fingerprint)
	if err == nil && existingDPU != nil {
		writeEnrollmentError(w, enrollment.ErrKeyExists(fingerprint))
		return
	}

	// Also check keymakers and admin_keys tables for duplicate fingerprints
	existingKM, err := s.store.GetKeyMakerByFingerprint(fingerprint)
	if err == nil && existingKM != nil {
		writeEnrollmentError(w, enrollment.ErrKeyExists(fingerprint))
		return
	}
	existingAdminKey, err := s.store.GetAdminKeyByFingerprint(fingerprint)
	if err == nil && existingAdminKey != nil {
		writeEnrollmentError(w, enrollment.ErrKeyExists(fingerprint))
		return
	}

	// Generate DPU identity ID: "dpu_" + uuid[:8]
	dpuIdentityID := "dpu_" + uuid.New().String()[:UUIDShortLength]

	// Update DPU enrollment: sets public_key, fingerprint, kid, status='active', clears enrollment_expires_at
	if err := s.store.UpdateDPUEnrollment(dpu.ID, pubKeyBytes, fingerprint, dpuIdentityID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to update DPU enrollment: "+err.Error())
		return
	}

	// Delete enrollment session
	if err := s.store.DeleteEnrollmentSession(session.ID); err != nil {
		// Log but don't fail - enrollment succeeded
	}

	// Audit log entry
	s.store.InsertAuditEntry(&store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "enroll.dpu.complete",
		Target:    dpuIdentityID,
		Decision:  "enrolled",
		Details: map[string]string{
			"fingerprint":   fingerprint,
			"ip":            getClientIP(r),
			"dpu_id":        dpu.ID,
			"dpu_name":      dpu.Name,
			"serial_number": dpu.SerialNumber,
		},
	})

	// Return response
	resp := EnrollCompleteResponse{
		ID:          dpuIdentityID,
		Fingerprint: fingerprint,
	}
	writeJSON(w, http.StatusOK, resp)
}
