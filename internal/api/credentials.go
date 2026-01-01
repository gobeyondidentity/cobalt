// Package api implements the HTTP API server for the dashboard.
package api

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"
)

// ----- SSH CA Types -----

type sshCAResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	KeyType       string `json:"keyType"`
	PublicKey     string `json:"publicKey,omitempty"` // Only in detail view
	CreatedAt     string `json:"createdAt"`
	Distributions int    `json:"distributions"` // Count of distributions
}

// ----- Distribution Types -----

type distributionResponse struct {
	ID                int64   `json:"id"`
	DPUName           string  `json:"dpuName"`
	CredentialType    string  `json:"credentialType"`
	CredentialName    string  `json:"credentialName"`
	Outcome           string  `json:"outcome"` // success, blocked-stale, blocked-failed, forced
	AttestationStatus *string `json:"attestationStatus,omitempty"`
	AttestationAge    *int    `json:"attestationAgeSeconds,omitempty"`
	InstalledPath     *string `json:"installedPath,omitempty"`
	ErrorMessage      *string `json:"errorMessage,omitempty"`
	CreatedAt         string  `json:"createdAt"`
}

// ----- SSH CA Handlers -----

// handleListSSHCAs returns all SSH CAs without their public keys.
func (s *Server) handleListSSHCAs(w http.ResponseWriter, r *http.Request) {
	cas, err := s.store.ListSSHCAs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list SSH CAs: "+err.Error())
		return
	}

	result := make([]sshCAResponse, 0, len(cas))
	for _, ca := range cas {
		// Count distributions for this CA
		count := s.countDistributionsForCredential(ca.Name)

		result = append(result, sshCAResponse{
			ID:            ca.ID,
			Name:          ca.Name,
			KeyType:       ca.KeyType,
			CreatedAt:     ca.CreatedAt.UTC().Format(time.RFC3339),
			Distributions: count,
		})
	}

	writeJSON(w, http.StatusOK, result)
}

// handleGetSSHCA returns a specific SSH CA with its public key.
func (s *Server) handleGetSSHCA(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	// Use GetSSHCA to validate existence, but we only need public key info
	ca, err := s.store.GetSSHCA(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "SSH CA not found")
		return
	}

	// Count distributions for this CA
	count := s.countDistributionsForCredential(ca.Name)

	// Encode public key as base64
	publicKeyB64 := base64.StdEncoding.EncodeToString(ca.PublicKey)

	result := sshCAResponse{
		ID:            ca.ID,
		Name:          ca.Name,
		KeyType:       ca.KeyType,
		PublicKey:     publicKeyB64,
		CreatedAt:     ca.CreatedAt.UTC().Format(time.RFC3339),
		Distributions: count,
	}

	writeJSON(w, http.StatusOK, result)
}

// countDistributionsForCredential counts distribution records for a credential name.
func (s *Server) countDistributionsForCredential(credentialName string) int {
	history, err := s.store.GetDistributionHistoryByCredential(credentialName)
	if err != nil {
		return 0
	}
	return len(history)
}

// ----- Distribution History Handlers -----

// handleDistributionHistory returns distribution history with optional filters.
// Query parameters:
//   - target: Filter by DPU name
//   - from: Filter from timestamp (RFC3339)
//   - to: Filter to timestamp (RFC3339)
//   - result: Filter by outcome (success, blocked-stale, blocked-failed, forced)
//   - limit: Max results (default 100)
func (s *Server) handleDistributionHistory(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	target := r.URL.Query().Get("target")
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	resultFilter := r.URL.Query().Get("result")
	limitStr := r.URL.Query().Get("limit")

	// Default limit
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// Parse time filters
	var fromTime, toTime *time.Time
	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			fromTime = &t
		} else {
			writeError(w, http.StatusBadRequest, "Invalid 'from' timestamp format. Use RFC3339.")
			return
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			toTime = &t
		} else {
			writeError(w, http.StatusBadRequest, "Invalid 'to' timestamp format. Use RFC3339.")
			return
		}
	}

	// Validate result filter if provided
	validOutcomes := map[string]bool{
		"success":        true,
		"blocked-stale":  true,
		"blocked-failed": true,
		"forced":         true,
	}
	if resultFilter != "" && !validOutcomes[resultFilter] {
		writeError(w, http.StatusBadRequest, "Invalid 'result' filter. Valid values: success, blocked-stale, blocked-failed, forced")
		return
	}

	// Query distributions with filters
	distributions, err := s.queryDistributionHistory(target, fromTime, toTime, resultFilter, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to query distribution history: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, distributions)
}

// queryDistributionHistory queries the distribution_history table with filters.
func (s *Server) queryDistributionHistory(target string, from, to *time.Time, outcome string, limit int) ([]distributionResponse, error) {
	// Build query dynamically based on filters
	query := `
		SELECT id, dpu_name, credential_type, credential_name, outcome,
		       attestation_status, attestation_age_seconds, installed_path, error_message, created_at
		FROM distribution_history
		WHERE 1=1
	`
	args := []interface{}{}

	if target != "" {
		query += " AND dpu_name = ?"
		args = append(args, target)
	}

	if from != nil {
		query += " AND created_at >= ?"
		args = append(args, from.Unix())
	}

	if to != nil {
		query += " AND created_at <= ?"
		args = append(args, to.Unix())
	}

	if outcome != "" {
		query += " AND outcome = ?"
		args = append(args, outcome)
	}

	query += " ORDER BY created_at DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.store.QueryRaw(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]distributionResponse, 0)
	for rows.Next() {
		var d distributionResponse
		var outcomeStr string
		var createdAt int64
		var attestationStatus sql.NullString
		var attestationAgeSecs sql.NullInt64
		var installedPath sql.NullString
		var errorMessage sql.NullString

		err := rows.Scan(
			&d.ID,
			&d.DPUName,
			&d.CredentialType,
			&d.CredentialName,
			&outcomeStr,
			&attestationStatus,
			&attestationAgeSecs,
			&installedPath,
			&errorMessage,
			&createdAt,
		)
		if err != nil {
			return nil, err
		}

		d.Outcome = outcomeStr
		d.CreatedAt = time.Unix(createdAt, 0).UTC().Format(time.RFC3339)

		if attestationStatus.Valid {
			d.AttestationStatus = &attestationStatus.String
		}
		if attestationAgeSecs.Valid {
			age := int(attestationAgeSecs.Int64)
			d.AttestationAge = &age
		}
		if installedPath.Valid {
			d.InstalledPath = &installedPath.String
		}
		if errorMessage.Valid {
			d.ErrorMessage = &errorMessage.String
		}

		result = append(result, d)
	}

	return result, rows.Err()
}
