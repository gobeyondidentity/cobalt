// Package api implements the HTTP API server for the dashboard.
package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/store"
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

// DistributionHistoryEntry is the response format for distribution history (Phase 3 audit trail).
type DistributionHistoryEntry struct {
	ID                  string  `json:"id"`
	Timestamp           string  `json:"timestamp"`
	Target              string  `json:"target"`
	CredentialType      string  `json:"credential_type"`
	CredentialName      string  `json:"credential_name"`
	OperatorID          string  `json:"operator_id"`
	OperatorEmail       string  `json:"operator_email"`
	TenantID            string  `json:"tenant_id"`
	Outcome             string  `json:"outcome"`
	AttestationStatus   string  `json:"attestation_status"`
	AttestationAge      string  `json:"attestation_age,omitempty"`
	AttestationSnapshot *string `json:"attestation_snapshot,omitempty"`
	BlockedReason       *string `json:"blocked_reason,omitempty"`
	ForcedBy            *string `json:"forced_by,omitempty"`
}

// ----- SSH CA Handlers -----

// handleListSSHCAs returns all SSH CAs without their public keys.
func (s *Server) handleListSSHCAs(w http.ResponseWriter, r *http.Request) {
	cas, err := s.store.ListSSHCAs()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to list SSH CAs: "+err.Error())
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
		writeError(w, r, http.StatusNotFound, "SSH CA not found")
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
//   - operator: Filter by operator ID or email
//   - tenant: Filter by tenant ID
//   - from: Filter from timestamp (RFC3339 or YYYY-MM-DD)
//   - to: Filter to timestamp (RFC3339 or YYYY-MM-DD)
//   - result: Filter by outcome (success, blocked, forced)
//   - limit: Max results (default 100)
//   - verbose: Include attestation_snapshot if true
func (s *Server) handleDistributionHistory(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	target := r.URL.Query().Get("target")
	operatorFilter := r.URL.Query().Get("operator")
	tenantFilter := r.URL.Query().Get("tenant")
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	resultFilter := r.URL.Query().Get("result")
	limitStr := r.URL.Query().Get("limit")
	verbose := r.URL.Query().Get("verbose") == "true"

	// Default limit
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// Parse time filters with flexible format support
	var fromTime, toTime *time.Time
	if fromStr != "" {
		t, err := parseFlexibleTime(fromStr, false)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "Invalid 'from' timestamp format. Use RFC3339 or YYYY-MM-DD.")
			return
		}
		fromTime = &t
	}
	if toStr != "" {
		t, err := parseFlexibleTime(toStr, true)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "Invalid 'to' timestamp format. Use RFC3339 or YYYY-MM-DD.")
			return
		}
		toTime = &t
	}

	// Build query options
	opts := store.DistributionQueryOpts{
		TargetDPU:     target,
		OperatorEmail: operatorFilter, // Filter by email (supports email addresses)
		TenantID:      tenantFilter,
		From:          fromTime,
		To:            toTime,
		Limit:         limit,
	}

	// Map simplified outcome names to actual values
	if resultFilter != "" {
		if resultFilter == "blocked" {
			// Use prefix matching to get both blocked-stale and blocked-failed
			opts.OutcomePrefix = "blocked"
		} else {
			mapped := mapOutcomeFilter(resultFilter)
			if mapped == nil {
				writeError(w, r, http.StatusBadRequest, "Invalid 'result' filter. Valid values: success, blocked, forced, blocked-stale, blocked-failed")
				return
			}
			opts.Outcome = mapped
		}
	}

	// Query distributions using the store method
	distributions, err := s.store.ListDistributionsWithFilters(opts)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to query distribution history: "+err.Error())
		return
	}

	// Convert to response format
	result := make([]DistributionHistoryEntry, 0, len(distributions))
	for _, d := range distributions {
		entry := distributionToHistoryEntry(d, verbose)
		result = append(result, entry)
	}

	writeJSON(w, http.StatusOK, result)
}

// parseFlexibleTime parses time in RFC3339 or YYYY-MM-DD format.
// If isEndOfDay is true and format is YYYY-MM-DD, returns 23:59:59.999999999 of that day.
// YYYY-MM-DD is parsed in local time for intuitive querying.
func parseFlexibleTime(s string, isEndOfDay bool) (time.Time, error) {
	// Try RFC3339 first (includes timezone info)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	// Try YYYY-MM-DD format (parse in local time for intuitive date queries)
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		if isEndOfDay {
			// Set to end of day (23:59:59.999999999)
			return t.Add(24*time.Hour - time.Nanosecond), nil
		}
		return t, nil
	}

	return time.Time{}, fmt.Errorf("unsupported time format: %s", s)
}

// mapOutcomeFilter maps user-friendly outcome names to store.DistributionOutcome.
// Supports both simplified names (success, blocked, forced) and full names.
func mapOutcomeFilter(filter string) *store.DistributionOutcome {
	filter = strings.ToLower(filter)

	switch filter {
	case "success":
		o := store.DistributionOutcomeSuccess
		return &o
	case "blocked", "blocked-stale":
		o := store.DistributionOutcomeBlockedStale
		return &o
	case "blocked-failed":
		o := store.DistributionOutcomeBlockedFailed
		return &o
	case "forced":
		o := store.DistributionOutcomeForced
		return &o
	default:
		return nil
	}
}

// formatHumanDuration converts seconds to a human-readable duration string.
// Examples: "5m", "2h", "3d", "1w"
func formatHumanDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	if seconds < 86400 {
		return fmt.Sprintf("%dh", seconds/3600)
	}
	if seconds < 604800 {
		return fmt.Sprintf("%dd", seconds/86400)
	}
	return fmt.Sprintf("%dw", seconds/604800)
}

// distributionToHistoryEntry converts a store.Distribution to DistributionHistoryEntry.
func distributionToHistoryEntry(d *store.Distribution, includeSnapshot bool) DistributionHistoryEntry {
	entry := DistributionHistoryEntry{
		ID:             fmt.Sprintf("%d", d.ID),
		Timestamp:      d.CreatedAt.UTC().Format(time.RFC3339),
		Target:         d.DPUName,
		CredentialType: d.CredentialType,
		CredentialName: d.CredentialName,
		OperatorID:     d.OperatorID,
		OperatorEmail:  d.OperatorEmail,
		TenantID:       d.TenantID,
		Outcome:        string(d.Outcome),
		BlockedReason:  d.BlockedReason,
		ForcedBy:       d.ForcedBy,
	}

	// Attestation status
	if d.AttestationStatus != nil {
		entry.AttestationStatus = *d.AttestationStatus
	}

	// Human-readable attestation age
	if d.AttestationAgeSecs != nil {
		entry.AttestationAge = formatHumanDuration(*d.AttestationAgeSecs)
	}

	// Include snapshot only in verbose mode
	if includeSnapshot && d.AttestationSnapshot != nil {
		entry.AttestationSnapshot = d.AttestationSnapshot
	}

	return entry
}
