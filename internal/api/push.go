// Package api implements the HTTP API server for the dashboard.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/attestation"
	"github.com/gobeyondidentity/secure-infra/pkg/grpcclient"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
)

// ----- Push Types -----

// pushRequest is the request body for pushing credentials to a DPU.
type pushRequest struct {
	CAName     string `json:"ca_name"`
	TargetDPU  string `json:"target_dpu"`
	OperatorID string `json:"operator_id"`
	Force      bool   `json:"force"` // Bypass stale attestation
}

// pushResponse is the response for a push operation.
type pushResponse struct {
	Success           bool   `json:"success"`
	InstalledPath     string `json:"installed_path,omitempty"`
	SSHDReloaded      bool   `json:"sshd_reloaded"`
	AttestationStatus string `json:"attestation_status"`
	AttestationAge    string `json:"attestation_age,omitempty"`
	Message           string `json:"message,omitempty"`
}

// handlePush handles POST /api/v1/push
// Distributes a credential to a DPU after authorization and attestation checks.
func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	var req pushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if req.CAName == "" {
		writeError(w, r, http.StatusBadRequest, "ca_name is required")
		return
	}
	if req.TargetDPU == "" {
		writeError(w, r, http.StatusBadRequest, "target_dpu is required")
		return
	}
	if req.OperatorID == "" {
		writeError(w, r, http.StatusBadRequest, "operator_id is required")
		return
	}

	// Check operator suspension status
	operator, err := s.store.GetOperator(req.OperatorID)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "operator not found")
		return
	}
	if operator.Status == "suspended" {
		writeError(w, r, http.StatusForbidden, "operator suspended")
		return
	}

	// Resolve CA by name
	ca, err := s.store.GetSSHCA(req.CAName)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "CA not found")
		return
	}

	// Resolve DPU by name
	dpu, err := s.store.Get(req.TargetDPU)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	// Check authorization
	authorized, err := s.store.CheckFullAuthorization(req.OperatorID, ca.ID, dpu.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to check authorization: "+err.Error())
		return
	}
	if !authorized {
		writeError(w, r, http.StatusForbidden, "not authorized for this CA and device")
		return
	}

	// Check attestation with auto-refresh
	// Note: operator was already fetched during suspension check above
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	decision, _, err := s.gate.CanDistributeWithAutoRefresh(ctx, dpu, "api:push", operator.Email)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to check attestation: "+err.Error())
		return
	}

	// Build attestation status and age for response
	var attestationStatus string
	var attestationAge string
	if decision.Attestation != nil {
		attestationStatus = string(decision.Attestation.Status)
		attestationAge = decision.Attestation.Age().Round(time.Second).String()
	} else {
		attestationStatus = "unavailable"
	}

	// If blocked and not forced, return 412 Precondition Failed
	if !decision.Allowed {
		// Failed attestations cannot be forced
		if decision.IsAttestationFailed() {
			recordBlockedDistribution(s.store, dpu, ca, operator, decision, req.Force)
			writeJSON(w, http.StatusPreconditionFailed, pushResponse{
				Success:           false,
				AttestationStatus: attestationStatus,
				AttestationAge:    attestationAge,
				Message:           "attestation failed: device failed integrity verification",
			})
			return
		}

		// Stale/unavailable attestation without force
		if !req.Force {
			recordBlockedDistribution(s.store, dpu, ca, operator, decision, false)
			writeJSON(w, http.StatusPreconditionFailed, pushResponse{
				Success:           false,
				AttestationStatus: attestationStatus,
				AttestationAge:    attestationAge,
				Message:           "attestation blocked: " + decision.Reason,
			})
			return
		}

		// Force flag set: proceed with stale/unavailable attestation
		// (but not with failed attestation, which was already handled above)
	}

	// Connect to aegis gRPC
	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		recordFailedDistribution(s.store, dpu, ca, operator, decision, req.Force, "failed to connect: "+err.Error())
		writeError(w, r, http.StatusServiceUnavailable, "failed to connect to DPU: "+err.Error())
		return
	}
	defer client.Close()

	// Distribute credential
	resp, err := client.DistributeCredential(ctx, "ssh-ca", ca.Name, ca.PublicKey)
	if err != nil {
		recordFailedDistribution(s.store, dpu, ca, operator, decision, req.Force, "distribution failed: "+err.Error())
		writeError(w, r, http.StatusInternalServerError, "failed to distribute credential: "+err.Error())
		return
	}

	if !resp.Success {
		recordFailedDistribution(s.store, dpu, ca, operator, decision, req.Force, resp.Message)
		writeError(w, r, http.StatusInternalServerError, "distribution failed: "+resp.Message)
		return
	}

	// Record successful distribution
	recordSuccessDistribution(s.store, dpu, ca, operator, decision, req.Force, resp.InstalledPath)

	writeJSON(w, http.StatusOK, pushResponse{
		Success:           true,
		InstalledPath:     resp.InstalledPath,
		SSHDReloaded:      resp.SshdReloaded,
		AttestationStatus: attestationStatus,
		AttestationAge:    attestationAge,
		Message:           resp.Message,
	})
}

// recordBlockedDistribution records a distribution that was blocked by attestation.
func recordBlockedDistribution(s *store.Store, dpu *store.DPU, ca *store.SSHCA, operator *store.Operator, decision *attestation.GateDecision, forced bool) {
	var outcome store.DistributionOutcome
	if decision.IsAttestationFailed() {
		outcome = store.DistributionOutcomeBlockedFailed
	} else {
		outcome = store.DistributionOutcomeBlockedStale
	}

	var attestationStatus *string
	var attestationAge *int
	if decision.Attestation != nil {
		status := string(decision.Attestation.Status)
		attestationStatus = &status
		age := int(decision.Attestation.Age().Seconds())
		attestationAge = &age
	}

	tenantID := ""
	if dpu.TenantID != nil {
		tenantID = *dpu.TenantID
	}

	reason := decision.Reason
	d := &store.Distribution{
		DPUName:            dpu.Name,
		CredentialType:     "ssh-ca",
		CredentialName:     ca.Name,
		Outcome:            outcome,
		AttestationStatus:  attestationStatus,
		AttestationAgeSecs: attestationAge,
		OperatorID:         operator.ID,
		OperatorEmail:      operator.Email,
		TenantID:           tenantID,
		BlockedReason:      &reason,
	}
	s.RecordDistribution(d)
}

// recordFailedDistribution records a distribution that failed due to gRPC error.
func recordFailedDistribution(s *store.Store, dpu *store.DPU, ca *store.SSHCA, operator *store.Operator, decision *attestation.GateDecision, forced bool, errMsg string) {
	outcome := store.DistributionOutcomeSuccess // Will be overwritten below
	if forced {
		outcome = store.DistributionOutcomeForced
	}

	var attestationStatus *string
	var attestationAge *int
	if decision.Attestation != nil {
		status := string(decision.Attestation.Status)
		attestationStatus = &status
		age := int(decision.Attestation.Age().Seconds())
		attestationAge = &age
	}

	tenantID := ""
	if dpu.TenantID != nil {
		tenantID = *dpu.TenantID
	}

	var forcedBy *string
	if forced {
		forcedBy = &operator.Email
	}

	d := &store.Distribution{
		DPUName:            dpu.Name,
		CredentialType:     "ssh-ca",
		CredentialName:     ca.Name,
		Outcome:            outcome,
		AttestationStatus:  attestationStatus,
		AttestationAgeSecs: attestationAge,
		OperatorID:         operator.ID,
		OperatorEmail:      operator.Email,
		TenantID:           tenantID,
		ErrorMessage:       &errMsg,
		ForcedBy:           forcedBy,
	}
	s.RecordDistribution(d)
}

// recordSuccessDistribution records a successful distribution.
func recordSuccessDistribution(s *store.Store, dpu *store.DPU, ca *store.SSHCA, operator *store.Operator, decision *attestation.GateDecision, forced bool, installedPath string) {
	outcome := store.DistributionOutcomeSuccess
	if forced {
		outcome = store.DistributionOutcomeForced
	}

	var attestationStatus *string
	var attestationAge *int
	if decision.Attestation != nil {
		status := string(decision.Attestation.Status)
		attestationStatus = &status
		age := int(decision.Attestation.Age().Seconds())
		attestationAge = &age
	}

	tenantID := ""
	if dpu.TenantID != nil {
		tenantID = *dpu.TenantID
	}

	var forcedBy *string
	if forced {
		forcedBy = &operator.Email
	}

	d := &store.Distribution{
		DPUName:            dpu.Name,
		CredentialType:     "ssh-ca",
		CredentialName:     ca.Name,
		Outcome:            outcome,
		AttestationStatus:  attestationStatus,
		AttestationAgeSecs: attestationAge,
		InstalledPath:      &installedPath,
		OperatorID:         operator.ID,
		OperatorEmail:      operator.Email,
		TenantID:           tenantID,
		ForcedBy:           forcedBy,
	}
	s.RecordDistribution(d)
}
