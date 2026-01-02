package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nmelo/secure-infra/pkg/attestation"
	"github.com/nmelo/secure-infra/pkg/audit"
	"github.com/nmelo/secure-infra/pkg/clierror"
	"github.com/nmelo/secure-infra/pkg/grpcclient"
	"github.com/nmelo/secure-infra/pkg/store"
	"github.com/spf13/cobra"
)

// operatorContext holds the operator identity for audit records.
type operatorContext struct {
	OperatorID    string
	OperatorEmail string
}

func init() {
	rootCmd.AddCommand(pushCmd)
	pushCmd.AddCommand(pushSSHCACmd)

	// Flags for push ssh-ca
	pushSSHCACmd.Flags().Bool("force", false, "Force push even with stale attestation (audited)")
}

var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push credentials to DPUs",
	Long: `Push credentials to DPUs with attestation gate checks.

Push requires the target DPU to have recent verified attestation.
Use --force to bypass stale attestation (this action is audited).`,
}

var pushSSHCACmd = &cobra.Command{
	Use:   "ssh-ca <ca-name> <target>",
	Short: "Push an SSH CA to a DPU",
	Long: `Push an SSH CA's public key to a target DPU.

This command verifies the attestation gate before allowing the push.
The CA public key is sent to the DPU agent, which installs it and reloads sshd.

Attestation Requirements:
- DPU must have a verified attestation record
- Attestation must be fresh (less than 1 hour old by default)
- Use --force to bypass stale attestation (logged to audit trail)

Examples:
  km push ssh-ca ops-ca bf3-lab
  km push ssh-ca ops-ca bf3-lab --force`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		caName := args[0]
		targetDPU := args[1]
		force, _ := cmd.Flags().GetBool("force")

		// Load operator context from config
		config, err := loadConfig()
		if err != nil {
			return clierror.TokenExpired()
		}

		operatorCtx := &operatorContext{
			OperatorID:    config.OperatorID,
			OperatorEmail: config.OperatorEmail,
		}

		// Check authorization before distributing (CA + device)
		if err := checkAuthorization(caName, targetDPU); err != nil {
			if authErr, ok := err.(*AuthorizationError); ok {
				if authErr.Type == "ca" {
					return clierror.NotAuthorized(fmt.Sprintf("CA '%s'", authErr.Resource))
				}
				return clierror.NotAuthorized(fmt.Sprintf("device '%s'", authErr.Resource))
			}
			// Connection error to control plane
			return clierror.ConnectionFailed("control plane")
		}

		// Verify SSH CA exists and get it
		ca, err := dpuStore.GetSSHCA(caName)
		if err != nil {
			return clierror.CANotFound(caName)
		}

		// Verify target DPU exists
		dpu, err := dpuStore.Get(targetDPU)
		if err != nil {
			return clierror.DeviceNotFound(targetDPU)
		}

		// Create gate and audit logger
		gate := attestation.NewGate(dpuStore)
		auditLogger := audit.NewLogger(dpuStore)

		fmt.Printf("Pushing CA '%s' to %s...\n", caName, dpu.Name)

		// Check attestation gate with auto-refresh
		decision, refreshed, err := gate.CanDistributeWithAutoRefresh(
			cmd.Context(),
			dpu,
			"auto:distribution",
			operatorCtx.OperatorEmail,
		)
		if err != nil {
			return clierror.AttestationUnavailable()
		}

		// Handle gate decision
		if decision.Allowed {
			// Log audit entry for successful gate check
			logAuditEntry(auditLogger, operatorCtx, dpu.Name, caName, "allowed", "false", decision)

			age := "unknown"
			if decision.Attestation != nil {
				age = formatAge(decision.Attestation.Age())
			}

			if refreshed {
				fmt.Printf("  Attestation stale. Refreshed successfully.\n")
			}
			fmt.Printf("  Attestation: verified (%s ago)\n\n", age)

			// Proceed with push
			return executeDistribution(cmd.Context(), dpu, ca, decision, false, "", operatorCtx)
		}

		// Gate blocked
		// Check if this is a failed attestation (hard block, no force allowed)
		if decision.IsAttestationFailed() {
			logAuditEntry(auditLogger, operatorCtx, dpu.Name, caName, "blocked", "false", decision)
			recordBlockedDistribution(dpu.Name, caName, decision, operatorCtx)

			if refreshed {
				fmt.Printf("  Attestation stale. Refresh failed.\n")
			}
			fmt.Printf("x Attestation failed: device failed integrity verification\n\n")
			fmt.Printf("Push blocked: device failed attestation.\n")
			fmt.Printf("Contact your infrastructure team. This event has been logged.\n")
			return clierror.AttestationFailed("device failed integrity verification")
		}

		// Stale or unavailable attestation (force may be allowed)
		if force {
			// Log audit entry for forced bypass
			logAuditEntry(auditLogger, operatorCtx, dpu.Name, caName, "forced", "true", decision)

			age := "unknown"
			if decision.Attestation != nil {
				age = formatAge(decision.Attestation.Age())
			}

			if refreshed {
				fmt.Printf("  Attestation refresh attempted but unavailable.\n")
			}
			fmt.Printf("! Attestation stale (%s ago)\n", age)
			fmt.Printf("Warning: Forcing push despite %s (logged)\n\n", decision.Reason)

			// Proceed with forced distribution
			return executeDistribution(cmd.Context(), dpu, ca, decision, true, decision.Reason, operatorCtx)
		}

		// Blocked, no force
		logAuditEntry(auditLogger, operatorCtx, dpu.Name, caName, "blocked", "false", decision)
		recordBlockedDistribution(dpu.Name, caName, decision, operatorCtx)

		if refreshed {
			fmt.Printf("  Attestation refresh attempted but unavailable.\n")
		}

		if decision.Attestation != nil {
			age := formatAge(decision.Attestation.Age())
			fmt.Printf("x Attestation stale (%s ago)\n\n", age)
		} else {
			fmt.Printf("x Attestation unavailable\n\n")
		}

		fmt.Printf("Push blocked: %s\n", decision.Reason)
		fmt.Printf("Hint: Use --force to bypass (audited)\n")

		// Return appropriate error based on reason
		if strings.HasPrefix(decision.Reason, "stale:") || strings.Contains(decision.Reason, "stale") {
			age := "unknown"
			if decision.Attestation != nil {
				age = decision.Attestation.Age().String()
			}
			return clierror.AttestationStale(age)
		}
		return clierror.AttestationUnavailable()
	},
}

// executeDistribution performs the actual gRPC call to push the credential.
func executeDistribution(ctx context.Context, dpu *store.DPU, ca *store.SSHCA, decision *attestation.GateDecision, forced bool, forceReason string, opCtx *operatorContext) error {
	// Connect to DPU agent
	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		recordFailedDistribution(dpu.Name, ca.Name, decision, fmt.Sprintf("connection failed: %v", err), opCtx)
		return clierror.ConnectionFailed(dpu.Address())
	}
	defer client.Close()

	// Call DistributeCredential RPC
	resp, err := client.DistributeCredential(ctx, "ssh-ca", ca.Name, ca.PublicKey)
	if err != nil {
		recordFailedDistribution(dpu.Name, ca.Name, decision, fmt.Sprintf("RPC failed: %v", err), opCtx)
		return clierror.ConnectionFailed(dpu.Address())
	}

	if !resp.Success {
		recordFailedDistribution(dpu.Name, ca.Name, decision, resp.Message, opCtx)
		fmt.Printf("x Push failed: %s\n", resp.Message)
		return clierror.InternalError(fmt.Errorf("agent rejected push: %s", resp.Message))
	}

	// Success output per ADR-006 format
	if resp.InstalledPath != "" {
		fmt.Printf("CA installed at %s\n", resp.InstalledPath)
	} else {
		fmt.Printf("CA installed.\n")
	}
	if resp.SshdReloaded {
		fmt.Printf("sshd reloaded.\n")
	}

	// Record successful distribution
	recordSuccessDistribution(dpu.Name, ca.Name, decision, resp.InstalledPath, forced, forceReason, opCtx)

	return nil
}

// logAuditEntry creates an audit log entry for the distribution action.
func logAuditEntry(auditLogger *audit.Logger, opCtx *operatorContext, dpuName, caName, decision, forced string, gateDecision *attestation.GateDecision) {
	logEntry := audit.AuditEntry{
		Action:   "credential.distribute.ssh-ca",
		Target:   dpuName,
		Decision: decision,
		Details: map[string]string{
			"ca_name":        caName,
			"forced":         forced,
			"operator_id":    opCtx.OperatorID,
			"operator_email": opCtx.OperatorEmail,
		},
	}

	if gateDecision.Attestation != nil {
		logEntry.AttestationSnapshot = &audit.AttestationSnapshot{
			DPUName:       gateDecision.Attestation.DPUName,
			Status:        string(gateDecision.Attestation.Status),
			LastValidated: gateDecision.Attestation.LastValidated,
			Age:           gateDecision.Attestation.Age(),
		}
	} else if decision == "blocked" || decision == "forced" {
		logEntry.AttestationSnapshot = &audit.AttestationSnapshot{
			Status: "none",
		}
	}

	if gateDecision.Reason != "" && (decision == "blocked" || decision == "forced") {
		logEntry.Details["block_reason"] = gateDecision.Reason
	}

	if err := auditLogger.Log(logEntry); err != nil {
		fmt.Printf("Warning: failed to write audit entry: %v\n", err)
	}
}

// recordSuccessDistribution records a successful distribution in history.
func recordSuccessDistribution(dpuName, caName string, decision *attestation.GateDecision, installedPath string, forced bool, forceReason string, opCtx *operatorContext) {
	var outcome store.DistributionOutcome
	if forced {
		outcome = store.DistributionOutcomeForced
	} else {
		outcome = store.DistributionOutcomeSuccess
	}

	d := &store.Distribution{
		DPUName:        dpuName,
		CredentialType: "ssh-ca",
		CredentialName: caName,
		Outcome:        outcome,
		InstalledPath:  strPtr(installedPath),
		OperatorID:     opCtx.OperatorID,
		OperatorEmail:  opCtx.OperatorEmail,
	}

	if decision.Attestation != nil {
		status := string(decision.Attestation.Status)
		ageSecs := int(decision.Attestation.Age().Seconds())
		d.AttestationStatus = &status
		d.AttestationAgeSecs = &ageSecs
	}

	if forced && forceReason != "" {
		d.ErrorMessage = strPtr(fmt.Sprintf("forced: %s", forceReason))
		d.ForcedBy = strPtr(opCtx.OperatorEmail)
	}

	if err := dpuStore.RecordDistribution(d); err != nil {
		fmt.Printf("Warning: failed to record distribution: %v\n", err)
	}
}

// recordBlockedDistribution records a blocked distribution in history.
func recordBlockedDistribution(dpuName, caName string, decision *attestation.GateDecision, opCtx *operatorContext) {
	var outcome store.DistributionOutcome
	if decision.Attestation == nil {
		outcome = store.DistributionOutcomeBlockedFailed
	} else {
		outcome = store.DistributionOutcomeBlockedStale
	}

	d := &store.Distribution{
		DPUName:        dpuName,
		CredentialType: "ssh-ca",
		CredentialName: caName,
		Outcome:        outcome,
		ErrorMessage:   strPtr(decision.Reason),
		BlockedReason:  strPtr(decision.Reason),
		OperatorID:     opCtx.OperatorID,
		OperatorEmail:  opCtx.OperatorEmail,
	}

	if decision.Attestation != nil {
		status := string(decision.Attestation.Status)
		ageSecs := int(decision.Attestation.Age().Seconds())
		d.AttestationStatus = &status
		d.AttestationAgeSecs = &ageSecs
	}

	if err := dpuStore.RecordDistribution(d); err != nil {
		fmt.Printf("Warning: failed to record distribution: %v\n", err)
	}
}

// recordFailedDistribution records a failed distribution in history.
func recordFailedDistribution(dpuName, caName string, decision *attestation.GateDecision, errorMsg string, opCtx *operatorContext) {
	d := &store.Distribution{
		DPUName:        dpuName,
		CredentialType: "ssh-ca",
		CredentialName: caName,
		Outcome:        store.DistributionOutcomeSuccess, // Still attempted, but failed at RPC level
		ErrorMessage:   strPtr(errorMsg),
		OperatorID:     opCtx.OperatorID,
		OperatorEmail:  opCtx.OperatorEmail,
	}

	if decision.Attestation != nil {
		status := string(decision.Attestation.Status)
		ageSecs := int(decision.Attestation.Age().Seconds())
		d.AttestationStatus = &status
		d.AttestationAgeSecs = &ageSecs
	}

	if err := dpuStore.RecordDistribution(d); err != nil {
		fmt.Printf("Warning: failed to record distribution: %v\n", err)
	}
}

// strPtr returns a pointer to a string.
func strPtr(s string) *string {
	return &s
}

// formatAge formats a duration into a human-readable age string.
func formatAge(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if minutes == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh%dm", hours, minutes)
}
