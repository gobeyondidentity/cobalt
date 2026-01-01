package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/attestation"
	"github.com/beyondidentity/fabric-console/pkg/audit"
	"github.com/beyondidentity/fabric-console/pkg/grpcclient"
	"github.com/beyondidentity/fabric-console/pkg/store"
	"github.com/spf13/cobra"
)

func init() {
	credentialCmd.AddCommand(distributeCmd)
	distributeCmd.AddCommand(distributeSSHCACmd)

	// Flags for distribute ssh-ca
	distributeSSHCACmd.Flags().StringP("target", "t", "", "Target DPU name (required)")
	distributeSSHCACmd.Flags().Bool("force", false, "Force distribution even with stale attestation (audited)")
	distributeSSHCACmd.MarkFlagRequired("target")
}

var distributeCmd = &cobra.Command{
	Use:   "distribute",
	Short: "Distribute credentials to DPUs",
	Long: `Commands to distribute credentials to DPUs with attestation gate checks.

Distribution requires the target DPU to have recent verified attestation.
Use --force to bypass stale attestation (this action is audited).`,
}

var distributeSSHCACmd = &cobra.Command{
	Use:   "ssh-ca <ca-name>",
	Short: "Distribute an SSH CA to a DPU",
	Long: `Distribute an SSH CA's public key to a target DPU.

This command verifies the attestation gate before allowing distribution.
The CA public key is sent to the DPU agent, which installs it and reloads sshd.

Attestation Requirements:
- DPU must have a verified attestation record
- Attestation must be fresh (less than 1 hour old by default)
- Use --force to bypass stale attestation (logged to audit trail)

Examples:
  bluectl credential distribute ssh-ca ops-ca --target bf3-lab
  bluectl credential distribute ssh-ca ops-ca --target bf3-lab --force`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		caName := args[0]
		targetDPU, _ := cmd.Flags().GetString("target")
		force, _ := cmd.Flags().GetBool("force")

		// Verify SSH CA exists and get it
		ca, err := dpuStore.GetSSHCA(caName)
		if err != nil {
			return fmt.Errorf("SSH CA '%s' not found", caName)
		}

		// Verify target DPU exists
		dpu, err := dpuStore.Get(targetDPU)
		if err != nil {
			return fmt.Errorf("target DPU '%s' not found", targetDPU)
		}

		// Create gate and audit logger
		gate := attestation.NewGate(dpuStore)
		auditLogger := audit.NewLogger(dpuStore)

		fmt.Printf("Checking attestation for %s...\n", dpu.Name)

		// Check attestation gate
		decision, err := gate.CanDistribute(dpu.Name)
		if err != nil {
			return fmt.Errorf("attestation gate check failed: %w", err)
		}

		// Handle gate decision
		if decision.Allowed {
			// Log audit entry for successful gate check
			logAuditEntry(auditLogger, dpu.Name, caName, "allowed", "false", decision)

			age := "unknown"
			if decision.Attestation != nil {
				age = formatAge(decision.Attestation.Age())
			}
			fmt.Printf("+ Attestation verified (%s ago)\n\n", age)

			// Proceed with distribution
			return executeDistribution(cmd.Context(), dpu, ca, decision, false, "")

		} else {
			// Gate blocked
			if force {
				// Log audit entry for forced bypass
				logAuditEntry(auditLogger, dpu.Name, caName, "forced", "true", decision)

				age := "unknown"
				if decision.Attestation != nil {
					age = formatAge(decision.Attestation.Age())
				}
				fmt.Printf("! Attestation stale (%s ago)\n", age)
				fmt.Printf("Warning: Forcing distribution despite %s (logged)\n\n", decision.Reason)

				// Proceed with forced distribution
				return executeDistribution(cmd.Context(), dpu, ca, decision, true, decision.Reason)

			} else {
				// Blocked, no force
				logAuditEntry(auditLogger, dpu.Name, caName, "blocked", "false", decision)

				// Record blocked distribution
				recordBlockedDistribution(dpu.Name, caName, decision)

				if decision.Attestation != nil {
					age := formatAge(decision.Attestation.Age())
					fmt.Printf("x Attestation stale (%s ago)\n\n", age)
				} else {
					fmt.Printf("x No attestation record\n\n")
				}

				fmt.Printf("Distribution blocked: %s\n", decision.Reason)
				fmt.Printf("Hint: Run 'bluectl attestation %s' or use --force (audited)\n", dpu.Name)
				return fmt.Errorf("distribution blocked by attestation gate")
			}
		}
	},
}

// executeDistribution performs the actual gRPC call to distribute the credential.
func executeDistribution(ctx context.Context, dpu *store.DPU, ca *store.SSHCA, decision *attestation.GateDecision, forced bool, forceReason string) error {
	fmt.Println("Distributing CA public key...")

	// Connect to DPU agent
	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		recordFailedDistribution(dpu.Name, ca.Name, decision, fmt.Sprintf("connection failed: %v", err))
		return fmt.Errorf("failed to connect to DPU agent: %w", err)
	}
	defer client.Close()

	// Call DistributeCredential RPC
	resp, err := client.DistributeCredential(ctx, "ssh-ca", ca.Name, ca.PublicKey)
	if err != nil {
		recordFailedDistribution(dpu.Name, ca.Name, decision, fmt.Sprintf("RPC failed: %v", err))
		return fmt.Errorf("distribution failed: %w", err)
	}

	if !resp.Success {
		recordFailedDistribution(dpu.Name, ca.Name, decision, resp.Message)
		fmt.Printf("x Distribution failed: %s\n", resp.Message)
		return fmt.Errorf("agent rejected distribution: %s", resp.Message)
	}

	// Success output
	fmt.Printf("+ CA installed on host\n")
	if resp.SshdReloaded {
		fmt.Printf("+ sshd reloaded\n")
	}
	fmt.Println()
	fmt.Printf("Distribution complete. Certificates signed by %s now accepted.\n", ca.Name)

	// Record successful distribution
	recordSuccessDistribution(dpu.Name, ca.Name, decision, resp.InstalledPath, forced, forceReason)

	return nil
}

// logAuditEntry creates an audit log entry for the distribution action.
func logAuditEntry(auditLogger *audit.Logger, dpuName, caName, decision, forced string, gateDecision *attestation.GateDecision) {
	logEntry := audit.AuditEntry{
		Action:   "credential.distribute.ssh-ca",
		Target:   dpuName,
		Decision: decision,
		Details: map[string]string{
			"ca_name": caName,
			"forced":  forced,
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
func recordSuccessDistribution(dpuName, caName string, decision *attestation.GateDecision, installedPath string, forced bool, forceReason string) {
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
	}

	if decision.Attestation != nil {
		status := string(decision.Attestation.Status)
		ageSecs := int(decision.Attestation.Age().Seconds())
		d.AttestationStatus = &status
		d.AttestationAgeSecs = &ageSecs
	}

	if forced && forceReason != "" {
		d.ErrorMessage = strPtr(fmt.Sprintf("forced: %s", forceReason))
	}

	if err := dpuStore.RecordDistribution(d); err != nil {
		fmt.Printf("Warning: failed to record distribution: %v\n", err)
	}
}

// recordBlockedDistribution records a blocked distribution in history.
func recordBlockedDistribution(dpuName, caName string, decision *attestation.GateDecision) {
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
func recordFailedDistribution(dpuName, caName string, decision *attestation.GateDecision, errorMsg string) {
	d := &store.Distribution{
		DPUName:        dpuName,
		CredentialType: "ssh-ca",
		CredentialName: caName,
		Outcome:        store.DistributionOutcomeSuccess, // Still attempted, but failed at RPC level
		ErrorMessage:   strPtr(errorMsg),
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
