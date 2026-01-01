package cmd

import (
	"fmt"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/attestation"
	"github.com/beyondidentity/fabric-console/pkg/audit"
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
	Long: `Prepare to distribute an SSH CA's public key to a target DPU.

This command verifies the attestation gate before allowing distribution.
The actual gRPC distribution will be implemented in Week 3.

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

		// Verify SSH CA exists
		exists, err := dpuStore.SSHCAExists(caName)
		if err != nil {
			return fmt.Errorf("failed to check SSH CA: %w", err)
		}
		if !exists {
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

		// Check attestation gate
		decision, err := gate.CanDistribute(dpu.Name)
		if err != nil {
			return fmt.Errorf("attestation gate check failed: %w", err)
		}

		// Handle gate decision
		if decision.Allowed {
			// Log audit entry for successful gate check
			logEntry := audit.AuditEntry{
				Action:   "credential.distribute.ssh-ca",
				Target:   dpu.Name,
				Decision: "allowed",
				Details: map[string]string{
					"ca_name": caName,
					"forced":  "false",
				},
			}
			if decision.Attestation != nil {
				logEntry.AttestationSnapshot = &audit.AttestationSnapshot{
					DPUName:       decision.Attestation.DPUName,
					Status:        string(decision.Attestation.Status),
					LastValidated: decision.Attestation.LastValidated,
					Age:           decision.Attestation.Age(),
				}
			}
			if err := auditLogger.Log(logEntry); err != nil {
				fmt.Printf("Warning: failed to write audit entry: %v\n", err)
			}

			age := "unknown"
			if decision.Attestation != nil {
				age = formatAge(decision.Attestation.Age())
			}
			fmt.Printf("Gate passed. Attestation verified (%s ago). Ready for distribution. [Week 3 will execute]\n", age)

		} else {
			// Gate blocked
			if force {
				// Log audit entry for forced bypass
				logEntry := audit.AuditEntry{
					Action:   "credential.distribute.ssh-ca",
					Target:   dpu.Name,
					Decision: "forced",
					Details: map[string]string{
						"ca_name":      caName,
						"forced":       "true",
						"block_reason": decision.Reason,
					},
				}
				if decision.Attestation != nil {
					logEntry.AttestationSnapshot = &audit.AttestationSnapshot{
						DPUName:       decision.Attestation.DPUName,
						Status:        string(decision.Attestation.Status),
						LastValidated: decision.Attestation.LastValidated,
						Age:           decision.Attestation.Age(),
					}
				} else {
					logEntry.AttestationSnapshot = &audit.AttestationSnapshot{
						Status: "none",
					}
				}
				if err := auditLogger.Log(logEntry); err != nil {
					fmt.Printf("Warning: failed to write audit entry: %v\n", err)
				}

				fmt.Printf("Warning: Forcing with %s (logged)\n", decision.Reason)
				fmt.Printf("Gate passed (forced). Ready for distribution. [Week 3 will execute]\n")
			} else {
				// Blocked, no force
				logEntry := audit.AuditEntry{
					Action:   "credential.distribute.ssh-ca",
					Target:   dpu.Name,
					Decision: "blocked",
					Details: map[string]string{
						"ca_name":      caName,
						"block_reason": decision.Reason,
					},
				}
				if decision.Attestation != nil {
					logEntry.AttestationSnapshot = &audit.AttestationSnapshot{
						DPUName:       decision.Attestation.DPUName,
						Status:        string(decision.Attestation.Status),
						LastValidated: decision.Attestation.LastValidated,
						Age:           decision.Attestation.Age(),
					}
				}
				if err := auditLogger.Log(logEntry); err != nil {
					fmt.Printf("Warning: failed to write audit entry: %v\n", err)
				}

				fmt.Printf("Error: %s\n", decision.Reason)
				if decision.Attestation == nil {
					fmt.Printf("Hint: run 'bluectl attestation %s' to verify DPU, or use --force (audited)\n", dpu.Name)
				} else {
					fmt.Printf("Hint: refresh attestation or use --force (audited)\n")
				}
				return fmt.Errorf("distribution blocked by attestation gate")
			}
		}

		return nil
	},
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
