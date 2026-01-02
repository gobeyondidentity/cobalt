package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	agentv1 "github.com/beyondidentity/fabric-console/gen/go/agent/v1"
	"github.com/beyondidentity/fabric-console/pkg/grpcclient"
	"github.com/beyondidentity/fabric-console/pkg/store"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(attestationCmd)
	attestationCmd.Flags().Bool("pem", false, "Output certificate PEM data")
	attestationCmd.Flags().String("target", "IRoT", "Attestation target: IRoT (DPU) or ERoT (BMC)")
	attestationCmd.Flags().Bool("no-save", false, "Don't persist attestation result to database")
	attestationCmd.Flags().Bool("include-host", false, "Include host posture in output")
}

var attestationCmd = &cobra.Command{
	Use:   "attestation <dpu-name-or-id>",
	Short: "Show DPU attestation status and certificates",
	Long: `Display DICE/SPDM attestation information from a DPU.

Shows the certificate chain hierarchy (L0-L6) and current attestation status.
Successful attestations are saved to enable gate checks for credential distribution.

Use --include-host to also display the security posture of the host paired with the DPU.

Examples:
  bluectl attestation bf3-lab
  bluectl attestation bf3-lab --target ERoT
  bluectl attestation bf3-lab --pem
  bluectl attestation bf3-lab -o json
  bluectl attestation bf3-lab --no-save
  bluectl attestation bf3-lab --include-host`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dpu, err := dpuStore.Get(args[0])
		if err != nil {
			return err
		}

		showPEM, _ := cmd.Flags().GetBool("pem")
		target, _ := cmd.Flags().GetString("target")
		noSave, _ := cmd.Flags().GetBool("no-save")
		includeHost, _ := cmd.Flags().GetBool("include-host")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := grpcclient.NewClient(dpu.Address())
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer client.Close()

		resp, err := client.GetAttestation(ctx, target)
		if err != nil {
			// Save failed attestation state
			if !noSave {
				saveAttestationResult(dpuStore, dpu.Name, store.AttestationStatusFailed, nil, nil, map[string]any{
					"error": err.Error(),
				})
				fmt.Printf("\nAttestation saved: status=failed, last_validated=%s\n", time.Now().Format(time.RFC3339))
			}
			return fmt.Errorf("failed to get attestation: %w", err)
		}

		if outputFormat != "table" {
			// Still save before returning JSON output
			if !noSave {
				diceHash, measHash := computeAttestationHashes(resp)
				saveAttestationResult(dpuStore, dpu.Name, store.AttestationStatusVerified, diceHash, measHash, map[string]any{
					"target":       target,
					"status":       resp.Status.String(),
					"certificates": len(resp.Certificates),
					"measurements": len(resp.Measurements),
				})
			}
			return formatOutput(resp)
		}

		// Show status
		fmt.Printf("Attestation Status: %s\n\n", resp.Status.String())

		if len(resp.Certificates) == 0 {
			fmt.Println("No certificates available")
			// Save unknown status if no certs
			if !noSave {
				saveAttestationResult(dpuStore, dpu.Name, store.AttestationStatusUnknown, nil, nil, map[string]any{
					"reason": "no certificates",
				})
				fmt.Printf("\nAttestation saved: status=unknown, last_validated=%s\n", time.Now().Format(time.RFC3339))
			}
			return nil
		}

		// Certificate chain
		fmt.Println("Certificate Chain:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "LEVEL\tSUBJECT\tISSUER\tALGORITHM\tVALID UNTIL")
		for _, cert := range resp.Certificates {
			subject := truncate(cert.Subject, 30)
			issuer := truncate(cert.Issuer, 20)
			fmt.Fprintf(w, "L%d\t%s\t%s\t%s\t%s\n",
				cert.Level, subject, issuer, cert.Algorithm, cert.NotAfter)
		}
		w.Flush()

		// Show PEM if requested
		if showPEM {
			fmt.Println("\nCertificate PEM Data:")
			for _, cert := range resp.Certificates {
				fmt.Printf("\n--- L%d: %s ---\n", cert.Level, cert.Subject)
				fmt.Println(cert.Pem)
			}
		}

		// Measurements if available
		if len(resp.Measurements) > 0 {
			fmt.Println("\nMeasurements:")
			for name, value := range resp.Measurements {
				fmt.Printf("  %s: %s\n", name, value)
			}
		}

		// Save successful attestation
		if !noSave {
			diceHash, measHash := computeAttestationHashes(resp)
			err = saveAttestationResult(dpuStore, dpu.Name, store.AttestationStatusVerified, diceHash, measHash, map[string]any{
				"target":       target,
				"status":       resp.Status.String(),
				"certificates": len(resp.Certificates),
				"measurements": len(resp.Measurements),
			})
			if err != nil {
				fmt.Printf("\nWarning: failed to save attestation: %v\n", err)
			} else {
				fmt.Printf("\nAttestation saved: status=verified, last_validated=%s\n", time.Now().Format(time.RFC3339))
			}
		}

		// Display host posture if requested
		if includeHost {
			displayHostPosture(dpu.Name)
		}

		dpuStore.UpdateStatus(dpu.ID, "healthy")
		return nil
	},
}

// computeAttestationHashes computes SHA256 hashes for DICE chain and measurements.
func computeAttestationHashes(resp *agentv1.GetAttestationResponse) (*string, *string) {
	var diceHash, measHash *string

	// Hash DICE chain (concatenate all certificate PEMs)
	if len(resp.Certificates) > 0 {
		h := sha256.New()
		for _, cert := range resp.Certificates {
			h.Write([]byte(cert.Pem))
		}
		hash := hex.EncodeToString(h.Sum(nil))
		diceHash = &hash
	}

	// Hash measurements
	if len(resp.Measurements) > 0 {
		// Serialize measurements to JSON for consistent hashing
		measJSON, err := json.Marshal(resp.Measurements)
		if err == nil {
			h := sha256.Sum256(measJSON)
			hash := hex.EncodeToString(h[:])
			measHash = &hash
		}
	}

	return diceHash, measHash
}

// saveAttestationResult persists attestation result to the database.
func saveAttestationResult(s *store.Store, dpuName string, status store.AttestationStatus, diceHash, measHash *string, rawData map[string]any) error {
	att := &store.Attestation{
		DPUName:       dpuName,
		Status:        status,
		LastValidated: time.Now(),
		RawData:       rawData,
	}

	if diceHash != nil {
		att.DICEChainHash = *diceHash
	}
	if measHash != nil {
		att.MeasurementsHash = *measHash
	}

	return s.SaveAttestation(att)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// displayHostPosture shows the host posture for a DPU.
func displayHostPosture(dpuName string) {
	host, err := dpuStore.GetAgentHostByDPU(dpuName)
	if err != nil {
		fmt.Println("\nHost Posture: No host agent paired")
		return
	}

	posture, err := dpuStore.GetAgentHostPosture(host.ID)
	if err != nil {
		fmt.Printf("\nHost Posture (%s): No posture data available\n", host.Hostname)
		return
	}

	fmt.Printf("\nHost Posture (%s):\n", host.Hostname)
	fmt.Printf("  Secure Boot: %s\n", formatBoolStatus(posture.SecureBoot))

	diskEnc := "unknown"
	if posture.DiskEncryption != "" {
		diskEnc = posture.DiskEncryption
	}
	fmt.Printf("  Disk Encryption: %s\n", diskEnc)

	osVer := "unknown"
	if posture.OSVersion != "" {
		osVer = posture.OSVersion
	}
	fmt.Printf("  OS: %s\n", osVer)

	kernel := "unknown"
	if posture.KernelVersion != "" {
		kernel = posture.KernelVersion
	}
	fmt.Printf("  Kernel: %s\n", kernel)

	fmt.Printf("  TPM: %s\n", formatTPMStatus(posture.TPMPresent))
	fmt.Printf("  Last Update: %s\n", formatRelativeTime(posture.CollectedAt))
}

// formatBoolStatus formats a *bool as enabled/disabled/unknown.
func formatBoolStatus(b *bool) string {
	if b == nil {
		return "unknown"
	}
	if *b {
		return "enabled"
	}
	return "disabled"
}

// formatTPMStatus formats a *bool as present/not detected/unknown.
func formatTPMStatus(b *bool) string {
	if b == nil {
		return "unknown"
	}
	if *b {
		return "present"
	}
	return "not detected"
}
