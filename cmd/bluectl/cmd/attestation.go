package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/grpcclient"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(attestationCmd)
	attestationCmd.Flags().Bool("pem", false, "Output certificate PEM data")
	attestationCmd.Flags().String("target", "IRoT", "Attestation target: IRoT (DPU) or ERoT (BMC)")
}

var attestationCmd = &cobra.Command{
	Use:   "attestation <dpu-name-or-id>",
	Short: "Show DPU attestation status and certificates",
	Long: `Display DICE/SPDM attestation information from a DPU.

Shows the certificate chain hierarchy (L0-L6) and current attestation status.

Examples:
  bluectl attestation bf3-lab
  bluectl attestation bf3-lab --target ERoT
  bluectl attestation bf3-lab --pem
  bluectl attestation bf3-lab -o json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dpu, err := dpuStore.Get(args[0])
		if err != nil {
			return err
		}

		showPEM, _ := cmd.Flags().GetBool("pem")
		target, _ := cmd.Flags().GetString("target")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := grpcclient.NewClient(dpu.Address())
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer client.Close()

		resp, err := client.GetAttestation(ctx, target)
		if err != nil {
			return fmt.Errorf("failed to get attestation: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(resp)
		}

		// Show status
		fmt.Printf("Attestation Status: %s\n\n", resp.Status.String())

		if len(resp.Certificates) == 0 {
			fmt.Println("No certificates available")
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

		dpuStore.UpdateStatus(dpu.ID, "healthy")
		return nil
	},
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
