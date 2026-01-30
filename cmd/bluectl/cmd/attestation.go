package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/nmelo/secure-infra/pkg/clierror"
	"github.com/nmelo/secure-infra/pkg/grpcclient"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(attestationCmd)
	attestationCmd.Flags().Bool("pem", false, "Output certificate PEM data")
	attestationCmd.Flags().String("target", "IRoT", "Attestation target: IRoT (DPU) or ERoT (BMC)")
	attestationCmd.Flags().Bool("include-host", false, "Include host posture in output")
}

var attestationCmd = &cobra.Command{
	Use:   "attestation <dpu-name-or-id>",
	Short: "Verify DPU hardware integrity via cryptographic attestation",
	Long: `Verify that DPU firmware has not been tampered with using DICE/SPDM cryptographic measurements.

Attestation proves hardware identity and integrity by validating the certificate chain
built during secure boot (levels L0-L6). Each level cryptographically binds to the next,
creating an unforgeable chain from silicon to running firmware.

Fresh attestation is required before distributing credentials to a DPU.

Use --include-host to also display the security posture of the host paired with the DPU.

Examples:
  bluectl attestation bf3-lab
  bluectl attestation bf3-lab --target ERoT
  bluectl attestation bf3-lab --pem
  bluectl attestation bf3-lab -o json
  bluectl attestation bf3-lab --include-host`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		client, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
		dpu, err := client.GetDPU(cmd.Context(), args[0])
		if err != nil {
			return clierror.DeviceNotFound(args[0])
		}

		showPEM, _ := cmd.Flags().GetBool("pem")
		target, _ := cmd.Flags().GetString("target")
		includeHost, _ := cmd.Flags().GetBool("include-host")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dpuAddress := fmt.Sprintf("%s:%d", dpu.Host, dpu.Port)
		grpcClient, err := grpcclient.NewClient(dpuAddress)
		if err != nil {
			return clierror.ConnectionFailed(dpuAddress)
		}
		defer grpcClient.Close()

		resp, err := grpcClient.GetAttestation(ctx, target)
		if err != nil {
			return clierror.AttestationFailed(err.Error())
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

		// Display host posture if requested
		if includeHost {
			displayHostPosture(dpu.Name)
		}

		return nil
	},
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// displayHostPosture shows the host posture for a DPU.
func displayHostPosture(_ string) {
	fmt.Println("\nHost Posture: Not available (requires server-side host agent API)")
}
