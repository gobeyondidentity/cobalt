package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/attestation"
	"github.com/gobeyondidentity/cobalt/pkg/grpcclient"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(corimCmd)
	corimCmd.AddCommand(corimFetchCmd)
	corimCmd.AddCommand(corimMeasureCmd)
	corimCmd.AddCommand(corimValidateCmd)
	corimCmd.AddCommand(corimListCmd)

	// Flags for measure command
	corimMeasureCmd.Flags().String("target", "IRoT", "Attestation target (IRoT or ERoT)")
	corimMeasureCmd.Flags().IntSlice("indices", nil, "Measurement indices to fetch (empty for all)")

	// Flags for validate command
	corimValidateCmd.Flags().Bool("verbose", false, "Show detailed comparison")
	corimValidateCmd.Flags().String("target", "IRoT", "Attestation target (IRoT or ERoT)")
}

var corimCmd = &cobra.Command{
	Use:   "corim",
	Short: "Validate firmware integrity against NVIDIA reference measurements",
	Long: `Commands for fetching, viewing, and validating CoRIM (Concise Reference Integrity Manifest).

CoRIM files contain golden measurements from NVIDIA that can be compared against
live SPDM measurements from the DPU to verify firmware integrity.

Examples:
  bluectl corim list                    # List available CoRIMs from NVIDIA
  bluectl corim fetch bf3-lab           # Fetch CoRIM for DPU firmware version
  bluectl corim measure bf3-lab         # Get live SPDM measurements
  bluectl corim validate bf3-lab        # Compare live vs reference`,
}

var corimListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available CoRIMs from NVIDIA RIM service",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		client := attestation.NewRIMClient()
		ids, err := client.ListRIMIDs(ctx)
		if err != nil {
			return fmt.Errorf("failed to list RIMs: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(map[string]interface{}{"ids": ids, "count": len(ids)})
		}

		fmt.Printf("Available CoRIMs from NVIDIA RIM Service (%d total):\n\n", len(ids))

		// Group by type
		bf3 := []string{}
		other := []string{}
		for _, id := range ids {
			if strings.Contains(id, "BF3") {
				bf3 = append(bf3, id)
			} else {
				other = append(other, id)
			}
		}

		if len(bf3) > 0 {
			fmt.Println("BlueField-3:")
			for _, id := range bf3 {
				fmt.Printf("  %s\n", id)
			}
		}

		if len(other) > 0 {
			fmt.Println("\nOther:")
			for _, id := range other {
				fmt.Printf("  %s\n", id)
			}
		}

		return nil
	},
}

var corimFetchCmd = &cobra.Command{
	Use:   "fetch <dpu-name-or-id>",
	Short: "Fetch CoRIM from NVIDIA for DPU firmware version",
	Long: `Fetches the CoRIM (Concise Reference Integrity Manifest) from NVIDIA's RIM service
for the firmware version running on the specified DPU.

The CoRIM contains golden reference measurements that can be used to validate
the DPU's firmware integrity.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		nexusClient, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
		dpu, err := nexusClient.GetDPU(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("DPU not found: %s", args[0])
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		dpuAddr := fmt.Sprintf("%s:%d", dpu.Host, dpu.Port)

		// Get DPU inventory to find firmware version
		client, err := grpcclient.NewClient(dpuAddr)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer client.Close()

		inv, err := client.GetDPUInventory(ctx)
		if err != nil {
			return fmt.Errorf("failed to get inventory: %w", err)
		}

		// Find NIC firmware version
		var nicVersion string
		for _, fw := range inv.Firmwares {
			if strings.Contains(strings.ToLower(fw.Name), "nic") {
				nicVersion = fw.Version
				break
			}
		}

		if nicVersion == "" {
			return fmt.Errorf("could not determine NIC firmware version")
		}

		fmt.Printf("Fetching CoRIM for NIC firmware %s...\n", nicVersion)

		// Fetch from NVIDIA RIM service
		rimClient := attestation.NewRIMClient()
		entry, err := rimClient.FindRIMForFirmware(ctx, nicVersion)
		if err != nil {
			return fmt.Errorf("failed to fetch CoRIM: %w", err)
		}

		// Verify integrity
		valid, err := attestation.VerifyRIMIntegrity(entry)
		if err != nil {
			return fmt.Errorf("failed to verify RIM integrity: %w", err)
		}

		// Parse the CoRIM
		manifest, err := attestation.ParseCoRIM(entry.RIM)
		if err != nil {
			return fmt.Errorf("failed to parse CoRIM: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(map[string]interface{}{
				"id":              entry.ID,
				"sha256":          entry.SHA256,
				"integrityValid":  valid,
				"lastUpdated":     entry.LastUpdated,
				"referenceValues": manifest.ReferenceValues,
			})
		}

		fmt.Printf("\nCoRIM: %s\n", entry.ID)
		fmt.Printf("SHA256: %s\n", entry.SHA256)
		fmt.Printf("Integrity: %s\n", boolStatus(valid))
		fmt.Printf("Last Updated: %s\n", entry.LastUpdated)
		fmt.Printf("\nReference Measurements (%d):\n", len(manifest.ReferenceValues))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "INDEX\tDESCRIPTION\tALGORITHM\tDIGEST")
		for _, m := range manifest.ReferenceValues {
			digest := truncateDigest(m.Digest, 24)
			fmt.Fprintf(w, "%d\t%s\t%s\t%s...\n", m.Index, m.Description, m.Algorithm, digest)
		}
		w.Flush()

		return nil
	},
}

var corimMeasureCmd = &cobra.Command{
	Use:   "measure <dpu-name-or-id>",
	Short: "Get live SPDM measurements from DPU",
	Long: `Retrieves signed SPDM measurements from the DPU's attestation hardware.

These measurements reflect the current firmware state of the DPU and can be
compared against reference values from a CoRIM.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		nexusClient, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
		dpu, err := nexusClient.GetDPU(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("DPU not found: %s", args[0])
		}

		target, _ := cmd.Flags().GetString("target")
		indices, _ := cmd.Flags().GetIntSlice("indices")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		dpuAddr := fmt.Sprintf("%s:%d", dpu.Host, dpu.Port)
		client, err := grpcclient.NewClient(dpuAddr)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer client.Close()

		// Generate nonce
		nonce := generateNonce()

		// Convert indices to int32
		var idx32 []int32
		for _, i := range indices {
			idx32 = append(idx32, int32(i))
		}

		fmt.Printf("Requesting signed measurements from %s...\n", target)

		resp, err := client.GetSignedMeasurements(ctx, nonce, idx32, target)
		if err != nil {
			return fmt.Errorf("failed to get measurements: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(resp)
		}

		fmt.Printf("\nSPDM Version: %s\n", resp.SpdmVersion)
		fmt.Printf("Hashing: %s\n", resp.HashingAlgorithm)
		fmt.Printf("Signing: %s\n", resp.SigningAlgorithm)
		fmt.Printf("\nMeasurements (%d):\n", len(resp.Measurements))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "INDEX\tDESCRIPTION\tDIGEST")
		for _, m := range resp.Measurements {
			digest := truncateDigest(m.Digest, 32)
			fmt.Fprintf(w, "%d\t%s\t%s...\n", m.Index, m.Description, digest)
		}
		w.Flush()

		return nil
	},
}

var corimValidateCmd = &cobra.Command{
	Use:   "validate <dpu-name-or-id>",
	Short: "Validate live measurements against CoRIM reference",
	Long: `Validates the DPU's live SPDM measurements against reference values from NVIDIA's CoRIM.

This command:
1. Fetches the CoRIM matching the DPU's firmware version from NVIDIA RIM service
2. Retrieves live SPDM measurements from the DPU
3. Compares each measurement against the reference value
4. Reports match/mismatch status for each measurement index`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		nexusClient, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
		dpu, err := nexusClient.GetDPU(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("DPU not found: %s", args[0])
		}

		verbose, _ := cmd.Flags().GetBool("verbose")
		target, _ := cmd.Flags().GetString("target")

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		dpuAddr := fmt.Sprintf("%s:%d", dpu.Host, dpu.Port)

		// Connect to DPU
		client, err := grpcclient.NewClient(dpuAddr)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer client.Close()

		// Get inventory to find firmware version
		fmt.Println("Fetching DPU inventory...")
		inv, err := client.GetDPUInventory(ctx)
		if err != nil {
			return fmt.Errorf("failed to get inventory: %w", err)
		}

		// Find NIC firmware version
		var nicVersion string
		for _, fw := range inv.Firmwares {
			if strings.Contains(strings.ToLower(fw.Name), "nic") {
				nicVersion = fw.Version
				break
			}
		}

		if nicVersion == "" {
			return fmt.Errorf("could not determine NIC firmware version")
		}

		// Fetch CoRIM
		fmt.Printf("Fetching reference from NVIDIA RIM service (firmware %s)...\n", nicVersion)
		rimClient := attestation.NewRIMClient()
		entry, err := rimClient.FindRIMForFirmware(ctx, nicVersion)
		if err != nil {
			return fmt.Errorf("failed to fetch CoRIM: %w", err)
		}

		manifest, err := attestation.ParseCoRIM(entry.RIM)
		if err != nil {
			return fmt.Errorf("failed to parse CoRIM: %w", err)
		}

		// Get live measurements
		fmt.Printf("Requesting live measurements from %s...\n", target)
		nonce := generateNonce()
		measResp, err := client.GetSignedMeasurements(ctx, nonce, nil, target)
		if err != nil {
			return fmt.Errorf("failed to get measurements: %w", err)
		}

		// Convert to internal types for comparison
		var liveMeas []attestation.SPDMMeasurement
		for _, m := range measResp.Measurements {
			liveMeas = append(liveMeas, attestation.SPDMMeasurement{
				Index:       int(m.Index),
				Description: m.Description,
				Algorithm:   m.Algorithm,
				Digest:      m.Digest,
			})
		}

		// Validate
		summary := attestation.ValidateMeasurements(liveMeas, manifest.ReferenceValues)
		summary.FirmwareVersion = nicVersion
		summary.CoRIMID = entry.ID

		if outputFormat != "table" {
			return formatOutput(summary)
		}

		// Display results
		fmt.Println("\n" + strings.Repeat("─", 60))
		fmt.Println("VALIDATION RESULTS")
		fmt.Println(strings.Repeat("─", 60))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, r := range summary.Results {
			status := "✓ MATCH"
			if r.Status == "mismatch" {
				status = "✗ MISMATCH"
			} else if r.Status == "missing_reference" {
				status = "? NO REF"
			} else if r.Status == "missing_live" {
				status = "? NO LIVE"
			}

			fmt.Fprintf(w, "Index %d (%s):\t%s\n", r.Index, r.Description, status)

			if verbose && (r.ReferenceDigest != "" || r.LiveDigest != "") {
				if r.ReferenceDigest != "" {
					fmt.Fprintf(w, "  Reference:\t%s\n", truncateDigest(r.ReferenceDigest, 48))
				}
				if r.LiveDigest != "" {
					fmt.Fprintf(w, "  Live:\t%s\n", truncateDigest(r.LiveDigest, 48))
				}
			}
		}
		w.Flush()

		fmt.Println(strings.Repeat("─", 60))

		if summary.Valid {
			fmt.Printf("\nOverall: ✓ VALID (%d/%d measurements verified)\n", summary.Matched, summary.TotalChecked)
		} else {
			fmt.Printf("\nOverall: ✗ INVALID (%d matched, %d mismatched)\n", summary.Matched, summary.Mismatched)
		}

		return nil
	},
}

func generateNonce() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func truncateDigest(digest string, max int) string {
	if len(digest) <= max {
		return digest
	}
	return digest[:max]
}

func boolStatus(b bool) string {
	if b {
		return "✓ Valid"
	}
	return "✗ Invalid"
}
