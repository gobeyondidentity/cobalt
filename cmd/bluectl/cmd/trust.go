package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/nmelo/secure-infra/pkg/attestation"
	"github.com/nmelo/secure-infra/pkg/store"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(trustCmd)
	trustCmd.AddCommand(trustCreateCmd)
	trustCmd.AddCommand(trustListCmd)
	trustCmd.AddCommand(trustDeleteCmd)

	// Flags for trust create
	trustCreateCmd.Flags().String("type", "ssh_host", "Trust type: ssh_host, mtls")
	trustCreateCmd.Flags().Bool("bidirectional", false, "Create bidirectional trust")

	// Flags for trust list
	trustListCmd.Flags().String("tenant", "", "Filter by tenant")
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage trust relationships between hosts",
	Long:  `Commands to create, list, and delete M2M trust relationships between hosts.`,
}

var trustCreateCmd = &cobra.Command{
	Use:   "create <source-host> <target-host>",
	Short: "Create a trust relationship between hosts",
	Long: `Create a trust relationship between two hosts.

The source host accepts connections from the target host. The target host
initiates connections and receives a CA-signed certificate. Use --bidirectional
to create mutual trust in both directions.

Both hosts must have registered host agents paired with DPUs. Trust creation
requires fresh attestation from both paired DPUs.

Trust types:
  ssh_host  - SSH host key trust (allows SSH access)
  mtls      - Mutual TLS trust (allows mTLS connections)

Examples:
  bluectl trust create compute-01 slurm-head
  bluectl trust create compute-01 slurm-head --type mtls
  bluectl trust create compute-01 slurm-head --bidirectional`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		sourceHostname := args[0]
		targetHostname := args[1]
		trustType, _ := cmd.Flags().GetString("type")
		bidirectional, _ := cmd.Flags().GetBool("bidirectional")

		// Validate trust type
		if trustType != "ssh_host" && trustType != "mtls" {
			return fmt.Errorf("invalid trust type: %s (must be 'ssh_host' or 'mtls')", trustType)
		}

		// Source and target must be different
		if sourceHostname == targetHostname {
			return fmt.Errorf("source and target must be different hosts")
		}

		// Look up source host by hostname
		sourceHost, err := dpuStore.GetAgentHostByHostname(sourceHostname)
		if err != nil {
			return fmt.Errorf("source host not found: %s\nHint: Ensure the host agent is registered with 'host-agent' and paired with a DPU", sourceHostname)
		}

		// Look up target host by hostname
		targetHost, err := dpuStore.GetAgentHostByHostname(targetHostname)
		if err != nil {
			return fmt.Errorf("target host not found: %s\nHint: Ensure the host agent is registered with 'host-agent' and paired with a DPU", targetHostname)
		}

		// Get paired DPUs for both hosts
		sourceDPU, err := dpuStore.Get(sourceHost.DPUName)
		if err != nil {
			return fmt.Errorf("source host's paired DPU not found: %s", sourceHost.DPUName)
		}

		targetDPU, err := dpuStore.Get(targetHost.DPUName)
		if err != nil {
			return fmt.Errorf("target host's paired DPU not found: %s", targetHost.DPUName)
		}

		// Both DPUs must belong to a tenant
		if sourceDPU.TenantID == nil {
			return fmt.Errorf("source host's DPU '%s' is not assigned to a tenant", sourceDPU.Name)
		}
		if targetDPU.TenantID == nil {
			return fmt.Errorf("target host's DPU '%s' is not assigned to a tenant", targetDPU.Name)
		}

		// Both DPUs must belong to the same tenant
		if *sourceDPU.TenantID != *targetDPU.TenantID {
			return fmt.Errorf("source and target hosts must belong to the same tenant (via their paired DPUs)")
		}

		tenantID := *sourceDPU.TenantID

		// Check if trust relationship already exists (by host)
		exists, err := dpuStore.TrustRelationshipExistsByHost(sourceHostname, targetHostname, store.TrustType(trustType))
		if err != nil {
			return fmt.Errorf("failed to check existing trust: %w", err)
		}
		if exists {
			return fmt.Errorf("trust relationship already exists between %s and %s for type %s", sourceHostname, targetHostname, trustType)
		}

		// Check attestation status for both DPUs (M2M Trust attestation gate)
		if err := checkAttestationForTrust(sourceDPU.Name); err != nil {
			fmt.Fprintf(os.Stderr, "Hint: Run 'bluectl attestation %s' to verify device attestation\n", sourceDPU.Name)
			return err
		}
		if err := checkAttestationForTrust(targetDPU.Name); err != nil {
			fmt.Fprintf(os.Stderr, "Hint: Run 'bluectl attestation %s' to verify device attestation\n", targetDPU.Name)
			return err
		}

		// Create trust relationship with host info
		tr := &store.TrustRelationship{
			SourceHost:    sourceHostname,
			TargetHost:    targetHostname,
			SourceDPUID:   sourceDPU.ID,
			SourceDPUName: sourceDPU.Name,
			TargetDPUID:   targetDPU.ID,
			TargetDPUName: targetDPU.Name,
			TenantID:      tenantID,
			TrustType:     store.TrustType(trustType),
			Bidirectional: bidirectional,
			Status:        store.TrustStatusActive,
		}

		if err := dpuStore.CreateTrustRelationship(tr); err != nil {
			return fmt.Errorf("failed to create trust relationship: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(tr)
		}

		// Format trust type for display
		typeDisplay := formatTrustType(trustType)

		fmt.Println("Trust relationship created:")
		if bidirectional {
			fmt.Printf("  %s <--> %s (%s, bidirectional)\n", sourceHostname, targetHostname, typeDisplay)
		} else {
			fmt.Printf("  %s <-- %s (%s)\n", sourceHostname, targetHostname, typeDisplay)
		}
		fmt.Printf("  Status: %s\n", tr.Status)
		fmt.Println()

		fmt.Println("What this enables:")
		if bidirectional {
			fmt.Printf("  %s and %s can now authenticate to each other using SSH certificates.\n", sourceHostname, targetHostname)
		} else {
			fmt.Printf("  %s can now SSH to %s using a CA-signed host certificate.\n", targetHostname, sourceHostname)
		}
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Printf("  1. Ensure both hosts have the SSH CA distributed\n")
		fmt.Printf("  2. Target host requests certificate: host-agent --request-cert\n")
		fmt.Printf("  3. Verify with: ssh -o StrictHostKeyChecking=accept-new %s\n", sourceHostname)

		return nil
	},
}

var trustListCmd = &cobra.Command{
	Use:   "list",
	Short: "List trust relationships",
	Long: `List all trust relationships, optionally filtered by tenant.

Examples:
  bluectl trust list
  bluectl trust list --tenant acme
  bluectl trust list --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		tenantFilter, _ := cmd.Flags().GetString("tenant")

		var relationships []*store.TrustRelationship
		var err error

		if tenantFilter != "" {
			// Look up tenant by name
			tenant, err := dpuStore.GetTenant(tenantFilter)
			if err != nil {
				return fmt.Errorf("tenant not found: %s", tenantFilter)
			}
			relationships, err = dpuStore.ListTrustRelationships(tenant.ID)
			if err != nil {
				return fmt.Errorf("failed to list trust relationships: %w", err)
			}
		} else {
			// List all trust relationships
			relationships, err = dpuStore.ListAllTrustRelationships()
			if err != nil {
				return fmt.Errorf("failed to list trust relationships: %w", err)
			}
		}

		if outputFormat != "table" {
			return formatOutput(relationships)
		}

		if len(relationships) == 0 {
			fmt.Println("No trust relationships found.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SOURCE HOST\tTARGET HOST\tDPUs\tTYPE\tDIRECTION\tSTATUS")
		for _, tr := range relationships {
			direction := "one-way"
			if tr.Bidirectional {
				direction = "bidirectional"
			}
			// Show DPU pairing for context
			dpuInfo := fmt.Sprintf("%s/%s", tr.SourceDPUName, tr.TargetDPUName)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				tr.SourceHost,
				tr.TargetHost,
				dpuInfo,
				tr.TrustType,
				direction,
				tr.Status)
		}
		w.Flush()
		return nil
	},
}

var trustDeleteCmd = &cobra.Command{
	Use:   "delete <trust-id>",
	Short: "Delete a trust relationship",
	Long: `Delete a trust relationship by its ID.

Use 'bluectl trust list' to find the ID of the trust relationship to delete.

Examples:
  bluectl trust delete tr_a1b2c3d4`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		trustID := args[0]

		// Verify trust exists before deletion
		_, err := dpuStore.GetTrustRelationship(trustID)
		if err != nil {
			return fmt.Errorf("trust relationship not found: %s", trustID)
		}

		if err := dpuStore.DeleteTrustRelationship(trustID); err != nil {
			return fmt.Errorf("failed to delete trust relationship: %w", err)
		}

		fmt.Println("Trust relationship deleted.")
		return nil
	},
}

// formatTrustType returns a human-readable trust type string.
func formatTrustType(trustType string) string {
	switch strings.ToLower(trustType) {
	case "ssh_host":
		return "SSH host"
	case "mtls":
		return "mTLS"
	default:
		return trustType
	}
}

// checkAttestationForTrust verifies that a DPU has valid attestation for trust creation.
// Returns nil if attestation is verified and fresh, otherwise returns an error.
func checkAttestationForTrust(dpuName string) error {
	gate := attestation.NewGate(dpuStore)
	decision, err := gate.CanDistribute(dpuName)
	if err != nil {
		return fmt.Errorf("cannot create trust: '%s' attestation check failed", dpuName)
	}
	if !decision.Allowed {
		return fmt.Errorf("cannot create trust: '%s' attestation not verified", dpuName)
	}
	return nil
}
