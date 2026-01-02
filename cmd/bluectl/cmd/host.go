package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(hostCmd)
	hostCmd.AddCommand(hostListCmd)
	hostCmd.AddCommand(hostPostureCmd)
	hostCmd.AddCommand(hostDeleteCmd)

	// Flags for host list
	hostListCmd.Flags().String("tenant", "", "Filter by tenant")
}

var hostCmd = &cobra.Command{
	Use:   "host",
	Short: "Manage host agents",
	Long:  `Commands to list, inspect, and delete host agents and their posture.`,
}

var hostListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered host agents",
	Long: `List all host agents registered with the fabric.

The output shows each DPU and its paired host (if any), along with
the host's last seen time and security posture attributes.

Examples:
  bluectl host list
  bluectl host list --tenant acme
  bluectl host list --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		tenantFilter, _ := cmd.Flags().GetString("tenant")

		var tenantID string
		if tenantFilter != "" {
			tenant, err := dpuStore.GetTenant(tenantFilter)
			if err != nil {
				return fmt.Errorf("tenant not found: %s", tenantFilter)
			}
			tenantID = tenant.ID
		}

		// Get all agent hosts (optionally filtered by tenant)
		hosts, err := dpuStore.ListAgentHosts(tenantID)
		if err != nil {
			return fmt.Errorf("failed to list hosts: %w", err)
		}

		// Build a map of DPU name to host for display
		type hostDisplay struct {
			DPUName        string
			Hostname       string
			LastSeen       string
			SecureBoot     string
			DiskEncryption string
		}

		var displays []hostDisplay
		for _, h := range hosts {
			d := hostDisplay{
				DPUName:        h.DPUName,
				Hostname:       h.Hostname,
				LastSeen:       formatRelativeTime(h.LastSeenAt),
				SecureBoot:     "-",
				DiskEncryption: "-",
			}

			// Get posture if available
			posture, err := dpuStore.GetAgentHostPosture(h.ID)
			if err == nil && posture != nil {
				if posture.SecureBoot != nil {
					if *posture.SecureBoot {
						d.SecureBoot = "enabled"
					} else {
						d.SecureBoot = "disabled"
					}
				}
				if posture.DiskEncryption != "" {
					d.DiskEncryption = strings.ToUpper(posture.DiskEncryption)
				}
			}
			displays = append(displays, d)
		}

		if outputFormat != "table" {
			// For JSON/YAML output, include full host and posture data
			type hostWithPosture struct {
				Host    interface{} `json:"host" yaml:"host"`
				Posture interface{} `json:"posture,omitempty" yaml:"posture,omitempty"`
			}
			var output []hostWithPosture
			for _, h := range hosts {
				hwp := hostWithPosture{Host: h}
				posture, err := dpuStore.GetAgentHostPosture(h.ID)
				if err == nil && posture != nil {
					hwp.Posture = posture
				}
				output = append(output, hwp)
			}
			return formatOutput(output)
		}

		if len(displays) == 0 {
			fmt.Println("No host agents registered.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "DPU\tHOSTNAME\tLAST SEEN\tSECURE BOOT\tDISK ENC")
		for _, d := range displays {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				d.DPUName,
				d.Hostname,
				d.LastSeen,
				d.SecureBoot,
				d.DiskEncryption)
		}
		w.Flush()
		return nil
	},
}

var hostPostureCmd = &cobra.Command{
	Use:   "posture <dpu-name>",
	Short: "Show host posture for a DPU",
	Long: `Display detailed security posture for the host paired with a DPU.

The posture includes security attributes like Secure Boot status,
disk encryption, OS version, kernel version, TPM presence, and
a hash of all posture attributes.

Examples:
  bluectl host posture bf3-01
  bluectl host posture bf3-01 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dpuName := args[0]

		// Look up host by DPU name
		host, err := dpuStore.GetAgentHostByDPU(dpuName)
		if err != nil {
			return fmt.Errorf("no host agent found for DPU '%s'", dpuName)
		}

		// Get posture
		posture, err := dpuStore.GetAgentHostPosture(host.ID)
		if err != nil {
			return fmt.Errorf("no posture data for host '%s': %w", host.Hostname, err)
		}

		if outputFormat != "table" {
			return formatOutput(map[string]interface{}{
				"host":    host,
				"posture": posture,
			})
		}

		// Display header
		fmt.Printf("Host: %s\n", host.Hostname)
		fmt.Printf("Paired with: %s\n", host.DPUName)
		fmt.Printf("Last Update: %s\n", formatRelativeTime(posture.CollectedAt))
		fmt.Println()

		// Display posture
		fmt.Println("Posture:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

		// Secure Boot
		secureBoot := "unknown"
		if posture.SecureBoot != nil {
			if *posture.SecureBoot {
				secureBoot = "enabled"
			} else {
				secureBoot = "disabled"
			}
		}
		fmt.Fprintf(w, "  Secure Boot:\t%s\n", secureBoot)

		// Disk Encryption
		diskEnc := "unknown"
		if posture.DiskEncryption != "" {
			diskEnc = strings.ToUpper(posture.DiskEncryption)
		}
		fmt.Fprintf(w, "  Disk Encryption:\t%s\n", diskEnc)

		// OS Version
		osVersion := "unknown"
		if posture.OSVersion != "" {
			osVersion = posture.OSVersion
		}
		fmt.Fprintf(w, "  OS Version:\t%s\n", osVersion)

		// Kernel
		kernel := "unknown"
		if posture.KernelVersion != "" {
			kernel = posture.KernelVersion
		}
		fmt.Fprintf(w, "  Kernel:\t%s\n", kernel)

		// TPM
		tpm := "unknown"
		if posture.TPMPresent != nil {
			if *posture.TPMPresent {
				tpm = "present"
			} else {
				tpm = "not present"
			}
		}
		fmt.Fprintf(w, "  TPM:\t%s\n", tpm)

		// Posture Hash (truncate for display)
		hash := posture.PostureHash
		if len(hash) > 12 {
			hash = hash[:12] + "..."
		}
		if hash == "" {
			hash = "none"
		}
		fmt.Fprintf(w, "  Posture Hash:\t%s\n", hash)

		w.Flush()
		return nil
	},
}

var hostDeleteCmd = &cobra.Command{
	Use:   "delete <host-id>",
	Short: "Delete a host agent",
	Long: `Delete a host agent by its ID.

Use 'bluectl host list --output json' to find host IDs.

Examples:
  bluectl host delete host_a1b2c3d4`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hostID := args[0]

		// Verify host exists
		_, err := dpuStore.GetAgentHost(hostID)
		if err != nil {
			return fmt.Errorf("host not found: %s", hostID)
		}

		if err := dpuStore.DeleteAgentHost(hostID); err != nil {
			return fmt.Errorf("failed to delete host: %w", err)
		}

		fmt.Println("Host deleted.")
		return nil
	},
}

// formatRelativeTime formats a time as a human-readable relative duration.
func formatRelativeTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	if d < 0 {
		return "just now"
	}
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
