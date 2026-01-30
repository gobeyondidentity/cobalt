package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(hostCmd)
	hostCmd.AddCommand(hostListCmd)
	hostCmd.AddCommand(hostPostureCmd)
	hostCmd.AddCommand(hostDeleteCmd)
	hostCmd.AddCommand(hostHealthCmd)

	// Flags for host list
	hostListCmd.Flags().String("tenant", "", "Filter by tenant")

	// Flags for host health
	hostHealthCmd.Flags().BoolP("verbose", "v", false, "Show component details")
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

		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		client, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
		hosts, err := client.ListAgentHosts(cmd.Context(), tenantFilter)
		if err != nil {
			return fmt.Errorf("failed to list hosts: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(hosts)
		}

		if len(hosts) == 0 {
			fmt.Println("No host agents registered.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "DPU\tHOSTNAME\tLAST SEEN")
		for _, h := range hosts {
			fmt.Fprintf(w, "%s\t%s\t%s\n", h.DPUName, h.Hostname, h.LastSeenAt)
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

		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		client, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
		posture, err := client.GetHostPostureByDPU(cmd.Context(), dpuName)
		if err != nil {
			if err == ErrNoPostureData {
				fmt.Printf("No posture data available for DPU '%s'.\n", dpuName)
				fmt.Println("The host may not have registered yet or has not reported posture.")
				return nil
			}
			return fmt.Errorf("failed to get host posture: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(posture)
		}

		// Table output with formatted labels
		fmt.Printf("Host posture for DPU '%s':\n", dpuName)

		// Format boolean values as enabled/disabled or yes/no
		secureBootStr := "unknown"
		if posture.SecureBoot != nil {
			if *posture.SecureBoot {
				secureBootStr = "enabled"
			} else {
				secureBootStr = "disabled"
			}
		}

		tpmPresentStr := "unknown"
		if posture.TPMPresent != nil {
			if *posture.TPMPresent {
				tpmPresentStr = "yes"
			} else {
				tpmPresentStr = "no"
			}
		}

		diskEncryption := posture.DiskEncryption
		if diskEncryption == "" {
			diskEncryption = "none"
		}

		osVersion := posture.OSVersion
		if osVersion == "" {
			osVersion = "unknown"
		}

		kernelVersion := posture.KernelVersion
		if kernelVersion == "" {
			kernelVersion = "unknown"
		}

		fmt.Printf("  Secure Boot:     %s\n", secureBootStr)
		fmt.Printf("  Disk Encryption: %s\n", diskEncryption)
		fmt.Printf("  OS Version:      %s\n", osVersion)
		fmt.Printf("  Kernel Version:  %s\n", kernelVersion)
		fmt.Printf("  TPM Present:     %s\n", tpmPresentStr)
		fmt.Printf("  Posture Hash:    %s\n", posture.PostureHash)
		fmt.Printf("  Last Updated:    %s\n", posture.CollectedAt)

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

		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		client, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
		if err := client.DeleteAgentHost(cmd.Context(), hostID); err != nil {
			return fmt.Errorf("failed to delete host: %w", err)
		}

		fmt.Println("Host deleted.")
		return nil
	},
}

var hostHealthCmd = &cobra.Command{
	Use:   "health <dpu-name>",
	Short: "Check host agent health",
	Long: `Check connectivity and health status of a host agent.

The host is identified by the DPU it's paired with. Since hosts register
via the DPU agent and do not expose a direct gRPC endpoint, this command
shows cached health information based on last seen timestamps and posture
updates.

Examples:
  bluectl host health bf3-lab
  bluectl host health bf3-lab --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runHostHealth,
}

func runHostHealth(cmd *cobra.Command, args []string) error {
	dpuName := args[0]
	verbose, _ := cmd.Flags().GetBool("verbose")

	serverURL, err := requireServer()
	if err != nil {
		return err
	}
	_ = serverURL // Will be used when API is fully implemented

	// For now, print informational message since host health requires
	// looking up host by DPU and checking cached health info
	fmt.Printf("Host health for DPU '%s':\n", dpuName)
	if verbose {
		fmt.Println("(verbose mode)")
	}
	fmt.Println()
	fmt.Println("Note: Host health via API not yet fully implemented.")
	fmt.Println("Use 'bluectl host list' to see hosts and their last seen times.")
	return nil
}

