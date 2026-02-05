package cmd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/clierror"
	"github.com/gobeyondidentity/cobalt/pkg/grpcclient"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(dpuCmd)
	dpuCmd.AddCommand(dpuListCmd)
	dpuCmd.AddCommand(dpuAddCmd)
	dpuCmd.AddCommand(dpuRemoveCmd)
	dpuCmd.AddCommand(dpuInfoCmd)
	dpuCmd.AddCommand(dpuHealthCmd)
	dpuCmd.AddCommand(dpuAssignCmd)
	dpuCmd.AddCommand(dpuDecommissionCmd)
	dpuCmd.AddCommand(dpuReactivateCmd)

	// Add flags
	dpuAddCmd.Flags().IntP("port", "p", 18051, "gRPC port")
	dpuAddCmd.Flags().StringP("name", "n", "", "DPU name (default: hostname from agent)")
	dpuAddCmd.Flags().Bool("offline", false, "Skip connectivity check and add DPU anyway")
	dpuHealthCmd.Flags().BoolP("verbose", "v", false, "Show detailed component health status")

	// Flags for dpu list
	dpuListCmd.Flags().String("status", "", "Filter by status (pending, active, decommissioned)")

	// Flags for dpu remove
	dpuRemoveCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	// Flags for dpu assign
	dpuAssignCmd.Flags().String("tenant", "", "Tenant to assign the DPU to (required)")
	dpuAssignCmd.MarkFlagRequired("tenant")

	// Flags for dpu decommission
	dpuDecommissionCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
	dpuDecommissionCmd.Flags().String("reason", "", "Reason for decommissioning (required)")
	dpuDecommissionCmd.MarkFlagRequired("reason")
	dpuDecommissionCmd.Flags().Bool("scrub-credentials", false, "Scrub queued credentials (default: false)")

	// Flags for dpu reactivate
	dpuReactivateCmd.Flags().String("reason", "", "Reason for reactivating (required, min 20 chars)")
	dpuReactivateCmd.MarkFlagRequired("reason")
}

var dpuCmd = &cobra.Command{
	Use:   "dpu",
	Short: "Manage DPU registrations",
	Long:  `Commands to list, add, remove, and query registered DPUs.`,
}

// validDPUStatuses defines the valid status values for DPU list filtering.
var validDPUStatuses = []string{"pending", "active", "decommissioned"}

var dpuListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered DPUs",
	Long: `List all registered DPUs, optionally filtered by status.

Examples:
  bluectl dpu list
  bluectl dpu list --status active
  bluectl dpu list --status decommissioned`,
	RunE: func(cmd *cobra.Command, args []string) error {
		statusFilter, _ := cmd.Flags().GetString("status")

		// Validate status if provided
		if statusFilter != "" {
			valid := false
			for _, s := range validDPUStatuses {
				if statusFilter == s {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid status: %s (must be one of: %s)", statusFilter, strings.Join(validDPUStatuses, ", "))
			}
		}

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return listDPUsRemote(cmd.Context(), serverURL, statusFilter)
	},
}

func listDPUsRemote(ctx context.Context, serverURL, statusFilter string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}
	dpus, err := client.ListDPUs(ctx, statusFilter)
	if err != nil {
		return fmt.Errorf("failed to list DPUs from server: %w", err)
	}

	// Return empty array for JSON/YAML when no DPUs
	if outputFormat != "table" {
		if len(dpus) == 0 {
			fmt.Println("[]")
			return nil
		}
		return formatOutput(dpus)
	}

	if len(dpus) == 0 {
		fmt.Println("No DPUs registered. Use 'bluectl dpu add' to register one.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tHOST\tPORT\tSTATUS*\tLAST SEEN")
	for _, dpu := range dpus {
		lastSeen := "never"
		if dpu.LastSeen != nil {
			lastSeen = *dpu.LastSeen
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
			dpu.Name, dpu.Host, dpu.Port, dpu.Status, lastSeen)
	}
	w.Flush()
	fmt.Println()
	fmt.Println("* Status reflects last known state. Use 'bluectl dpu health <name>' for live status.")
	return nil
}

var dpuAddCmd = &cobra.Command{
	Use:   "add <host>",
	Short: "Register a new DPU",
	Long: `A DPU (Data Processing Unit) is a smart NIC installed inside a host server.
The DPU Agent runs on the DPU itself. Credentials are distributed to the
host server through the paired Host Agent.

Register a new DPU by connecting to its agent and retrieving identity information.

The host is the DPU's gRPC agent address (IP or hostname). This is the DPU's management
interface where the agent runs on the ARM cores, NOT the BMC address. The agent listens
on port 18051 by default.

By default, the DPU is named using the hostname reported by the agent. Use --name to
override with a custom name.

By default, registration requires a successful connectivity check to the DPU agent.
Use --offline to register a DPU that is not currently reachable (requires --name).

Examples:
  bluectl dpu add 192.168.1.204                      # Uses agent hostname as name
  bluectl dpu add 192.168.1.204 --name bf3-lab       # Custom name
  bluectl dpu add 192.168.1.204 --offline --name bf3-lab  # Skip connectivity check
  bluectl dpu add dpu.example.com                    # Hostname, default port
  bluectl dpu add 10.0.0.50 --port 50052             # Custom port`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hostArg := args[0]
		port, _ := cmd.Flags().GetInt("port")
		name, _ := cmd.Flags().GetString("name")
		offline, _ := cmd.Flags().GetBool("offline")

		// Parse host:port if provided in argument (e.g., "192.168.1.204:18051")
		// This prevents double-port bug where "IP:PORT" + default port = "IP:PORT:PORT"
		host, portStr, err := net.SplitHostPort(hostArg)
		if err != nil {
			// No port in argument, use as-is
			host = hostArg
		} else {
			// Port was in argument, parse it (overrides --port flag)
			parsedPort, parseErr := strconv.Atoi(portStr)
			if parseErr != nil {
				return fmt.Errorf("invalid port in address %q: %w", hostArg, parseErr)
			}
			port = parsedPort
		}

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return addDPURemote(cmd.Context(), serverURL, name, host, port, offline)
	},
}

func addDPURemote(ctx context.Context, serverURL, name, host string, port int, offline bool) error {
	// Connectivity check (unless --offline)
	if !offline {
		fmt.Printf("Checking connectivity to %s:%d...\n", host, port)
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		grpcClient, err := grpcclient.NewClient(fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			if name == "" {
				return fmt.Errorf("cannot connect to DPU agent at %s:%d: %w\n\nUse --offline with --name to skip connectivity check", host, port, err)
			}
			return fmt.Errorf("cannot connect to DPU agent at %s:%d: %w\n\nUse --offline to skip connectivity check", host, port, err)
		}
		defer grpcClient.Close()

		info, err := grpcClient.GetSystemInfo(checkCtx)
		if err != nil {
			return fmt.Errorf("failed to get DPU system info: %w", err)
		}

		// Show DPU identity info
		fmt.Println("Connected to DPU:")
		fmt.Printf("  Hostname: %s\n", info.Hostname)
		if info.SerialNumber != "" {
			fmt.Printf("  Serial:   %s\n", info.SerialNumber)
		}

		// Use hostname as name if not provided
		if name == "" {
			name = info.Hostname
		}
	} else if name == "" {
		return fmt.Errorf("--name is required when using --offline")
	}

	if name == "" {
		return fmt.Errorf("could not determine DPU name. Use --name to specify one")
	}

	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}
	dpu, err := client.AddDPU(ctx, name, host, port)
	if err != nil {
		return fmt.Errorf("failed to add DPU to server: %w", err)
	}

	if outputFormat == "json" || outputFormat == "yaml" {
		return formatOutput(map[string]any{
			"status": "created",
			"dpu":    dpu,
		})
	}

	fmt.Printf("Added DPU '%s' at %s:%d.\n", dpu.Name, dpu.Host, dpu.Port)
	fmt.Println()
	fmt.Printf("Next: Assign to a tenant with 'bluectl tenant assign <tenant> %s'\n", dpu.Name)
	return nil
}

var dpuRemoveCmd = &cobra.Command{
	Use:   "remove <name-or-id>",
	Short: "Remove a registered DPU",
	Long: `Remove a DPU registration. This action is permanent.

Examples:
  bluectl dpu remove bf3-lab
  bluectl dpu remove bf3-lab --yes`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nameOrID := args[0]
		skipConfirm, _ := cmd.Flags().GetBool("yes")

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return removeDPURemote(cmd.Context(), serverURL, nameOrID, skipConfirm)
	},
}

func removeDPURemote(ctx context.Context, serverURL, nameOrID string, skipConfirm bool) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}

	// Get DPU details first for confirmation and output
	dpu, err := client.GetDPU(ctx, nameOrID)
	if err != nil {
		return fmt.Errorf("DPU not found: %s", nameOrID)
	}

	if !skipConfirm {
		fmt.Printf("Remove DPU '%s' (%s:%d)? This action is permanent.\n", dpu.Name, dpu.Host, dpu.Port)
		fmt.Print("Type 'yes' to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Println("Removal cancelled.")
			return nil
		}
	}

	if err := client.RemoveDPU(ctx, dpu.ID); err != nil {
		return fmt.Errorf("failed to remove DPU from server: %w", err)
	}
	fmt.Printf("Removed DPU '%s'\n", dpu.Name)
	return nil
}

var dpuInfoCmd = &cobra.Command{
	Use:     "info <name-or-id>",
	Aliases: []string{"show", "describe"},
	Short:   "Show DPU system information",
	Args:    ExactArgsWithUsage(1),
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

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		grpcClient, err := grpcclient.NewClient(fmt.Sprintf("%s:%d", dpu.Host, dpu.Port))
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer grpcClient.Close()

		info, err := grpcClient.GetSystemInfo(ctx)
		if err != nil {
			return fmt.Errorf("failed to get system info: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(info)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Hostname:\t%s\n", info.Hostname)
		fmt.Fprintf(w, "Model:\t%s\n", info.Model)
		fmt.Fprintf(w, "Serial:\t%s\n", info.SerialNumber)
		fmt.Fprintf(w, "Firmware:\t%s\n", info.FirmwareVersion)
		fmt.Fprintf(w, "DOCA Version:\t%s\n", info.DocaVersion)
		fmt.Fprintf(w, "OVS Version:\t%s\n", info.OvsVersion)
		fmt.Fprintf(w, "Kernel:\t%s\n", info.KernelVersion)
		fmt.Fprintf(w, "ARM Cores:\t%d\n", info.ArmCores)
		fmt.Fprintf(w, "Memory:\t%d GB\n", info.MemoryGb)
		fmt.Fprintf(w, "Uptime:\t%s\n", formatDuration(info.UptimeSeconds))
		w.Flush()

		return nil
	},
}

func formatDuration(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

var dpuHealthCmd = &cobra.Command{
	Use:   "health <name>",
	Short: "Check DPU agent health and connectivity",
	Long: `Check connectivity and health status of a DPU agent.

Shows connection status, latency, agent version, and component health.
Use --verbose to see detailed component status.

Examples:
  bluectl dpu health bf3-lab
  bluectl dpu health bf3-lab --verbose`,
	Args: ExactArgsWithUsage(1),
	RunE: runDPUHealth,
}

func runDPUHealth(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")

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
		return fmt.Errorf("DPU not found: %s", args[0])
	}

	dpuAddr := fmt.Sprintf("%s:%d", dpu.Host, dpu.Port)
	fmt.Printf("DPU: %s (%s)\n", dpu.Name, dpuAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	grpcClient, err := grpcclient.NewClient(dpuAddr)
	if err != nil {
		fmt.Println("Status: offline")
		fmt.Printf("Error: %v\n", err)
		fmt.Println()
		fmt.Println("Troubleshooting:")
		fmt.Printf("  - Verify DPU is powered on and network is connected\n")
		fmt.Printf("  - Check firewall allows port %d\n", dpu.Port)
		fmt.Printf("  - Try: ping %s\n", dpu.Host)
		return nil
	}
	defer grpcClient.Close()

	resp, err := grpcClient.HealthCheck(ctx)
	latency := time.Since(start)

	if err != nil {
		fmt.Println("Status: unhealthy")
		fmt.Printf("Error: %v\n", err)
		fmt.Println()
		fmt.Println("Troubleshooting:")
		fmt.Println("  - Agent is reachable but health check failed")
		fmt.Println("  - Check agent logs on the DPU")
		fmt.Println("  - Try: bluectl dpu info", dpu.Name)
		return nil
	}

	status := "healthy"
	if !resp.Healthy {
		status = "unhealthy"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Latency: %dms\n", latency.Milliseconds())
	fmt.Printf("Agent Version: %s\n", resp.Version)
	fmt.Printf("Uptime: %s\n", formatDuration(resp.UptimeSeconds))

	if verbose && len(resp.Components) > 0 {
		fmt.Println()
		fmt.Println("Components:")
		for name, comp := range resp.Components {
			compStatus := "healthy"
			if !comp.Healthy {
				compStatus = "unhealthy"
			}
			msg := comp.Message
			if msg == "" {
				msg = "ok"
			}
			fmt.Printf("  %-8s %s (%s)\n", name+":", compStatus, msg)
		}
	}

	return nil
}

var dpuAssignCmd = &cobra.Command{
	Use:   "assign <dpu-name>",
	Short: "Assign a DPU to a tenant",
	Long: `Assign a DPU to a tenant for grouping and access control.

This is an alias for 'bluectl tenant assign <tenant> <dpu>'.

Examples:
  bluectl dpu assign bf3-lab --tenant "Production"
  bluectl dpu assign bf3-dev --tenant acme`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dpuName := args[0]
		tenantName, _ := cmd.Flags().GetString("tenant")

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return assignDPURemote(cmd.Context(), serverURL, tenantName, dpuName)
	},
}

var dpuDecommissionCmd = &cobra.Command{
	Use:   "decommission <name-or-id>",
	Short: "Decommission a DPU",
	Long: `Decommission a DPU by name or ID. The DPU will no longer authenticate,
but audit records are preserved. Use this for hardware removal scenarios.

Unlike 'dpu remove' which deletes the record entirely, decommissioning:
  - Blocks all authentication attempts (returns auth.decommissioned)
  - Optionally scrubs queued credentials
  - Retains audit trail for compliance

Examples:
  bluectl dpu decommission bf3-lab --reason "Hardware removal"
  bluectl dpu decommission bf3-lab --reason "RMA" --scrub-credentials
  bluectl dpu decommission bf3-lab --reason "Decommissioning" --yes`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nameOrID := args[0]
		skipConfirm, _ := cmd.Flags().GetBool("yes")
		reason, _ := cmd.Flags().GetString("reason")
		scrubCredentials, _ := cmd.Flags().GetBool("scrub-credentials")

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return decommissionDPURemote(cmd.Context(), serverURL, nameOrID, reason, skipConfirm, scrubCredentials)
	},
}

func decommissionDPURemote(ctx context.Context, serverURL, nameOrID, reason string, skipConfirm, scrubCredentials bool) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}

	// Get DPU details first for confirmation and output
	dpu, err := client.GetDPU(ctx, nameOrID)
	if err != nil {
		return fmt.Errorf("DPU not found: %s", nameOrID)
	}

	// Check if already decommissioned
	if dpu.Status == "decommissioned" {
		fmt.Printf("DPU '%s' is already decommissioned.\n", dpu.Name)
		return nil
	}

	if !skipConfirm {
		fmt.Printf("Decommission DPU '%s' (%s:%d)?\n", dpu.Name, dpu.Host, dpu.Port)
		fmt.Printf("  Status: %s\n", dpu.Status)
		if scrubCredentials {
			fmt.Println("  WARNING: Queued credentials will be scrubbed")
		}
		fmt.Printf("  Reason: %s\n", reason)
		fmt.Println()
		fmt.Print("Type 'yes' to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Println("Decommission cancelled.")
			return nil
		}
	}

	result, err := client.DecommissionDPU(ctx, dpu.ID, reason, scrubCredentials)
	if err != nil {
		return fmt.Errorf("failed to decommission DPU: %w", err)
	}

	if outputFormat == "json" || outputFormat == "yaml" {
		return formatOutput(map[string]any{
			"status": "decommissioned",
			"dpu":    result,
		})
	}

	fmt.Printf("DPU decommissioned:\n")
	fmt.Printf("  ID:                   %s\n", result.ID)
	fmt.Printf("  Status:               %s\n", result.Status)
	fmt.Printf("  Decommissioned at:    %s\n", result.DecommissionedAt)
	fmt.Printf("  Credentials scrubbed: %d\n", result.CredentialsScrubbed)
	return nil
}

var dpuReactivateCmd = &cobra.Command{
	Use:   "reactivate <name-or-id>",
	Short: "Reactivate a decommissioned DPU",
	Long: `Reactivate a decommissioned DPU by name or ID. This restores the DPU
to 'pending' status and creates a new 24-hour enrollment window.

This command is restricted to super:admin only. Tenant admins cannot
reactivate DPUs. Use this for hardware returning from RMA.

The --reason flag is required and must be at least 20 characters to ensure
proper documentation of the reactivation.

Examples:
  bluectl dpu reactivate bf3-lab --reason "Hardware returned from RMA repair"
  bluectl dpu reactivate bf3-lab --reason "Reinstalled after maintenance window"`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nameOrID := args[0]
		reason, _ := cmd.Flags().GetString("reason")

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return reactivateDPURemote(cmd.Context(), serverURL, nameOrID, reason)
	},
}

func reactivateDPURemote(ctx context.Context, serverURL, nameOrID, reason string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}

	// Get DPU details first for better error messages
	dpu, err := client.GetDPU(ctx, nameOrID)
	if err != nil {
		return fmt.Errorf("DPU not found: %s", nameOrID)
	}

	// Check if not decommissioned
	if dpu.Status != "decommissioned" {
		return fmt.Errorf("DPU '%s' is not decommissioned (status: %s)", dpu.Name, dpu.Status)
	}

	// Validate reason length before API call
	if len(reason) < 20 {
		return fmt.Errorf("reason must be at least 20 characters (got %d)", len(reason))
	}

	result, err := client.ReactivateDPU(ctx, dpu.ID, reason)
	if err != nil {
		return fmt.Errorf("failed to reactivate DPU: %w", err)
	}

	if outputFormat == "json" || outputFormat == "yaml" {
		return formatOutput(map[string]any{
			"status": "reactivated",
			"dpu":    result,
		})
	}

	fmt.Printf("DPU reactivated:\n")
	fmt.Printf("  ID:                  %s\n", result.ID)
	fmt.Printf("  Status:              %s\n", result.Status)
	fmt.Printf("  Reactivated at:      %s\n", result.ReactivatedAt)
	fmt.Printf("  Reactivated by:      %s\n", result.ReactivatedBy)
	fmt.Printf("  Enrollment expires:  %s\n", result.EnrollmentExpiresAt)
	fmt.Println()
	fmt.Println("The DPU can now complete enrollment within the enrollment window.")
	return nil
}
