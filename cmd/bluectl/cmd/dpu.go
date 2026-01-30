package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/nmelo/secure-infra/pkg/clierror"
	"github.com/nmelo/secure-infra/pkg/grpcclient"
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

	// Add flags
	dpuAddCmd.Flags().IntP("port", "p", 18051, "gRPC port")
	dpuAddCmd.Flags().StringP("name", "n", "", "DPU name (default: hostname from agent)")
	dpuAddCmd.Flags().Bool("offline", false, "Skip connectivity check and add DPU anyway")
	dpuHealthCmd.Flags().BoolP("verbose", "v", false, "Show detailed component health status")

	// Flags for dpu assign
	dpuAssignCmd.Flags().String("tenant", "", "Tenant to assign the DPU to (required)")
	dpuAssignCmd.MarkFlagRequired("tenant")
}

var dpuCmd = &cobra.Command{
	Use:   "dpu",
	Short: "Manage DPU registrations",
	Long:  `Commands to list, add, remove, and query registered DPUs.`,
}

var dpuListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered DPUs",
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return listDPUsRemote(cmd.Context(), serverURL)
	},
}

func listDPUsRemote(ctx context.Context, serverURL string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}
	dpus, err := client.ListDPUs(ctx)
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
	Args: cobra.ExactArgs(1),
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
	// When using remote server, we always require --name since the server
	// handles connectivity checks and may not be able to reach the DPU directly
	if name == "" {
		// Try to get name from DPU if we can reach it
		if !offline {
			fmt.Printf("Checking connectivity to %s:%d...\n", host, port)
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			grpcClient, err := grpcclient.NewClient(fmt.Sprintf("%s:%d", host, port))
			if err != nil {
				return fmt.Errorf("cannot connect to DPU agent at %s:%d: %w\n\nUse --name to specify a name manually", host, port, err)
			}
			defer grpcClient.Close()

			info, err := grpcClient.GetSystemInfo(checkCtx)
			if err != nil {
				return fmt.Errorf("failed to get DPU system info: %w\n\nUse --name to specify a name manually", err)
			}
			name = info.Hostname
			fmt.Printf("Using hostname from agent: %s\n", name)
		} else {
			return fmt.Errorf("--name is required when using --offline or when server cannot reach DPU")
		}
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
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return removeDPURemote(cmd.Context(), serverURL, args[0])
	},
}

func removeDPURemote(ctx context.Context, serverURL, nameOrID string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}
	if err := client.RemoveDPU(ctx, nameOrID); err != nil {
		return fmt.Errorf("failed to remove DPU from server: %w", err)
	}
	fmt.Printf("Removed DPU '%s'\n", nameOrID)
	return nil
}

var dpuInfoCmd = &cobra.Command{
	Use:     "info <name-or-id>",
	Aliases: []string{"show", "describe"},
	Short:   "Show DPU system information",
	Args:    cobra.ExactArgs(1),
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
	Args: cobra.ExactArgs(1),
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
	Args: cobra.ExactArgs(1),
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
