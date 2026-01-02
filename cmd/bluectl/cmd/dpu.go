package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
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

	// Add flags
	dpuAddCmd.Flags().IntP("port", "p", 50051, "gRPC port")
	dpuAddCmd.Flags().Bool("offline", false, "Skip connectivity check and add DPU anyway")
	dpuHealthCmd.Flags().BoolP("verbose", "v", false, "Show detailed component health status")
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
		dpus, err := dpuStore.List()
		if err != nil {
			return err
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
		fmt.Fprintln(w, "NAME\tHOST\tPORT\tSTATUS\tLAST SEEN")
		for _, dpu := range dpus {
			lastSeen := "never"
			if dpu.LastSeen != nil {
				lastSeen = dpu.LastSeen.Format(time.RFC3339)
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
				dpu.Name, dpu.Host, dpu.Port, dpu.Status, lastSeen)
		}
		w.Flush()
		return nil
	},
}

var dpuAddCmd = &cobra.Command{
	Use:   "add <name> <host>",
	Short: "Register a new DPU",
	Long: `A DPU (Data Processing Unit) is a smart NIC installed inside a host server.
The DPU Agent runs on the DPU itself. Credentials are distributed to the
host server through the paired Host Agent.

Register a new DPU with a name and host address.

The host is the DPU's gRPC agent address (IP or hostname). This is the DPU's management
interface where the agent runs on the ARM cores, NOT the BMC address. The agent listens
on port 50051 by default.

By default, registration requires a successful connectivity check to the DPU agent.
Use --offline to register a DPU that is not currently reachable.

Examples:
  bluectl dpu add bf3-lab 192.168.1.204              # IP address, default port 50051
  bluectl dpu add bf3-lab 192.168.1.204 --offline    # Skip connectivity check
  bluectl dpu add bf3-prod dpu.example.com           # Hostname, default port
  bluectl dpu add bf3-dev 10.0.0.50 --port 50052     # Custom port`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		host := args[1]
		port, _ := cmd.Flags().GetInt("port")
		offline, _ := cmd.Flags().GetBool("offline")

		// Check for duplicate address:port - idempotent: return success if exists
		existing, err := dpuStore.GetDPUByAddress(host, port)
		if err != nil {
			return fmt.Errorf("failed to check for duplicates: %w", err)
		}
		if existing != nil {
			if outputFormat == "json" || outputFormat == "yaml" {
				return formatOutput(map[string]any{
					"status": "already_exists",
					"dpu":    existing,
				})
			}
			fmt.Printf("DPU already exists at %s:%d: %s\n", host, port, existing.Name)
			return nil
		}

		// Check connectivity BEFORE adding (unless --offline)
		var status string
		if offline {
			status = "offline"
			fmt.Printf("Skipping connectivity check (--offline)\n")
		} else {
			fmt.Printf("Checking connectivity to %s:%d...\n", host, port)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			client, err := grpcclient.NewClient(fmt.Sprintf("%s:%d", host, port))
			if err != nil {
				return fmt.Errorf("cannot connect to DPU agent at %s:%d: %w\n\nUse --offline to add without connectivity check", host, port, err)
			}
			defer client.Close()

			if _, err := client.HealthCheck(ctx); err != nil {
				return fmt.Errorf("DPU agent health check failed at %s:%d: %w\n\nUse --offline to add without connectivity check", host, port, err)
			}

			status = "healthy"
			fmt.Println("Connection verified: agent is healthy")
		}

		// Now add the DPU
		id := uuid.New().String()[:8]
		if err := dpuStore.Add(id, name, host, port); err != nil {
			return fmt.Errorf("failed to add DPU: %w", err)
		}
		dpuStore.UpdateStatus(id, status)

		// Get the created DPU for output
		created, _ := dpuStore.Get(name)

		if outputFormat == "json" || outputFormat == "yaml" {
			return formatOutput(map[string]any{
				"status": "created",
				"dpu":    created,
			})
		}

		fmt.Printf("Added DPU '%s' at %s:%d (id: %s)\n", name, host, port, id)
		fmt.Println()
		fmt.Printf("Next: Assign to a tenant with 'bluectl tenant assign <tenant> %s'\n", name)

		return nil
	},
}

var dpuRemoveCmd = &cobra.Command{
	Use:   "remove <name-or-id>",
	Short: "Remove a registered DPU",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := dpuStore.Remove(args[0]); err != nil {
			return err
		}
		fmt.Printf("Removed DPU '%s'\n", args[0])
		return nil
	},
}

var dpuInfoCmd = &cobra.Command{
	Use:     "info <name-or-id>",
	Aliases: []string{"show", "describe"},
	Short:   "Show DPU system information",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dpu, err := dpuStore.Get(args[0])
		if err != nil {
			return clierror.DeviceNotFound(args[0])
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := grpcclient.NewClient(dpu.Address())
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer client.Close()

		info, err := client.GetSystemInfo(ctx)
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

		// Update status
		dpuStore.UpdateStatus(dpu.ID, "healthy")

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

	dpu, err := dpuStore.Get(args[0])
	if err != nil {
		return err
	}

	fmt.Printf("DPU: %s (%s)\n", dpu.Name, dpu.Address())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		dpuStore.UpdateStatus(dpu.ID, "offline")
		fmt.Println("Status: offline")
		fmt.Printf("Error: %v\n", err)
		fmt.Println()
		fmt.Println("Troubleshooting:")
		fmt.Printf("  - Verify DPU is powered on and network is connected\n")
		fmt.Printf("  - Check firewall allows port %d\n", dpu.Port)
		fmt.Printf("  - Try: ping %s\n", dpu.Host)
		return nil
	}
	defer client.Close()

	resp, err := client.HealthCheck(ctx)
	latency := time.Since(start)

	if err != nil {
		dpuStore.UpdateStatus(dpu.ID, "unhealthy")
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
	dpuStore.UpdateStatus(dpu.ID, status)

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
