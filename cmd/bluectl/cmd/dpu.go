package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/nmelo/secure-infra/pkg/grpcclient"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(dpuCmd)
	dpuCmd.AddCommand(dpuListCmd)
	dpuCmd.AddCommand(dpuAddCmd)
	dpuCmd.AddCommand(dpuRemoveCmd)
	dpuCmd.AddCommand(dpuInfoCmd)

	// Add flags
	dpuAddCmd.Flags().IntP("port", "p", 50051, "gRPC port")
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

		if outputFormat != "table" {
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
	Long: `Register a new DPU with a name and host address.

The host is the DPU's gRPC agent address (IP or hostname). This is the DPU's management
interface where the agent runs on the ARM cores, NOT the BMC address. The agent listens
on port 50051 by default.

After registration, the CLI verifies connectivity by performing a health check against
the agent. Use 'bluectl tenant assign' to associate the DPU with a tenant.

Examples:
  bluectl dpu add bf3-lab 192.168.1.204              # IP address, default port 50051
  bluectl dpu add bf3-prod dpu.example.com           # Hostname, default port
  bluectl dpu add bf3-dev 10.0.0.50 --port 50052     # Custom port`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		host := args[1]
		port, _ := cmd.Flags().GetInt("port")

		id := uuid.New().String()[:8]

		if err := dpuStore.Add(id, name, host, port); err != nil {
			return fmt.Errorf("failed to add DPU: %w", err)
		}

		fmt.Printf("Added DPU '%s' at %s:%d (id: %s)\n", name, host, port, id)

		// Try to connect and update status
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		client, err := grpcclient.NewClient(fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			dpuStore.UpdateStatus(id, "offline")
			fmt.Printf("Warning: Could not connect to agent: %v\n", err)
			return nil
		}
		defer client.Close()

		if _, err := client.HealthCheck(ctx); err != nil {
			dpuStore.UpdateStatus(id, "unhealthy")
			fmt.Printf("Warning: Health check failed: %v\n", err)
		} else {
			dpuStore.UpdateStatus(id, "healthy")
			fmt.Println("Connection verified: agent is healthy")
		}

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
			return err
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
