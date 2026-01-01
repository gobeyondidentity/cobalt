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
	rootCmd.AddCommand(healthCmd)
}

var healthCmd = &cobra.Command{
	Use:   "health <dpu-name-or-id>",
	Short: "Check DPU agent health",
	Long: `Check connectivity and component health of a DPU agent.

Examples:
  bluectl health bf3-lab
  bluectl health bf3-lab -o json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dpu, err := dpuStore.Get(args[0])
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := grpcclient.NewClient(dpu.Address())
		if err != nil {
			dpuStore.UpdateStatus(dpu.ID, "offline")
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer client.Close()

		resp, err := client.HealthCheck(ctx)
		if err != nil {
			dpuStore.UpdateStatus(dpu.ID, "unhealthy")
			return fmt.Errorf("health check failed: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(resp)
		}

		status := "HEALTHY"
		if !resp.Healthy {
			status = "UNHEALTHY"
		}

		fmt.Printf("Status: %s\n", status)
		fmt.Printf("Version: %s\n", resp.Version)
		fmt.Printf("Uptime: %s\n", formatDuration(resp.UptimeSeconds))
		fmt.Println()

		if len(resp.Components) > 0 {
			fmt.Println("Components:")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "COMPONENT\tSTATUS\tMESSAGE")
			for name, comp := range resp.Components {
				compStatus := "OK"
				if !comp.Healthy {
					compStatus = "FAIL"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", name, compStatus, comp.Message)
			}
			w.Flush()
		}

		if resp.Healthy {
			dpuStore.UpdateStatus(dpu.ID, "healthy")
		} else {
			dpuStore.UpdateStatus(dpu.ID, "unhealthy")
		}

		return nil
	},
}
