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
	rootCmd.AddCommand(flowsCmd)
	flowsCmd.Flags().StringP("bridge", "b", "", "Bridge name (default: all bridges)")
}

var flowsCmd = &cobra.Command{
	Use:   "flows <dpu-name-or-id>",
	Short: "Show OVS flows for a DPU",
	Long: `Display OpenFlow rules from a DPU's OVS bridges.

Examples:
  bluectl flows bf3-lab
  bluectl flows bf3-lab --bridge ovsbr1
  bluectl flows bf3-lab -o json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dpu, err := dpuStore.Get(args[0])
		if err != nil {
			return err
		}

		bridge, _ := cmd.Flags().GetString("bridge")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := grpcclient.NewClient(dpu.Address())
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer client.Close()

		resp, err := client.GetFlows(ctx, bridge)
		if err != nil {
			return fmt.Errorf("failed to get flows: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(resp.Flows)
		}

		if len(resp.Flows) == 0 {
			fmt.Println("No flows found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TABLE\tPRIORITY\tMATCH\tACTIONS\tPKTS\tBYTES")
		for _, flow := range resp.Flows {
			match := flow.Match
			if match == "" {
				match = "*"
			}
			// Truncate long matches for table display
			if len(match) > 40 {
				match = match[:37] + "..."
			}
			actions := flow.Actions
			if len(actions) > 30 {
				actions = actions[:27] + "..."
			}
			fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%d\t%d\n",
				flow.Table, flow.Priority, match, actions, flow.Packets, flow.Bytes)
		}
		w.Flush()

		dpuStore.UpdateStatus(dpu.ID, "healthy")
		return nil
	},
}
