package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/nmelo/secure-infra/pkg/grpcclient"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(flowsCmd)
	flowsCmd.Flags().StringP("bridge", "b", "", "Bridge name (default: all bridges)")
}

var flowsCmd = &cobra.Command{
	Use:   "flows <dpu-name-or-id>",
	Short: "Show network flow rules from the DPU's software switch",
	Long: `Display OpenFlow rules from a DPU's OVS (Open vSwitch) bridges.

OVS flows define how the DPU routes network traffic. Each flow specifies match criteria
(e.g., source IP, port, VLAN) and actions (e.g., forward, drop, modify headers).
Use this command to inspect and debug network behavior on the DPU.

Examples:
  bluectl flows bf3-lab
  bluectl flows bf3-lab --bridge ovsbr1
  bluectl flows bf3-lab -o json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		nexus := NewNexusClient(serverURL)

		dpu, err := nexus.GetDPU(cmd.Context(), args[0])
		if err != nil {
			return err
		}

		bridge, _ := cmd.Flags().GetString("bridge")

		ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer cancel()

		client, err := grpcclient.NewClient(fmt.Sprintf("%s:%d", dpu.Host, dpu.Port))
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

		return nil
	},
}
