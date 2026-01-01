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
	rootCmd.AddCommand(inventoryCmd)
}

var inventoryCmd = &cobra.Command{
	Use:   "inventory <dpu>",
	Short: "Show DPU firmware and software inventory",
	Long: `Display detailed firmware versions, installed packages, kernel modules,
and boot configuration for a DPU.

Examples:
  bluectl inventory bf3-lab
  bluectl inventory bf3-lab --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dpu, err := dpuStore.Get(args[0])
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		client, err := grpcclient.NewClient(dpu.Address())
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer client.Close()

		inv, err := client.GetDPUInventory(ctx)
		if err != nil {
			return fmt.Errorf("failed to get inventory: %w", err)
		}

		if outputFormat != "table" {
			return formatOutput(inv)
		}

		// Firmware table
		fmt.Println("FIRMWARE VERSIONS")
		fmt.Println("-----------------")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tVERSION\tBUILD DATE")
		for _, fw := range inv.Firmwares {
			buildDate := fw.BuildDate
			if buildDate == "" {
				buildDate = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", fw.Name, fw.Version, buildDate)
		}
		w.Flush()

		// Boot info
		fmt.Println("\nBOOT CONFIGURATION")
		fmt.Println("------------------")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if inv.Boot != nil {
			fmt.Fprintf(w, "UEFI Mode:\t%v\n", inv.Boot.UefiMode)
			fmt.Fprintf(w, "Secure Boot:\t%v\n", inv.Boot.SecureBoot)
			fmt.Fprintf(w, "Boot Device:\t%s\n", inv.Boot.BootDevice)
		}
		fmt.Fprintf(w, "Operation Mode:\t%s\n", inv.OperationMode)
		w.Flush()

		// Packages (show count if many)
		fmt.Println("\nINSTALLED PACKAGES")
		fmt.Println("------------------")
		if len(inv.Packages) == 0 {
			fmt.Println("No DOCA/MLNX packages found")
		} else {
			w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tVERSION")
			// Show first 20 packages in table mode
			limit := 20
			if len(inv.Packages) < limit {
				limit = len(inv.Packages)
			}
			for i := 0; i < limit; i++ {
				pkg := inv.Packages[i]
				fmt.Fprintf(w, "%s\t%s\n", pkg.Name, pkg.Version)
			}
			w.Flush()
			if len(inv.Packages) > limit {
				fmt.Printf("... and %d more (use --output json for full list)\n", len(inv.Packages)-limit)
			}
		}

		// Kernel modules (show count if many)
		fmt.Println("\nKERNEL MODULES")
		fmt.Println("--------------")
		if len(inv.Modules) == 0 {
			fmt.Println("No Mellanox/RDMA modules found")
		} else {
			w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSIZE\tUSED BY")
			// Show first 20 modules in table mode
			limit := 20
			if len(inv.Modules) < limit {
				limit = len(inv.Modules)
			}
			for i := 0; i < limit; i++ {
				mod := inv.Modules[i]
				fmt.Fprintf(w, "%s\t%s\t%d\n", mod.Name, mod.Size, mod.UsedBy)
			}
			w.Flush()
			if len(inv.Modules) > limit {
				fmt.Printf("... and %d more (use --output json for full list)\n", len(inv.Modules)-limit)
			}
		}

		// Update DPU status
		dpuStore.UpdateStatus(dpu.ID, "healthy")

		return nil
	},
}
