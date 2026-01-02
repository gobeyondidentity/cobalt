// Package cmd implements the keymaker CLI commands.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nmelo/secure-infra/pkg/store"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	// Version is set at build time
	Version = "0.1.0"

	// Global flags
	outputFormat string
	dbPath       string

	// Shared store instance
	dpuStore *store.Store
)

var rootCmd = &cobra.Command{
	Use:   "km",
	Short: "Keymaker - Credential management for Secure Infrastructure",
	Long: `km (keymaker) is a command-line interface for credential management.

It provides commands to create and manage SSH Certificate Authorities,
distribute credentials to DPUs with attestation gates, and view
distribution history.`,
	Version:      Version,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip store initialization for commands that don't need it
		if cmd.Name() == "completion" || cmd.Name() == "help" || cmd.Name() == "init" || cmd.Name() == "whoami" {
			return nil
		}

		// Initialize store
		path := dbPath
		if path == "" {
			path = store.DefaultPath()
		}

		var err error
		dpuStore, err = store.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if dpuStore != nil {
			dpuStore.Close()
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, yaml")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "Database path (default: ~/.local/share/bluectl/dpus.db)")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

// formatOutput handles output formatting based on the --output flag.
func formatOutput(data interface{}) error {
	switch outputFormat {
	case "json":
		return outputJSON(data)
	case "yaml":
		return outputYAML(data)
	default:
		// Table format is handled by each command
		return nil
	}
}

func outputJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func outputYAML(data interface{}) error {
	out, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	fmt.Print(string(out))
	return nil
}
