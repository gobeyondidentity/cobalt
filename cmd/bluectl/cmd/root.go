// Package cmd implements the bluectl CLI commands.
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
	Use:   "bluectl",
	Short: "Fabric Console CLI for DPU management",
	Long: `bluectl is a command-line interface for managing NVIDIA BlueField DPUs.

It provides commands to register DPUs, query system information,
view OVS flows, and check attestation status.`,
	Version:      Version,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip store initialization for completion commands
		if cmd.Name() == "completion" || cmd.Name() == "help" {
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

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for bluectl.

To load completions:

Bash:
  # Add to ~/.bashrc:
  source <(bluectl completion bash)

  # Or install system-wide (Linux):
  bluectl completion bash > /etc/bash_completion.d/bluectl

Zsh:
  # Add to ~/.zshrc:
  source <(bluectl completion zsh)

  # Or if using oh-my-zsh, add to ~/.oh-my-zsh/completions/:
  bluectl completion zsh > ~/.oh-my-zsh/completions/_bluectl

Fish:
  # Add to ~/.config/fish/completions/:
  bluectl completion fish > ~/.config/fish/completions/bluectl.fish

PowerShell:
  # Add to your PowerShell profile:
  bluectl completion powershell | Out-String | Invoke-Expression`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		default:
			return fmt.Errorf("unknown shell: %s", args[0])
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, yaml")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "Database path (default: ~/.local/share/bluectl/dpus.db)")
	rootCmd.AddCommand(completionCmd)
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
