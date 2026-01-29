// Package cmd implements the keymaker CLI commands.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/nmelo/secure-infra/internal/version"
	"github.com/nmelo/secure-infra/pkg/clierror"
	"github.com/nmelo/secure-infra/pkg/store"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	// Global flags
	outputFormat string
	dbPath       string
	insecure     bool

	// Shared store instance
	dpuStore *store.Store
)

// colorizedUsageTemplate is a custom usage template that colorizes subcommand names in cyan.
// fatih/color handles NO_COLOR env var automatically.
const colorizedUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{cyan (rpad .Name .NamePadding)}} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{cyan (rpad .Name .NamePadding)}} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{cyan (rpad .Name .NamePadding)}} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

var rootCmd = &cobra.Command{
	Use:   "km",
	Short: "🔑 Keymaker - Credential management for Secure Infrastructure",
	Long: `km (keymaker) securely manages and pushes credentials to DPUs and hosts.

Credential types:
  - SSH CA:    Certificate authorities for passwordless SSH authentication
  - Host Cert: Certificates for machine-to-machine SSH trust
  - (Future)   TLS certificates, MUNGE keys, API keys

All credentials are hardware-protected using TPM or Secure Enclave when available.
Push requires fresh attestation from the target DPU, ensuring credentials
only reach devices with verified firmware integrity.

Getting started:
  1. Bind your workstation: km init
  2. Create an SSH CA:      km ssh-ca create ops-ca
  3. Push to a DPU:         km push ssh-ca ops-ca target-dpu
  4. View history:          km history`,
	Version:      version.Version,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip store initialization for commands that don't need it
		if cmd.Name() == "completion" || cmd.Name() == "help" || cmd.Name() == "init" || cmd.Name() == "whoami" || cmd.Name() == "version" {
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

		// Handle insecure mode flag (only meaningful if user explicitly requests it)
		if insecure {
			store.SetInsecureMode(true)
			fmt.Fprintln(os.Stderr, "WARNING: Operating in insecure mode. Private keys are NOT encrypted.")
		}
		// Note: With auto-generation, IsEncryptionEnabled() is always true
		// unless there's a file system error. The encryption key auto-generates
		// at ~/.local/share/bluectl/key on first run.
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if dpuStore != nil {
			dpuStore.Close()
		}
	},
}

func init() {
	// Add cyan template function for colorizing subcommand names
	cyan := color.New(color.FgCyan).SprintFunc()
	cobra.AddTemplateFunc("cyan", cyan)

	rootCmd.SetUsageTemplate(colorizedUsageTemplate)
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, yaml")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "Database path (default: ~/.local/share/bluectl/dpus.db)")
	rootCmd.PersistentFlags().BoolVar(&insecure, "insecure", false, "Allow plaintext key storage (INSECURE: use only for development)")
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

// handleError handles command errors with proper exit codes and structured output.
// It checks if the error is already a CLIError and formats it appropriately,
// otherwise wraps unknown errors as InternalError.
func handleError(cmd *cobra.Command, err error) {
	format, _ := cmd.Flags().GetString("output")

	// Check if it's already a CLIError
	if cliErr, ok := err.(*clierror.CLIError); ok {
		clierror.PrintError(cliErr, format)
		os.Exit(cliErr.ExitCode)
	}

	// Wrap unknown errors as InternalError
	cliErr := clierror.InternalError(err)
	clierror.PrintError(cliErr, format)
	os.Exit(cliErr.ExitCode)
}
