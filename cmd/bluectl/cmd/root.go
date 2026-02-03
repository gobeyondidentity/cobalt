// Package cmd implements the bluectl CLI commands.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/gobeyondidentity/secure-infra/internal/version"
	"github.com/gobeyondidentity/secure-infra/pkg/clierror"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	// Global flags
	outputFormat string
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
	Use:     "bluectl",
	Short:   "🧊 Fabric Console CLI for DPU management",
	Version: version.Version,
	Long: `bluectl is a command-line interface for managing NVIDIA BlueField DPUs.

It provides commands to register DPUs, query system information,
view OVS flows, and check attestation status.`,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip for completion commands
		if cmd.Name() == "completion" || cmd.Name() == "help" {
			return nil
		}
		return nil
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
	// Add cyan template function for colorizing subcommand names
	cyan := color.New(color.FgCyan).SprintFunc()
	cobra.AddTemplateFunc("cyan", cyan)

	rootCmd.SetUsageTemplate(colorizedUsageTemplate)
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, yaml")
	rootCmd.AddCommand(completionCmd)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

// requireServer returns the server URL or an error if no server is configured.
// Use this at the start of commands that require server mode.
func requireServer() (string, error) {
	serverURL := GetServer()
	if serverURL == "" {
		return "", fmt.Errorf("server connection required\n\nConfigure with: bluectl config set-server <url>\nOr use:        bluectl --server <url> <command>")
	}
	return serverURL, nil
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

// HandleError handles CLI errors with proper output formatting and exit codes.
func HandleError(cmd *cobra.Command, err error) {
	if err == nil {
		return
	}

	outputFormat, _ := cmd.Flags().GetString("output")

	var cliErr *clierror.CLIError
	if e, ok := err.(*clierror.CLIError); ok {
		cliErr = e
	} else {
		cliErr = clierror.InternalError(err)
	}

	clierror.PrintError(cliErr, outputFormat)
	os.Exit(cliErr.ExitCode)
}
