package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Config represents the bluectl configuration.
type Config struct {
	Server string `yaml:"server,omitempty"`
}

// Global server flag (overrides config file)
var serverFlag string

func init() {
	// Add --server flag to root command
	rootCmd.PersistentFlags().StringVar(&serverFlag, "server", "", "Nexus server URL (overrides config file)")

	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configSetServerCmd)
	configCmd.AddCommand(configGetServerCmd)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage bluectl configuration",
	Long: `Commands to configure bluectl settings.

The configuration file is stored at ~/.config/bluectl/config.yaml

Examples:
  bluectl config set-server http://nexus.example.com:18080
  bluectl config get-server`,
}

// ConfigPath returns the path to the config file.
func ConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "bluectl", "config.yaml")
}

// LoadConfig reads the configuration from disk.
// Returns an empty config if the file doesn't exist.
func LoadConfig() (*Config, error) {
	path := ConfigPath()
	if path == "" {
		return &Config{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// SaveConfig writes the configuration to disk.
func SaveConfig(cfg *Config) error {
	path := ConfigPath()
	if path == "" {
		return fmt.Errorf("could not determine home directory")
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetServer returns the server URL using the following precedence:
// 1. --server flag (highest priority)
// 2. SERVER_URL environment variable
// 3. Config file
func GetServer() string {
	// 1. Flag takes highest precedence
	if serverFlag != "" {
		return serverFlag
	}

	// 2. Check SERVER_URL env var
	if url := os.Getenv("SERVER_URL"); url != "" {
		return url
	}

	// 3. Fall back to config file
	cfg, err := LoadConfig()
	if err != nil {
		return ""
	}

	return cfg.Server
}

var configSetServerCmd = &cobra.Command{
	Use:   "set-server <url>",
	Short: "Set the Nexus server URL",
	Long: `Configure the default Nexus server URL for bluectl commands.

The server URL is saved to ~/.config/bluectl/config.yaml and used
by all commands that communicate with the control plane.

Use the --server flag on any command to temporarily override this setting.

Examples:
  bluectl config set-server http://nexus.example.com:18080
  bluectl config set-server https://nexus.internal:443`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := args[0]

		cfg, err := LoadConfig()
		if err != nil {
			return err
		}

		cfg.Server = serverURL

		if err := SaveConfig(cfg); err != nil {
			return err
		}

		fmt.Printf("Server set to: %s\n", serverURL)
		fmt.Printf("Config saved to: %s\n", ConfigPath())
		return nil
	},
}

var configGetServerCmd = &cobra.Command{
	Use:   "get-server",
	Short: "Display the configured Nexus server URL",
	Long: `Show the current Nexus server URL from the configuration file.

If no server is configured, this command displays a message indicating
that no server has been set.

Examples:
  bluectl config get-server`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := LoadConfig()
		if err != nil {
			return err
		}

		if cfg.Server == "" {
			fmt.Println("No server configured.")
			fmt.Println()
			fmt.Println("Set one with: bluectl config set-server <url>")
			return nil
		}

		if outputFormat == "json" || outputFormat == "yaml" {
			return formatOutput(map[string]string{"server": cfg.Server})
		}

		fmt.Printf("Server: %s\n", cfg.Server)
		return nil
	},
}
