package cmd

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(authStatusCmd)
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication management",
	Long:  "Commands for managing authentication state and diagnostics.",
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication status",
	Long: `Show the current authentication status including:
  - Enrollment state (enrolled or not enrolled)
  - Key file path and whether it exists
  - Server URL configured
  - Server connectivity (reachable or unreachable)`,
	RunE: runAuthStatus,
}

// AuthStatus represents the authentication status for JSON/YAML output.
type AuthStatus struct {
	Enrolled    bool   `json:"enrolled" yaml:"enrolled"`
	KeyPath     string `json:"key_path" yaml:"key_path"`
	KeyExists   bool   `json:"key_exists" yaml:"key_exists"`
	KIDPath     string `json:"kid_path" yaml:"kid_path"`
	KIDExists   bool   `json:"kid_exists" yaml:"kid_exists"`
	ServerURL   string `json:"server_url,omitempty" yaml:"server_url,omitempty"`
	ServerOK    bool   `json:"server_reachable" yaml:"server_reachable"`
	ServerError string `json:"server_error,omitempty" yaml:"server_error,omitempty"`
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	status := AuthStatus{}

	// Get key paths for km client type
	keyPath, kidPath := dpop.DefaultKeyPaths("km")
	status.KeyPath = keyPath
	status.KIDPath = kidPath

	// Check if key exists
	keyStore := dpop.NewFileKeyStore(keyPath)
	status.KeyExists = keyStore.Exists()

	// Check if KID exists
	kidStore := dpop.NewFileKIDStore(kidPath)
	status.KIDExists = kidStore.Exists()

	// Enrollment requires both key and KID
	status.Enrolled = status.KeyExists && status.KIDExists

	// Try to load config for server URL
	config, err := loadConfig()
	if err == nil && config != nil {
		status.ServerURL = config.ServerURL
	}

	// Check server connectivity if we have a URL
	if status.ServerURL != "" {
		status.ServerOK, status.ServerError = checkServerConnectivity(status.ServerURL)
	}

	// Handle non-table output formats
	if outputFormat != "table" {
		return formatOutput(status)
	}

	// Table output
	fmt.Println("Authentication Status")
	fmt.Println()

	// Enrollment state
	if status.Enrolled {
		fmt.Println("  Enrollment:  enrolled")
	} else {
		fmt.Println("  Enrollment:  not enrolled")
		if !status.KeyExists {
			fmt.Printf("               (key missing: %s)\n", status.KeyPath)
		}
		if !status.KIDExists {
			fmt.Printf("               (kid missing: %s)\n", status.KIDPath)
		}
	}

	// Key file
	if status.KeyExists {
		fmt.Printf("  Key file:    %s (exists)\n", status.KeyPath)
	} else {
		fmt.Printf("  Key file:    %s (missing)\n", status.KeyPath)
	}

	// Server URL
	if status.ServerURL != "" {
		fmt.Printf("  Server:      %s\n", status.ServerURL)

		// Connectivity
		if status.ServerOK {
			fmt.Println("  Connectivity: reachable")
		} else {
			fmt.Printf("  Connectivity: unreachable (%s)\n", status.ServerError)
		}
	} else {
		fmt.Println("  Server:      (not configured)")
		fmt.Println("  Connectivity: (no server configured)")
	}

	// Hint for next steps
	fmt.Println()
	if !status.Enrolled {
		fmt.Println("Run 'km init' to enroll this operator.")
	}

	return nil
}

// checkServerConnectivity performs a basic health check against the server.
func checkServerConnectivity(serverURL string) (bool, string) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Try a simple GET to the health endpoint (or root if no health endpoint)
	resp, err := client.Get(serverURL + "/health")
	if err != nil {
		// Try root as fallback
		resp, err = client.Get(serverURL + "/")
		if err != nil {
			if os.IsTimeout(err) {
				return false, "connection timed out"
			}
			return false, "connection failed"
		}
	}
	defer resp.Body.Close()

	// Any response means the server is reachable
	return true, ""
}
