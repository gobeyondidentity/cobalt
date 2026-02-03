package cmd

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(whoamiCmd)
}

// WhoamiOutput represents the JSON/YAML output for whoami command.
type WhoamiOutput struct {
	Identity    string `json:"identity" yaml:"identity"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	ServerURL   string `json:"server_url,omitempty" yaml:"server_url,omitempty"`
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current authenticated identity",
	Long: `Display the current authenticated identity for bluectl.

Shows the admin key ID, key fingerprint, and configured server URL.
Returns a non-zero exit code if not authenticated.

Examples:
  bluectl whoami
  bluectl whoami -o json`,
	RunE: runWhoami,
}

func runWhoami(cmd *cobra.Command, args []string) error {
	keyPath, kidPath := dpop.DefaultKeyPaths("bluectl")
	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)

	// Check if enrolled
	if !keyStore.Exists() || !kidStore.Exists() {
		fmt.Fprintln(os.Stderr, "Error: Not authenticated.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Run 'bluectl init' to enroll as the first admin,")
		fmt.Fprintln(os.Stderr, "or use an invite code from your administrator.")
		os.Exit(2)
	}

	// Load key ID
	kid, err := kidStore.Load()
	if err != nil {
		return fmt.Errorf("failed to load identity: %w", err)
	}

	// Load private key to compute fingerprint
	privKey, err := keyStore.Load()
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}

	// Compute fingerprint (SHA256 of public key)
	pubKey := privKey.Public().(ed25519.PublicKey)
	hash := sha256.Sum256(pubKey)
	fingerprint := hex.EncodeToString(hash[:])

	// Get server URL from config
	serverURL := GetServer()

	output := WhoamiOutput{
		Identity:    kid,
		Fingerprint: fingerprint,
		ServerURL:   serverURL,
	}

	// Handle JSON/YAML output
	if outputFormat != "table" {
		return formatOutput(output)
	}

	// Table output
	fmt.Printf("Identity:    %s\n", kid)
	fmt.Printf("Fingerprint: %s\n", fingerprint)
	if serverURL != "" {
		fmt.Printf("Server:      %s\n", serverURL)
	} else {
		fmt.Printf("Server:      (not configured)\n")
	}

	return nil
}
