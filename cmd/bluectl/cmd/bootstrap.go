package cmd

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().Bool("force", false, "Force re-enrollment (removes existing identity)")
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize bluectl and enroll as first admin",
	Long: `Initialize bluectl by enrolling as the first admin on the nexus server.

This command is used during initial setup to enroll the first administrator.
It must be run within 10 minutes of starting the nexus server for the first time.

The command will:
1. Generate a new Ed25519 keypair
2. Request a challenge from the server
3. Sign the challenge with the private key
4. Complete enrollment and save the identity

Use --force to re-enroll if already configured (removes existing identity).

Prerequisites:
- Nexus server must be running
- Bootstrap window must be open (within 10 minutes of first server start)
- No other admin has been enrolled yet

Examples:
  bluectl init
  bluectl init --server https://nexus.example.com:18080
  bluectl init --force  # Re-enroll (removes existing identity)`,
	RunE: runInit,
}

// bootstrapRequest is the request body for POST /api/v1/admin/bootstrap
type bootstrapRequest struct {
	PublicKey string `json:"public_key"`
}

// bootstrapResponse is the response from POST /api/v1/admin/bootstrap
type bootstrapResponse struct {
	Challenge    string `json:"challenge"`
	EnrollmentID string `json:"enrollment_id"`
}

// enrollCompleteRequest is the request body for POST /api/v1/enroll/complete
type enrollCompleteRequest struct {
	EnrollmentID    string `json:"enrollment_id"`
	PublicKey       string `json:"public_key"`
	SignedChallenge string `json:"signed_challenge"`
}

// enrollCompleteResponse is the response from POST /api/v1/enroll/complete
type enrollCompleteResponse struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

// errorResponse represents an error response from the API
type errorResponse struct {
	Error string `json:"error"`
}

func runInit(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")

	// Get server URL
	serverURL := GetServer()
	if serverURL == "" {
		// Prompt for server URL if not configured
		fmt.Print("Enter nexus server URL: ")
		reader := bufio.NewReader(os.Stdin)
		url, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read server URL: %w", err)
		}
		serverURL = strings.TrimSpace(url)
		if serverURL == "" {
			return fmt.Errorf("server URL is required")
		}
	}

	// Check if already enrolled
	keyPath, kidPath := dpop.DefaultKeyPaths("bluectl")
	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)
	idCfg := dpop.IdentityConfig{
		KeyStore:  keyStore,
		KIDStore:  kidStore,
		ServerURL: serverURL,
	}

	if dpop.IsEnrolled(idCfg) {
		if !force {
			return fmt.Errorf("already enrolled. Use --force to re-enroll")
		}
		fmt.Println("Removing existing identity (--force)...")
		// Remove existing key and kid files
		if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove existing key: %w", err)
		}
		if err := os.Remove(kidPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove existing kid: %w", err)
		}
	}

	fmt.Println("Generating keypair...")

	// Generate new keypair using dpop utilities
	pubKey, privKey, err := dpop.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Encode public key as base64
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKey)

	fmt.Println("Requesting bootstrap challenge...")

	// POST /api/v1/admin/bootstrap
	bootstrapReq := bootstrapRequest{
		PublicKey: pubKeyBase64,
	}
	reqBody, err := json.Marshal(bootstrapReq)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	resp, err := http.Post(
		serverURL+"/api/v1/admin/bootstrap",
		"application/json",
		strings.NewReader(string(reqBody)),
	)
	if err != nil {
		return fmt.Errorf("cannot connect to server at %s: %w\nVerify the URL and check your network connection", serverURL, err)
	}
	defer resp.Body.Close()

	// Handle bootstrap-specific errors
	if resp.StatusCode == http.StatusForbidden {
		var errResp errorResponse
		json.NewDecoder(resp.Body).Decode(&errResp)

		switch errResp.Error {
		case "bootstrap.window_closed":
			fmt.Fprintln(os.Stderr, "Error: Bootstrap window closed.")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "The 10-minute bootstrap window has expired. To retry:")
			fmt.Fprintln(os.Stderr, "1. Restart the nexus server")
			fmt.Fprintln(os.Stderr, "2. Run `bluectl init` within 10 minutes")
			return fmt.Errorf("bootstrap window closed")

		case "bootstrap.already_enrolled":
			fmt.Fprintln(os.Stderr, "Error: First admin already enrolled.")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "Bootstrap is complete. Ask an existing admin to invite you:")
			fmt.Fprintln(os.Stderr, "  bluectl operator invite --email you@example.com")
			return fmt.Errorf("first admin already enrolled")
		}

		return fmt.Errorf("bootstrap failed: %s", errResp.Error)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return fmt.Errorf("bootstrap failed: %s", errResp.Error)
		}
		return fmt.Errorf("bootstrap failed: HTTP %d", resp.StatusCode)
	}

	var bootResp bootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&bootResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Println("Signing challenge...")

	// Decode challenge (base64-encoded raw bytes)
	challengeBytes, err := base64.StdEncoding.DecodeString(bootResp.Challenge)
	if err != nil {
		return fmt.Errorf("failed to decode challenge: %w", err)
	}

	// Sign the challenge with the private key
	signature := ed25519.Sign(privKey, challengeBytes)
	signedChallengeBase64 := base64.StdEncoding.EncodeToString(signature)

	fmt.Println("Completing enrollment...")

	// POST /api/v1/enroll/complete
	completeReq := enrollCompleteRequest{
		EnrollmentID:    bootResp.EnrollmentID,
		PublicKey:       pubKeyBase64,
		SignedChallenge: signedChallengeBase64,
	}
	completeBody, err := json.Marshal(completeReq)
	if err != nil {
		return fmt.Errorf("failed to encode complete request: %w", err)
	}

	completeResp, err := http.Post(
		serverURL+"/api/v1/enroll/complete",
		"application/json",
		strings.NewReader(string(completeBody)),
	)
	if err != nil {
		return fmt.Errorf("failed to complete enrollment: %w", err)
	}
	defer completeResp.Body.Close()

	if completeResp.StatusCode != http.StatusOK {
		var errResp errorResponse
		json.NewDecoder(completeResp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return fmt.Errorf("enrollment failed: %s", errResp.Error)
		}
		return fmt.Errorf("enrollment failed: HTTP %d", completeResp.StatusCode)
	}

	var enrollResp enrollCompleteResponse
	if err := json.NewDecoder(completeResp.Body).Decode(&enrollResp); err != nil {
		return fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	fmt.Println("Saving identity...")

	// Save the identity using dpop utilities
	if err := dpop.CompleteEnrollment("bluectl", privKey, enrollResp.ID); err != nil {
		return fmt.Errorf("failed to save identity: %w", err)
	}

	// Save server URL to config
	cfg, err := LoadConfig()
	if err != nil {
		cfg = &Config{}
	}
	cfg.Server = serverURL
	if err := SaveConfig(cfg); err != nil {
		// Non-fatal, identity is saved
		fmt.Fprintf(os.Stderr, "Warning: failed to save server URL to config: %v\n", err)
	}

	fmt.Println()
	fmt.Println("Enrollment complete.")
	fmt.Printf("  Admin ID:    %s\n", enrollResp.ID)
	fmt.Printf("  Fingerprint: %s\n", enrollResp.Fingerprint)
	fmt.Printf("  Server:      %s\n", serverURL)
	fmt.Println()
	fmt.Println("Identity saved. You can now use bluectl commands to manage the system.")

	return nil
}
