package cmd

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nmelo/secure-infra/internal/version"
	"github.com/nmelo/secure-infra/pkg/dpop"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(whoamiCmd)

	initCmd.Flags().String("name", "", "Custom name for this KeyMaker")
	initCmd.Flags().String("server", "http://localhost:18080", "Control Plane URL (env: KM_SERVER)")
	initCmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")
	initCmd.Flags().String("invite-code", "", "Invite code (will prompt if not provided)")
	initCmd.Flags().Bool("force", false, "Force re-initialization (removes existing config)")

	whoamiCmd.Flags().BoolP("verbose", "v", false, "Show internal IDs")
}

// KMConfig is stored in ~/.km/config.json
type KMConfig struct {
	KID             string `json:"kid"`               // Server-assigned key ID (e.g., "km_xxx")
	ControlPlaneURL string `json:"control_plane_url"` // Server URL
	// Legacy fields for backward compatibility
	KeyMakerID    string `json:"keymaker_id,omitempty"`
	OperatorID    string `json:"operator_id,omitempty"`
	OperatorEmail string `json:"operator_email,omitempty"`
}

// getConfigDirFunc is a variable to allow testing with a custom directory
var getConfigDirFunc = getConfigDir

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize and bind this KeyMaker to the server",
	Long: `Initialize a new KeyMaker by binding it to the server.

You will need an invite code from your administrator. The code is
generated with 'bluectl operator invite'.

This command:
1. Generates a new ed25519 keypair
2. Performs two-phase enrollment with challenge-response
3. Stores configuration in ~/.km/config.json

Use --force to re-initialize if already configured (removes existing keypair).

Environment variables:
  SERVER_URL  Control Plane URL (preferred, takes precedence over all other options)
  KM_SERVER   Control Plane URL (deprecated, use SERVER_URL instead)

Examples:
  km init
  km init --name workstation-home
  km init --force                                    # Re-initialize
  km init --server https://fabric.acme.com
  SERVER_URL=https://fabric.acme.com km init         # Using env var`,
	RunE: runInit,
}

// getServerURL resolves the server URL using the following precedence:
// 1. SERVER_URL environment variable (preferred)
// 2. KM_SERVER environment variable (deprecated)
// 3. --server flag
// 4. --control-plane flag (deprecated)
// 5. Default value from --server flag
//
// Returns the URL and a boolean indicating if a deprecated option was used.
func getServerURL(cmd *cobra.Command) (string, bool) {
	// 1. Check SERVER_URL env var first (highest precedence)
	if url := os.Getenv("SERVER_URL"); url != "" {
		return url, false
	}

	// 2. Check deprecated KM_SERVER env var
	if url := os.Getenv("KM_SERVER"); url != "" {
		return url, true // true = show deprecation warning
	}

	// 3. Check --server flag
	if cmd.Flags().Changed("server") {
		url, _ := cmd.Flags().GetString("server")
		return url, false
	}

	// 4. Check deprecated --control-plane flag
	if cmd.Flags().Changed("control-plane") {
		url, _ := cmd.Flags().GetString("control-plane")
		return url, true // true = show deprecation warning
	}

	// 5. Return default (from --server flag which has the default)
	url, _ := cmd.Flags().GetString("server")
	return url, false
}

func runInit(cmd *cobra.Command, args []string) error {
	serverURL, deprecated := getServerURL(cmd)
	if deprecated {
		// Check which deprecated option was used
		if os.Getenv("KM_SERVER") != "" && os.Getenv("SERVER_URL") == "" {
			fmt.Fprintln(os.Stderr, "WARNING: KM_SERVER is deprecated, use SERVER_URL instead")
		} else {
			fmt.Fprintln(os.Stderr, "WARNING: --control-plane is deprecated, use --server instead")
		}
	}
	inviteCode, _ := cmd.Flags().GetString("invite-code")

	// Print header with version and platform info
	fmt.Printf("KeyMaker v%s\n", version.Version)
	fmt.Printf("Platform: %s (%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Secure Element: software (TPM/Secure Enclave not available)\n")
	fmt.Println()

	// Check if already initialized
	configPath := getConfigPath()
	force, _ := cmd.Flags().GetBool("force")
	if _, err := os.Stat(configPath); err == nil {
		if !force {
			return fmt.Errorf("KeyMaker already initialized. Use --force to re-initialize")
		}
		// Remove existing config for re-initialization
		fmt.Println("Removing existing configuration (--force)...")
		configDir := getConfigDirFunc()
		if err := os.RemoveAll(configDir); err != nil {
			return fmt.Errorf("failed to remove existing config: %w", err)
		}
	}

	// Prompt for invite code if not provided
	if inviteCode == "" {
		fmt.Print("Enter invite code: ")
		reader := bufio.NewReader(os.Stdin)
		code, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read invite code: %w", err)
		}
		inviteCode = strings.TrimSpace(code)
	}

	if inviteCode == "" {
		return fmt.Errorf("invite code is required")
	}

	fmt.Println()
	fmt.Println("Enrolling with server...")

	// Perform two-phase enrollment
	kid, err := doEnrollment(inviteCode, serverURL)
	if err != nil {
		return err
	}

	// Save config
	config := KMConfig{
		KID:             kid,
		ControlPlaneURL: serverURL,
	}

	configData, _ := json.MarshalIndent(config, "", "  ")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Print success output
	fmt.Println()
	fmt.Println("Enrolled successfully.")
	fmt.Printf("  Identity: %s\n", kid)
	fmt.Println()
	fmt.Printf("Config saved to %s\n", configPath)

	// Show next steps
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  Run 'km whoami' to verify your identity.")

	return nil
}

// doEnrollment performs the two-phase enrollment flow:
// 1. POST /api/v1/enroll/init with invite code to get challenge
// 2. Generate keypair, sign challenge
// 3. POST /api/v1/enroll/complete with public key and signed challenge
// 4. Save identity using dpop.CompleteEnrollment
func doEnrollment(inviteCode, serverURL string) (string, error) {
	// Phase 1: Initialize enrollment
	initReq := map[string]string{
		"code": inviteCode,
	}
	initBody, _ := json.Marshal(initReq)

	resp, err := http.Post(
		serverURL+"/api/v1/enroll/init",
		"application/json",
		strings.NewReader(string(initBody)),
	)
	if err != nil {
		return "", fmt.Errorf("cannot connect to server at %s: %w\nVerify the URL and check your network connection", serverURL, err)
	}
	defer resp.Body.Close()

	// Handle error response from init
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", parseEnrollmentError(resp)
	}

	// Parse init response
	var initResp struct {
		Challenge    string `json:"challenge"`
		EnrollmentID string `json:"enrollment_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return "", fmt.Errorf("failed to parse enrollment init response: %w", err)
	}

	// Decode challenge from base64
	challengeBytes, err := base64.StdEncoding.DecodeString(initResp.Challenge)
	if err != nil {
		return "", fmt.Errorf("failed to decode challenge: %w", err)
	}

	// Generate keypair using crypto/rand via dpop package
	pubKey, privKey, err := dpop.GenerateKeyPair()
	if err != nil {
		return "", fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Sign the challenge (raw bytes) with private key
	signature := ed25519.Sign(privKey, challengeBytes)

	// Phase 2: Complete enrollment
	completeReq := map[string]string{
		"enrollment_id":    initResp.EnrollmentID,
		"public_key":       base64.StdEncoding.EncodeToString(pubKey),
		"signed_challenge": base64.StdEncoding.EncodeToString(signature),
	}
	completeBody, _ := json.Marshal(completeReq)

	resp2, err := http.Post(
		serverURL+"/api/v1/enroll/complete",
		"application/json",
		strings.NewReader(string(completeBody)),
	)
	if err != nil {
		return "", fmt.Errorf("cannot connect to server: %w", err)
	}
	defer resp2.Body.Close()

	// Handle error response from complete
	if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusCreated {
		return "", parseEnrollmentError(resp2)
	}

	// Parse complete response
	var completeResp struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&completeResp); err != nil {
		return "", fmt.Errorf("failed to parse enrollment complete response: %w", err)
	}

	// Save identity using dpop utilities (handles key storage with correct permissions)
	if err := dpop.CompleteEnrollment("km", privKey, completeResp.ID); err != nil {
		return "", fmt.Errorf("failed to save identity: %w", err)
	}

	return completeResp.ID, nil
}

// parseEnrollmentError parses an error response from the enrollment endpoints.
func parseEnrollmentError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("enrollment failed: HTTP %d", resp.StatusCode)
	}

	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		return fmt.Errorf("%s", enrollmentErrorMessage(errResp.Error))
	}

	return fmt.Errorf("enrollment failed: HTTP %d", resp.StatusCode)
}

// enrollmentErrorMessage returns a user-friendly error message for enrollment error codes.
func enrollmentErrorMessage(code string) string {
	switch code {
	case "enroll.invalid_code":
		return "Invalid or expired invite code"
	case "enroll.expired_code":
		return "Invite code has expired"
	case "enroll.code_consumed":
		return "Invite code already used"
	case "enroll.challenge_expired":
		return "Enrollment session timed out. Please try again"
	case "enroll.invalid_signature":
		return "Signature verification failed"
	case "enroll.key_exists":
		return "This key is already enrolled"
	default:
		return fmt.Sprintf("Enrollment failed: %s", code)
	}
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current KeyMaker identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := loadConfig()
		if err != nil {
			return fmt.Errorf("KeyMaker not initialized. Run 'km init' first")
		}

		if outputFormat != "table" {
			return formatOutput(config)
		}

		verbose, _ := cmd.Flags().GetBool("verbose")

		// Display identity
		kid := config.KID
		if kid == "" {
			// Fallback for legacy config
			kid = config.KeyMakerID
		}

		fmt.Printf("Identity: %s\n", kid)
		fmt.Printf("Server:   %s\n", config.ControlPlaneURL)

		// Show legacy fields if present and verbose
		if verbose {
			if config.OperatorEmail != "" {
				fmt.Println()
				fmt.Printf("Operator: %s\n", config.OperatorEmail)
			}
			if config.OperatorID != "" {
				fmt.Printf("Operator ID: %s\n", config.OperatorID)
			}
		}

		// Fetch and display authorizations
		authorizations, err := getAuthorizations()
		if err != nil {
			// Non-fatal: show identity even if authorizations can't be fetched
			fmt.Printf("\nAuthorizations: (unable to fetch: %v)\n", err)
		} else if len(authorizations) == 0 {
			fmt.Printf("\nAuthorizations: none\n")
		} else {
			fmt.Printf("\nAuthorizations:\n")
			for _, auth := range authorizations {
				// Use CANames (names resolved from IDs by the API)
				var caDisplay string
				if len(auth.CANames) > 0 {
					if verbose {
						// Verbose: show name (id) format
						var caParts []string
						for i, name := range auth.CANames {
							if i < len(auth.CAIDs) && name != auth.CAIDs[i] {
								caParts = append(caParts, fmt.Sprintf("%s (%s)", name, auth.CAIDs[i]))
							} else {
								caParts = append(caParts, name)
							}
						}
						caDisplay = strings.Join(caParts, ", ")
					} else {
						caDisplay = strings.Join(auth.CANames, ", ")
					}
				} else if len(auth.CAIDs) > 0 {
					caDisplay = strings.Join(auth.CAIDs, ", ")
				} else {
					caDisplay = "none"
				}

				// Use DeviceNames (names resolved from IDs by the API)
				var deviceDisplay string
				if len(auth.DeviceNames) > 0 {
					if verbose {
						// Verbose: show name (id) format
						var deviceParts []string
						for i, name := range auth.DeviceNames {
							if i < len(auth.DeviceIDs) && name != auth.DeviceIDs[i] && auth.DeviceIDs[i] != "all" {
								deviceParts = append(deviceParts, fmt.Sprintf("%s (%s)", name, auth.DeviceIDs[i]))
							} else {
								deviceParts = append(deviceParts, name)
							}
						}
						deviceDisplay = strings.Join(deviceParts, ", ")
					} else {
						deviceDisplay = strings.Join(auth.DeviceNames, ", ")
					}
				} else if len(auth.DeviceIDs) > 0 {
					deviceDisplay = strings.Join(auth.DeviceIDs, ", ")
				} else {
					deviceDisplay = "none"
				}

				fmt.Printf("  CA: %s, Devices: %s\n", caDisplay, deviceDisplay)
			}
		}

		return nil
	},
}

func getConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".km")
}

func getConfigPath() string {
	return filepath.Join(getConfigDirFunc(), "config.json")
}

func getPrivateKeyPath() string {
	return filepath.Join(getConfigDirFunc(), "keymaker.pem")
}

func loadConfig() (*KMConfig, error) {
	data, err := os.ReadFile(getConfigPath())
	if err != nil {
		return nil, err
	}

	var config KMConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
