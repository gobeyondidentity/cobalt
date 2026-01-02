package cmd

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func init() {
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(whoamiCmd)

	initCmd.Flags().String("name", "", "Custom name for this KeyMaker")
	initCmd.Flags().String("control-plane", "http://localhost:8080", "Control plane URL")
	initCmd.Flags().String("invite-code", "", "Invite code (will prompt if not provided)")
	initCmd.Flags().Bool("force", false, "Force re-initialization (removes existing config)")

	whoamiCmd.Flags().BoolP("verbose", "v", false, "Show internal IDs")
}

// KMConfig is stored in ~/.km/config.json
type KMConfig struct {
	KeyMakerID      string `json:"keymaker_id"`
	OperatorID      string `json:"operator_id"`
	OperatorEmail   string `json:"operator_email"`
	ControlPlaneURL string `json:"control_plane_url"`
	PrivateKeyPath  string `json:"private_key_path"`
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize and bind this KeyMaker to the control plane",
	Long: `Initialize a new KeyMaker by binding it to the control plane.

You will need an invite code from your administrator. The code is
generated with 'bluectl operator invite'.

This command:
1. Generates a new ed25519 keypair
2. Binds the public key to the control plane using your invite code
3. Stores configuration in ~/.km/config.json

Use --force to re-initialize if already configured (removes existing keypair).

Examples:
  km init
  km init --name workstation-home
  km init --force                                    # Re-initialize
  km init --control-plane https://fabric.acme.com`,
	RunE: runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	controlPlane, _ := cmd.Flags().GetString("control-plane")
	inviteCode, _ := cmd.Flags().GetString("invite-code")

	// Print header with version and platform info
	fmt.Printf("KeyMaker v%s\n", Version)
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
		configDir := getConfigDir()
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
	fmt.Println("Generating keypair...")

	// Generate keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Convert to SSH format
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key: %w", err)
	}
	sshPubKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPubKey)))

	// Generate a short ID for the KeyMaker name (will be updated after bind)
	shortID := strings.ToLower(uuid.New().String()[:4])

	// Build bind request (name will be finalized after we get the operator email)
	bindReq := map[string]string{
		"invite_code":        inviteCode,
		"public_key":         sshPubKeyStr,
		"platform":           runtime.GOOS,
		"secure_element":     "software",
		"device_fingerprint": uuid.New().String(),
		"device_name":        name, // Temporary, may be updated
	}

	// POST to control plane
	fmt.Println("Binding to control plane...")
	reqBody, _ := json.Marshal(bindReq)
	resp, err := http.Post(
		controlPlane+"/api/v1/keymakers/bind",
		"application/json",
		strings.NewReader(string(reqBody)),
	)
	if err != nil {
		return fmt.Errorf("cannot connect to control plane at %s: %w\nVerify the URL and check your network connection", controlPlane, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("invalid or expired invite code. Request a new code from your admin")
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return fmt.Errorf("binding failed: %s", errResp.Error)
		}
		return fmt.Errorf("binding failed: HTTP %d", resp.StatusCode)
	}

	// Parse response with tenants
	var bindResp struct {
		KeyMakerID    string `json:"keymaker_id"`
		OperatorID    string `json:"operator_id"`
		OperatorEmail string `json:"operator_email"`
		Tenants       []struct {
			TenantID   string `json:"tenant_id"`
			TenantName string `json:"tenant_name"`
			Role       string `json:"role"`
		} `json:"tenants"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bindResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract operator name from email for KeyMaker name generation
	operatorName := extractNameFromEmail(bindResp.OperatorEmail)

	// Auto-generate meaningful name if not provided
	if name == "" {
		name = fmt.Sprintf("km-%s-%s-%s", runtime.GOOS, operatorName, shortID)
	}

	// Save private key
	keyPath := getPrivateKeyPath()
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: privKey,
	})
	if err := os.WriteFile(keyPath, privKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save config
	config := KMConfig{
		KeyMakerID:      bindResp.KeyMakerID,
		OperatorID:      bindResp.OperatorID,
		OperatorEmail:   bindResp.OperatorEmail,
		ControlPlaneURL: controlPlane,
		PrivateKeyPath:  keyPath,
	}

	configData, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Print success output
	fmt.Println()
	fmt.Println("Bound successfully.")
	fmt.Printf("  Operator: %s\n", bindResp.OperatorEmail)

	// Show tenant info if available
	if len(bindResp.Tenants) > 0 {
		tenant := bindResp.Tenants[0]
		fmt.Printf("  Tenant: %s (%s)\n", tenant.TenantName, tenant.Role)
	}

	fmt.Printf("  KeyMaker: %s\n", name)
	fmt.Println()
	fmt.Printf("Config saved to %s\n", configPath)

	// Show next steps and access summary
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  Run 'km whoami' to verify your identity.")

	// Fetch authorizations to show access summary
	authorizations, err := getAuthorizations()
	if err != nil {
		// Non-fatal: config is saved, just can't fetch authorizations yet
		fmt.Println()
		fmt.Println("Unable to fetch authorizations. Run 'km whoami' to check your access.")
	} else {
		// Count unique CAs and devices across all authorizations
		caSet := make(map[string]struct{})
		deviceSet := make(map[string]struct{})
		for _, auth := range authorizations {
			for _, caID := range auth.CAIDs {
				caSet[caID] = struct{}{}
			}
			for _, deviceID := range auth.DeviceIDs {
				deviceSet[deviceID] = struct{}{}
			}
		}
		caCount := len(caSet)
		deviceCount := len(deviceSet)

		if caCount > 0 {
			fmt.Println("  Run 'km ssh-ca list' to see available CAs.")
		}

		fmt.Println()
		fmt.Printf("You have access to %d CA(s) and %d device(s).\n", caCount, deviceCount)

		if caCount == 0 {
			fmt.Printf("Ask your admin to grant access: bluectl operator grant %s <tenant> <ca> <devices>\n", bindResp.OperatorEmail)
		}
	}

	return nil
}

// extractNameFromEmail extracts the username portion from an email address.
// For example, "nelson@acme.com" returns "nelson".
func extractNameFromEmail(email string) string {
	if idx := strings.Index(email, "@"); idx > 0 {
		return strings.ToLower(email[:idx])
	}
	return "user"
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

		fmt.Printf("Operator: %s\n", config.OperatorEmail)
		fmt.Printf("Server:   %s\n", config.ControlPlaneURL)

		if verbose {
			fmt.Println()
			fmt.Printf("KeyMaker ID: %s\n", config.KeyMakerID)
			fmt.Printf("Operator ID: %s\n", config.OperatorID)
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
				// Prefer name fields if available, fall back to IDs
				var caDisplay string
				if auth.CAName != "" {
					caDisplay = auth.CAName
				} else if len(auth.CAIDs) > 0 {
					caDisplay = auth.CAIDs[0] // Show first ID as fallback
				} else {
					caDisplay = "none"
				}

				var deviceDisplay string
				if len(auth.Devices) > 0 {
					deviceDisplay = strings.Join(auth.Devices, ", ")
				} else if len(auth.DeviceIDs) > 0 {
					// Check if it's "all" (special case)
					if len(auth.DeviceIDs) == 1 && auth.DeviceIDs[0] == "all" {
						deviceDisplay = "all"
					} else {
						deviceDisplay = strings.Join(auth.DeviceIDs, ", ")
					}
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
	return filepath.Join(getConfigDir(), "config.json")
}

func getPrivateKeyPath() string {
	return filepath.Join(getConfigDir(), "keymaker.pem")
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
