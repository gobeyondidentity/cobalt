package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/gobeyondidentity/secure-infra/pkg/clierror"
	"github.com/gobeyondidentity/secure-infra/pkg/sshca"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(sshCACmd)
	sshCACmd.AddCommand(sshCACreateCmd)
	sshCACmd.AddCommand(sshCAListCmd)
	sshCACmd.AddCommand(sshCAShowCmd)
	sshCACmd.AddCommand(sshCASignCmd)
	sshCACmd.AddCommand(sshCADeleteCmd)

	// Flags for create
	sshCACreateCmd.Flags().String("type", "ed25519", "Key type")

	// Flags for show
	sshCAShowCmd.Flags().Bool("public-key", false, "Output only public key")

	// Flags for sign
	sshCASignCmd.Flags().StringP("principal", "p", "", "Certificate principal (required)")
	sshCASignCmd.Flags().StringP("validity", "v", "8h", "Certificate validity duration")
	sshCASignCmd.Flags().String("pubkey", "", "Path to user's public key file (required)")
	sshCASignCmd.MarkFlagRequired("principal")
	sshCASignCmd.MarkFlagRequired("pubkey")

	// Flags for delete
	sshCADeleteCmd.Flags().Bool("force", false, "Skip confirmation prompt")
	sshCADeleteCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt (alias for --force)")
}

var sshCACmd = &cobra.Command{
	Use:   "ssh-ca",
	Short: "Manage SSH Certificate Authorities",
	Long: `Commands to create, list, and manage SSH Certificate Authorities.

SSH CAs are used to sign user certificates for passwordless SSH authentication.
Once a CA is created, its public key can be added to servers' sshd_config to
trust certificates signed by this CA.`,
}

var sshCACreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new SSH CA",
	Long: `Generate a new SSH Certificate Authority key pair.

The private key is stored securely in the local database. The public key
can be retrieved using 'km ssh-ca show <name> --public-key'
and added to servers' sshd_config TrustedUserCAKeys directive.

Examples:
  km ssh-ca create ops-ca
  km ssh-ca create prod-ca --type ed25519`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		keyType, _ := cmd.Flags().GetString("type")

		// Validate key type
		if keyType != "ed25519" {
			return fmt.Errorf("unsupported key type: %s (only ed25519 is supported)", keyType)
		}

		// Check if CA already exists - idempotent: return success if exists
		existing, err := dpuStore.GetSSHCA(name)
		if err == nil && existing != nil {
			if outputFormat == "json" || outputFormat == "yaml" {
				return formatOutput(map[string]any{
					"status": "already_exists",
					"ssh_ca": map[string]any{
						"id":         existing.ID,
						"name":       existing.Name,
						"type":       existing.KeyType,
						"public_key": strings.TrimSpace(string(existing.PublicKey)),
						"created_at": existing.CreatedAt,
					},
				})
			}
			fmt.Printf("SSH CA '%s' already exists\n", name)
			return nil
		}

		// Generate CA
		ca, err := sshca.GenerateCA(keyType)
		if err != nil {
			return fmt.Errorf("failed to generate CA: %w", err)
		}
		ca.Name = name

		// Generate ID
		id := "ca_" + uuid.New().String()[:8]

		// Get public key in SSH format for storage
		pubKeyStr, err := ca.PublicKeyString()
		if err != nil {
			return fmt.Errorf("failed to format public key: %w", err)
		}

		// Get private key in PEM format for storage
		privKeyPEM, err := ca.MarshalPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to marshal private key: %w", err)
		}

		// Store in database (private key will be encrypted by CreateSSHCA)
		// tenantID is nil - CA can be assigned to tenant later via bluectl
		if err := dpuStore.CreateSSHCA(id, name, []byte(pubKeyStr), privKeyPEM, keyType, nil); err != nil {
			return err
		}

		// Try to register CA with the nexus server
		// Registration failure is non-fatal - the CA is usable locally
		var registered bool
		var registrationWarning string

		config, configErr := loadConfig()
		if configErr == nil {
			registered, registrationWarning = registerSSHCA(config, name, pubKeyStr, keyType)
		}

		if outputFormat == "json" || outputFormat == "yaml" {
			output := map[string]any{
				"status": "created",
				"ssh_ca": map[string]any{
					"id":         id,
					"name":       name,
					"type":       keyType,
					"public_key": strings.TrimSpace(pubKeyStr),
				},
			}
			if registered {
				output["registered"] = true
			}
			if registrationWarning != "" {
				output["registration_warning"] = registrationWarning
			}
			return formatOutput(output)
		}

		if registered {
			fmt.Printf("SSH CA '%s' created. Registered with server.\n", name)
		} else if registrationWarning != "" {
			fmt.Printf("SSH CA '%s' created.\n", name)
			fmt.Printf("Warning: Failed to register with server: %s\n", registrationWarning)
		} else {
			fmt.Printf("SSH CA '%s' created.\n", name)
		}
		return nil
	},
}

var sshCAListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all SSH CAs",
	RunE: func(cmd *cobra.Command, args []string) error {
		cas, err := dpuStore.ListSSHCAs()
		if err != nil {
			return clierror.InternalError(err)
		}

		// For JSON/YAML output, always return a list (empty [] if no CAs)
		if outputFormat != "table" {
			// Ensure we return an empty array, not null
			if cas == nil {
				cas = []*store.SSHCA{}
			}
			return formatOutput(cas)
		}

		if len(cas) == 0 {
			fmt.Println("No SSH CAs found.")
			fmt.Println()
			fmt.Println("Create one with:")
			fmt.Println("  km ssh-ca create <name>")
			fmt.Println()
			fmt.Println("Example:")
			fmt.Println("  km ssh-ca create ops-ca")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tKEY TYPE\tCREATED")
		for _, ca := range cas {
			fmt.Fprintf(w, "%s\t%s\t%s\n",
				ca.Name, ca.KeyType, ca.CreatedAt.Format(time.RFC3339))
		}
		w.Flush()
		return nil
	},
}

var sshCAShowCmd = &cobra.Command{
	Use:     "show <name>",
	Aliases: []string{"describe"},
	Short:   "Show SSH CA details",
	Long: `Display details about an SSH CA.

Use --public-key to output only the public key, suitable for piping to a file
or configuring sshd_config TrustedUserCAKeys.

Examples:
  km ssh-ca show ops-ca
  km ssh-ca show ops-ca --public-key
  km ssh-ca show ops-ca --public-key > /etc/ssh/trusted_user_ca`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		showPublicKey, _ := cmd.Flags().GetBool("public-key")

		ca, err := dpuStore.GetSSHCA(name)
		if err != nil {
			return err
		}

		pubKeyStr := strings.TrimSpace(string(ca.PublicKey))

		// If --public-key flag, output only the public key (no trailing newline for piping)
		if showPublicKey {
			fmt.Print(pubKeyStr)
			return nil
		}

		// Private key storage info (always "Software (encrypted)" until hardware key storage)
		privateKeyStorage := "Software (encrypted)"

		if outputFormat != "table" {
			// For JSON/YAML, exclude private key but include storage info
			output := struct {
				ID                string    `json:"id" yaml:"id"`
				Name              string    `json:"name" yaml:"name"`
				KeyType           string    `json:"key_type" yaml:"key_type"`
				PublicKey         string    `json:"public_key" yaml:"public_key"`
				PrivateKeyStorage string    `json:"private_key_storage" yaml:"private_key_storage"`
				CreatedAt         time.Time `json:"created_at" yaml:"created_at"`
			}{
				ID:                ca.ID,
				Name:              ca.Name,
				KeyType:           ca.KeyType,
				PublicKey:         pubKeyStr,
				PrivateKeyStorage: privateKeyStorage,
				CreatedAt:         ca.CreatedAt,
			}
			return formatOutput(output)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Name:\t%s\n", ca.Name)
		fmt.Fprintf(w, "Key Type:\t%s\n", ca.KeyType)
		fmt.Fprintf(w, "Private Key:\t%s\n", privateKeyStorage)
		fmt.Fprintf(w, "Created:\t%s\n", ca.CreatedAt.Format(time.RFC3339))
		fmt.Fprintf(w, "Public Key:\t%s\n", pubKeyStr)
		w.Flush()

		return nil
	},
}

var sshCASignCmd = &cobra.Command{
	Use:   "sign <ca-name>",
	Short: "Sign a user's public key",
	Long: `Sign a user's SSH public key to create a certificate.

The generated certificate grants the specified principal access to servers
that trust the CA. The validity period defaults to 8 hours if not specified.

Validity formats: "8h" (hours), "24h" (hours), "7d" (days)

Examples:
  km ssh-ca sign ops-ca --principal alice --pubkey ~/.ssh/id_ed25519.pub
  km ssh-ca sign ops-ca -p alice -v 24h --pubkey ~/.ssh/id_ed25519.pub > ~/.ssh/id_ed25519-cert.pub
  km ssh-ca sign ops-ca -p admin -v 7d --pubkey /path/to/key.pub`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		caName := args[0]
		principal, _ := cmd.Flags().GetString("principal")
		validityStr, _ := cmd.Flags().GetString("validity")
		pubkeyPath, _ := cmd.Flags().GetString("pubkey")

		// Check authorization before signing
		if err := checkAuthorization(caName, ""); err != nil {
			if authErr, ok := err.(*AuthorizationError); ok {
				fmt.Fprintln(os.Stderr, authErr.Error())
				os.Exit(1)
			}
			return err
		}

		// Parse validity duration
		validity, err := sshca.ParseDuration(validityStr)
		if err != nil {
			return err
		}

		// Read user's public key
		pubKeyData, err := os.ReadFile(pubkeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %w", err)
		}

		// Validate public key format (basic check)
		pubKeyStr := strings.TrimSpace(string(pubKeyData))
		if !strings.HasPrefix(pubKeyStr, "ssh-") && !strings.HasPrefix(pubKeyStr, "ecdsa-") {
			return fmt.Errorf("invalid public key format: file does not appear to be an SSH public key")
		}

		// Get CA from store (private key is decrypted automatically)
		storedCA, err := dpuStore.GetSSHCA(caName)
		if err != nil {
			return err
		}

		// Reconstruct CA for signing: unmarshal the PEM private key back to raw bytes
		privKeyBytes, err := sshca.UnmarshalPrivateKey(storedCA.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to parse CA private key: %w", err)
		}

		ca := &sshca.CA{
			ID:         storedCA.ID,
			Name:       storedCA.Name,
			KeyType:    storedCA.KeyType,
			PrivateKey: privKeyBytes,
			CreatedAt:  storedCA.CreatedAt,
		}

		// Sign the certificate using CertOptions
		validBefore := time.Now().Add(validity)
		certStr, err := ca.SignCertificate(pubKeyStr, sshca.CertOptions{
			Principal:   principal,
			ValidBefore: validBefore,
		})
		if err != nil {
			return fmt.Errorf("failed to sign certificate: %w", err)
		}

		// Output certificate to stdout
		fmt.Println(certStr)
		return nil
	},
}

var sshCADeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an SSH CA",
	Long: `Delete an SSH Certificate Authority.

This permanently removes the CA and its private key. Any certificates signed
by this CA will remain valid until their expiry, but no new certificates can
be signed.

Use --yes/-y or --force to skip the confirmation prompt.

Examples:
  km ssh-ca delete old-ca
  km ssh-ca delete old-ca --yes
  km ssh-ca delete old-ca -y`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		force, _ := cmd.Flags().GetBool("force")
		yes, _ := cmd.Flags().GetBool("yes")

		// Check if CA exists first
		exists, err := dpuStore.SSHCAExists(name)
		if err != nil {
			return clierror.InternalError(err)
		}
		if !exists {
			return clierror.CANotFound(name)
		}

		// Confirm deletion unless --yes/-y or --force is set
		if !force && !yes {
			fmt.Printf("Are you sure you want to delete SSH CA '%s'? [y/N]: ", name)
			var response string
			fmt.Scanln(&response)
			response = strings.ToLower(strings.TrimSpace(response))
			if response != "y" && response != "yes" {
				fmt.Println("Deletion cancelled.")
				return nil
			}
		}

		// Delete the CA
		if err := dpuStore.DeleteSSHCA(name); err != nil {
			return clierror.InternalError(err)
		}

		if outputFormat == "json" || outputFormat == "yaml" {
			return formatOutput(map[string]any{
				"status": "deleted",
				"name":   name,
			})
		}

		fmt.Printf("SSH CA '%s' deleted.\n", name)
		return nil
	},
}

// registerSSHCA attempts to register an SSH CA with the nexus server.
// Returns (true, "") on success, (false, "") on conflict (already registered), and
// (false, errorMessage) on failure.
func registerSSHCA(config *KMConfig, name, pubKeyStr, keyType string) (bool, string) {
	reqBody := map[string]string{
		"name":        name,
		"public_key":  pubKeyStr,
		"key_type":    keyType,
		"operator_id": config.OperatorID,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return false, "failed to marshal request: " + err.Error()
	}

	// Get DPoP-enabled HTTP client
	httpClient, err := getDPoPHTTPClient(config.ControlPlaneURL)
	if err != nil {
		return false, err.Error()
	}

	req, err := http.NewRequest("POST", config.ControlPlaneURL+"/api/v1/ssh-cas", bytes.NewReader(jsonBody))
	if err != nil {
		return false, "failed to create request: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, "connection failed: " + err.Error()
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated:
		return true, ""
	case http.StatusConflict:
		// CA already registered on server - not an error
		return false, ""
	case http.StatusUnauthorized, http.StatusForbidden:
		// Auth error - provide user-friendly message
		return false, "authentication failed: please run 'km init' to enroll"
	default:
		var errResp struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(resp.Body).Decode(&errResp) == nil && errResp.Error != "" {
			return false, errResp.Error
		}
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
}
