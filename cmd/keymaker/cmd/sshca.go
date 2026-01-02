package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nmelo/secure-infra/pkg/sshca"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(sshCACmd)
	sshCACmd.AddCommand(sshCACreateCmd)
	sshCACmd.AddCommand(sshCAListCmd)
	sshCACmd.AddCommand(sshCAShowCmd)
	sshCACmd.AddCommand(sshCASignCmd)

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

		// Check if CA already exists
		exists, err := dpuStore.SSHCAExists(name)
		if err != nil {
			return fmt.Errorf("failed to check CA existence: %w", err)
		}
		if exists {
			return fmt.Errorf("SSH CA '%s' already exists", name)
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

		fmt.Printf("SSH CA '%s' created. ID: %s\n", name, id)
		return nil
	},
}

var sshCAListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all SSH CAs",
	RunE: func(cmd *cobra.Command, args []string) error {
		cas, err := dpuStore.ListSSHCAs()
		if err != nil {
			return err
		}

		if outputFormat != "table" {
			return formatOutput(cas)
		}

		if len(cas) == 0 {
			fmt.Println("No SSH CAs configured. Use 'km ssh-ca create' to create one.")
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
	Use:   "show <name>",
	Short: "Show SSH CA details",
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

		if outputFormat != "table" {
			// For JSON/YAML, exclude private key
			output := struct {
				ID        string    `json:"id" yaml:"id"`
				Name      string    `json:"name" yaml:"name"`
				KeyType   string    `json:"key_type" yaml:"key_type"`
				PublicKey string    `json:"public_key" yaml:"public_key"`
				CreatedAt time.Time `json:"created_at" yaml:"created_at"`
			}{
				ID:        ca.ID,
				Name:      ca.Name,
				KeyType:   ca.KeyType,
				PublicKey: pubKeyStr,
				CreatedAt: ca.CreatedAt,
			}
			return formatOutput(output)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "ID:\t%s\n", ca.ID)
		fmt.Fprintf(w, "Name:\t%s\n", ca.Name)
		fmt.Fprintf(w, "Key Type:\t%s\n", ca.KeyType)
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
