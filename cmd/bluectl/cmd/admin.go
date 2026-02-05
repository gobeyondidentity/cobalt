package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(adminCmd)
	adminCmd.AddCommand(adminListCmd)
	adminCmd.AddCommand(adminRevokeCmd)

	// Flags for admin list
	adminListCmd.Flags().String("status", "", "Filter by status (active, revoked)")

	// Flags for admin revoke
	adminRevokeCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
	adminRevokeCmd.Flags().String("reason", "", "Reason for revocation (required)")
	adminRevokeCmd.MarkFlagRequired("reason")
}

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage AdminKeys",
	Long: `AdminKeys are file-based admin credentials used for system operations.

Each super:admin operator can have multiple AdminKeys bound to different machines.
Unlike KeyMakers (TPM-bound), AdminKeys use file-based Ed25519 keys stored in
~/.bluectl/key.pem.

Use these commands to list and revoke AdminKeys for security and lifecycle
management.`,
}

// validAdminKeyStatuses defines the valid status values for admin list filtering.
var validAdminKeyStatuses = []string{"active", "revoked"}

var adminListCmd = &cobra.Command{
	Use:   "list",
	Short: "List AdminKeys",
	Long: `List all AdminKeys, optionally filtered by status.

Requires super:admin role.

Examples:
  bluectl admin list
  bluectl admin list --status active
  bluectl admin list --status revoked
  bluectl admin list --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		statusFilter, _ := cmd.Flags().GetString("status")

		// Validate status if provided
		if statusFilter != "" {
			valid := false
			for _, s := range validAdminKeyStatuses {
				if statusFilter == s {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid status: %s (must be one of: %s)", statusFilter, strings.Join(validAdminKeyStatuses, ", "))
			}
		}

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return listAdminKeysRemote(cmd.Context(), serverURL, statusFilter)
	},
}

func listAdminKeysRemote(ctx context.Context, serverURL, statusFilter string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}

	adminKeys, err := client.ListAdminKeys(ctx, statusFilter)
	if err != nil {
		return fmt.Errorf("failed to list AdminKeys: %w", err)
	}

	if outputFormat != "table" {
		if len(adminKeys) == 0 {
			fmt.Println("[]")
			return nil
		}
		return formatOutput(adminKeys)
	}

	if len(adminKeys) == 0 {
		fmt.Println("No AdminKeys found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSTATUS\tBOUND AT\tLAST SEEN")
	for _, ak := range adminKeys {
		lastSeen := "-"
		if ak.LastSeen != nil {
			lastSeen = *ak.LastSeen
		}
		name := ak.Name
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			ak.ID, name, ak.Status, ak.BoundAt, lastSeen)
	}
	w.Flush()
	return nil
}

var adminRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke an AdminKey",
	Long: `Revoke an AdminKey by ID. The AdminKey will no longer be able to
authenticate to the control plane.

A reason must be provided for audit purposes.

Requires super:admin role.

Examples:
  bluectl admin revoke adm_abc123 --reason "Key compromised"
  bluectl admin revoke adm_abc123 --reason "Employee offboarded" --yes`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		skipConfirm, _ := cmd.Flags().GetBool("yes")
		reason, _ := cmd.Flags().GetString("reason")

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return revokeAdminKeyRemote(cmd.Context(), serverURL, id, reason, skipConfirm)
	},
}

func revokeAdminKeyRemote(ctx context.Context, serverURL, id, reason string, skipConfirm bool) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}

	// Get AdminKey details first for confirmation and output
	ak, err := client.GetAdminKey(ctx, id)
	if err != nil {
		return fmt.Errorf("AdminKey not found: %s", id)
	}

	name := ak.Name
	if name == "" {
		name = "(unnamed)"
	}

	if !skipConfirm {
		fmt.Printf("Revoke AdminKey '%s' (%s)?\n", name, ak.ID)
		fmt.Printf("  Reason: %s\n", reason)
		fmt.Print("Type 'yes' to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Println("Revocation cancelled.")
			return nil
		}
	}

	if err := client.RevokeAdminKey(ctx, id, reason); err != nil {
		return fmt.Errorf("failed to revoke AdminKey: %w", err)
	}

	if outputFormat == "json" || outputFormat == "yaml" {
		return formatOutput(map[string]interface{}{
			"status":   "revoked",
			"adminKey": ak,
		})
	}

	fmt.Printf("AdminKey revoked:\n")
	fmt.Printf("  ID:     %s\n", ak.ID)
	fmt.Printf("  Name:   %s\n", name)
	fmt.Printf("  Reason: %s\n", reason)
	return nil
}
