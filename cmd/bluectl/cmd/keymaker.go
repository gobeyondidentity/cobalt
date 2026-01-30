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
	rootCmd.AddCommand(keymakerCmd)
	keymakerCmd.AddCommand(keymakerListCmd)
	keymakerCmd.AddCommand(keymakerRevokeCmd)

	// Flags for keymaker list
	keymakerListCmd.Flags().String("operator", "", "Filter by operator email")

	// Flags for keymaker revoke
	keymakerRevokeCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
}

var keymakerCmd = &cobra.Command{
	Use:   "keymaker",
	Short: "Manage operator workstations (KeyMakers)",
	Long: `KeyMakers are hardware-bound operator workstations that have completed
the enrollment process.

When an operator runs 'km init' with a valid invite code, their workstation
becomes a KeyMaker. The KeyMaker stores cryptographic material in the system's
secure element (TPM, Secure Enclave, etc.) and is used to sign credential
distribution requests.

Workflow:
  1. Admin invites operator:     bluectl operator invite user@example.com tenant
  2. Operator binds workstation: km init (enter invite code)
  3. Operator workstation becomes a KeyMaker
  4. Admin can list/revoke:      bluectl keymaker list`,
}

var keymakerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List KeyMakers",
	Long: `List all KeyMakers, optionally filtered by operator email.

Examples:
  bluectl keymaker list
  bluectl keymaker list --operator nelson@acme.com
  bluectl keymaker list --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		operatorFilter, _ := cmd.Flags().GetString("operator")

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return listKeyMakersRemote(cmd.Context(), serverURL, operatorFilter)
	},
}

func listKeyMakersRemote(ctx context.Context, serverURL, operatorFilter string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}

	// If filtering by email, we need to resolve to operator ID
	var operatorID string
	if operatorFilter != "" {
		op, err := client.GetOperator(ctx, operatorFilter)
		if err != nil {
			return fmt.Errorf("operator not found: %s", operatorFilter)
		}
		operatorID = op.ID
	}

	keymakers, err := client.ListKeyMakers(ctx, operatorID)
	if err != nil {
		return fmt.Errorf("failed to list KeyMakers: %w", err)
	}

	if outputFormat != "table" {
		if len(keymakers) == 0 {
			fmt.Println("[]")
			return nil
		}
		return formatOutput(keymakers)
	}

	if len(keymakers) == 0 {
		fmt.Println("No KeyMakers found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tOPERATOR\tNAME\tPLATFORM\tSTATUS\tBOUND AT\tLAST SEEN")
	for _, km := range keymakers {
		lastSeen := "-"
		if km.LastSeen != nil {
			lastSeen = *km.LastSeen
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			km.ID, km.OperatorEmail, km.Name, km.Platform, km.Status, km.BoundAt, lastSeen)
	}
	w.Flush()
	return nil
}

var keymakerRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke a KeyMaker",
	Long: `Revoke a KeyMaker by ID. The KeyMaker will no longer be able to
distribute credentials.

Examples:
  bluectl keymaker revoke km-abc123
  bluectl keymaker revoke km-abc123 --yes`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		skipConfirm, _ := cmd.Flags().GetBool("yes")

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return revokeKeyMakerRemote(cmd.Context(), serverURL, id, skipConfirm)
	},
}

func revokeKeyMakerRemote(ctx context.Context, serverURL, id string, skipConfirm bool) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}

	// Get KeyMaker details first for confirmation and output
	km, err := client.GetKeyMaker(ctx, id)
	if err != nil {
		return fmt.Errorf("KeyMaker not found: %s", id)
	}

	if !skipConfirm {
		fmt.Printf("Revoke KeyMaker '%s' (%s) owned by %s?\n", km.Name, km.ID, km.OperatorEmail)
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

	if err := client.RevokeKeyMaker(ctx, id); err != nil {
		return fmt.Errorf("failed to revoke KeyMaker: %w", err)
	}

	if outputFormat == "json" || outputFormat == "yaml" {
		return formatOutput(map[string]interface{}{
			"status":    "revoked",
			"keymaker":  km,
		})
	}

	fmt.Printf("KeyMaker revoked:\n")
	fmt.Printf("  ID:       %s\n", km.ID)
	fmt.Printf("  Name:     %s\n", km.Name)
	fmt.Printf("  Operator: %s\n", km.OperatorEmail)
	fmt.Printf("  Platform: %s\n", km.Platform)
	return nil
}
