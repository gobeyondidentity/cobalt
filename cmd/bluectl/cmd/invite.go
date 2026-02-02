package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(inviteCmd)
	inviteCmd.AddCommand(inviteRemoveCmd)

	// Flags for invite remove
	inviteRemoveCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
}

var inviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Manage operator invite codes",
}

var inviteRemoveCmd = &cobra.Command{
	Use:     "remove <code>",
	Aliases: []string{"delete", "revoke"},
	Short:   "Remove/revoke an invite code",
	Long: `Remove an invite code from the server. If the invite is pending, it will be deleted.
If already used, it will be marked as revoked.

Use --yes/-y to skip the confirmation prompt.

Examples:
  bluectl invite remove ACME-ABCD-1234
  bluectl invite remove ACME-ABCD-1234 --yes`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		code := args[0]
		yes, _ := cmd.Flags().GetBool("yes")

		// Confirm deletion unless --yes/-y is set
		if !yes {
			fmt.Printf("Are you sure you want to remove invite code '%s'? [y/N]: ", code)
			var response string
			fmt.Scanln(&response)
			response = strings.ToLower(strings.TrimSpace(response))
			if response != "y" && response != "yes" {
				fmt.Println("Removal cancelled.")
				return nil
			}
		}

		serverURL := GetServer()
		if serverURL == "" {
			return fmt.Errorf("invite remove requires a server connection (--server or SERVER_URL)")
		}
		return removeInviteRemote(cmd.Context(), serverURL, code)
	},
}

func removeInviteRemote(ctx context.Context, serverURL, code string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}
	if err := client.RemoveInviteCode(ctx, code); err != nil {
		return fmt.Errorf("failed to remove invite: %w", err)
	}
	fmt.Printf("Removed invite code\n")
	return nil
}
