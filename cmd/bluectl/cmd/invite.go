package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(inviteCmd)
	inviteCmd.AddCommand(inviteRemoveCmd)
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

Examples:
  bluectl invite remove ACME-ABCD-1234`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := GetServer()
		if serverURL == "" {
			return fmt.Errorf("invite remove requires a server connection (--server or BLUECTL_SERVER)")
		}
		return removeInviteRemote(cmd.Context(), serverURL, args[0])
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
