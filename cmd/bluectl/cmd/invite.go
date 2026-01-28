package cmd

import (
	"fmt"

	"github.com/nmelo/secure-infra/pkg/store"
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
	Long: `Remove an invite code. If the invite is pending, it will be deleted.
If already used, it will be marked as revoked.

Examples:
  bluectl invite remove ACME-ABCD-1234`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		code := args[0]

		// Hash the code to find it
		codeHash := store.HashInviteCode(code)
		invite, err := dpuStore.GetInviteCodeByHash(codeHash)
		if err != nil {
			return fmt.Errorf("invite code not found: %s", code)
		}

		// For pending invites, delete them. For used invites, just mark revoked.
		if invite.Status == "pending" {
			if err := dpuStore.DeleteInviteCode(invite.ID); err != nil {
				return err
			}
			fmt.Printf("Removed pending invite for %s\n", invite.OperatorEmail)
		} else {
			// Already used or in other state - can't delete, just revoke if not already
			if invite.Status != "revoked" {
				if err := dpuStore.RevokeInviteCode(invite.ID); err != nil {
					return err
				}
				fmt.Printf("Revoked invite for %s (was: %s)\n", invite.OperatorEmail, invite.Status)
			} else {
				fmt.Printf("Invite for %s already revoked\n", invite.OperatorEmail)
			}
		}

		return nil
	},
}
