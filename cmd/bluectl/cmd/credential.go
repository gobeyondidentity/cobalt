package cmd

import (
	"github.com/spf13/cobra"
)

// credentialCmd is the parent command for credential management.
var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage credentials (SSH CAs, certificates)",
	Long:  `Commands to create, list, and manage credentials.`,
}

func init() {
	rootCmd.AddCommand(credentialCmd)
}
