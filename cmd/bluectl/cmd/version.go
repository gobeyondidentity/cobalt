package cmd

import (
	"fmt"

	"github.com/gobeyondidentity/secure-infra/internal/version"
	"github.com/gobeyondidentity/secure-infra/internal/versioncheck"
	"github.com/spf13/cobra"
)

var (
	checkForUpdate  bool
	skipUpdateCheck bool
)

// versionChecker is the checker used by the version command.
// Can be overridden for testing.
var versionChecker *versioncheck.Checker

func init() {
	rootCmd.AddCommand(newVersionCmd())
}

// newVersionCmd creates the version command with the default checker.
func newVersionCmd() *cobra.Command {
	return newVersionCmdWithChecker(nil)
}

// newVersionCmdWithChecker creates the version command with a custom checker.
// If checker is nil, a default checker will be created when needed.
func newVersionCmdWithChecker(checker *versioncheck.Checker) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long: `Display the current version of bluectl.

Use --check to check for available updates.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersion(cmd, checker)
		},
	}

	cmd.Flags().BoolVar(&checkForUpdate, "check", false, "Check for available updates")
	cmd.Flags().BoolVar(&skipUpdateCheck, "skip-update-check", false, "Skip the update check (only show version)")

	return cmd
}

func runVersion(cmd *cobra.Command, checker *versioncheck.Checker) error {
	// Always show current version first
	fmt.Fprintf(cmd.OutOrStdout(), "bluectl version %s\n", version.String())

	// Skip update check if --skip-update-check is set or --check is not set
	if skipUpdateCheck || !checkForUpdate {
		return nil
	}

	// Perform update check
	if checker == nil {
		checker = versioncheck.NewChecker()
	}

	result := checker.Check(version.Version)

	// Handle errors gracefully
	if result.Error != nil && result.LatestVersion == "" {
		fmt.Fprintf(cmd.OutOrStdout(), "(Could not check for updates)\n")
		return nil
	}

	// Show update status
	if result.UpdateAvailable {
		fmt.Fprintf(cmd.OutOrStdout(), "\nA newer version is available: %s\n", result.LatestVersion)
		fmt.Fprintf(cmd.OutOrStdout(), "  Release notes: %s\n", result.ReleaseURL)
		fmt.Fprintf(cmd.OutOrStdout(), "\nTo upgrade:\n")
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", versioncheck.GetUpgradeCommand(result.InstallMethod, "bluectl", result.LatestVersion))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "You are running the latest version.\n")
	}

	return nil
}
