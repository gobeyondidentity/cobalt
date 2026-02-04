package cmd

import (
	"fmt"

	"github.com/gobeyondidentity/cobalt/internal/version"
	"github.com/gobeyondidentity/cobalt/internal/versioncheck"
	"github.com/spf13/cobra"
)

var (
	checkForUpdates   bool
	skipUpdateCheck   bool
)

func init() {
	rootCmd.AddCommand(versionCmd)

	versionCmd.Flags().BoolVar(&checkForUpdates, "check", false, "Check for updates and show upgrade instructions")
	versionCmd.Flags().BoolVar(&skipUpdateCheck, "skip-update-check", false, "Only show version without checking for updates")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long: `Display the current km version and optionally check for updates.

Examples:
  km version                  # Show current version
  km version --check          # Check for updates and show upgrade instructions
  km version --skip-update-check  # Only show version (no update check)`,
	RunE: runVersion,
}

func runVersion(cmd *cobra.Command, args []string) error {
	// Always print current version
	fmt.Fprintf(cmd.OutOrStdout(), "km version %s\n", version.String())

	// If --skip-update-check is set, or --check is not set, stop here
	if skipUpdateCheck || !checkForUpdates {
		return nil
	}

	// Check for updates
	checker := versioncheck.NewChecker()
	result := checker.Check(version.Version)

	// Handle errors (network timeout, etc.)
	if result.Error != nil && result.LatestVersion == "" {
		fmt.Fprintln(cmd.OutOrStdout(), "(Could not check for updates)")
		return nil
	}

	// If update is available, show details
	if result.UpdateAvailable {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.OutOrStdout(), "A newer version is available: %s\n", result.LatestVersion)
		if result.ReleaseURL != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "  Release notes: %s\n", result.ReleaseURL)
		}
		fmt.Fprintln(cmd.OutOrStdout())

		// Get upgrade command for km specifically
		upgradeCmd := versioncheck.GetUpgradeCommand(result.InstallMethod, "km", result.LatestVersion)
		if upgradeCmd != "" {
			fmt.Fprintln(cmd.OutOrStdout(), "To upgrade:")
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", upgradeCmd)
		}
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "You are running the latest version.")
	}

	return nil
}
