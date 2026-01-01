package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/store"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(distributionCmd)
	distributionCmd.AddCommand(distributionHistoryCmd)

	// Flags for history
	distributionHistoryCmd.Flags().String("target", "", "Filter by DPU name")
	distributionHistoryCmd.Flags().Int("limit", 20, "Maximum results")
}

var distributionCmd = &cobra.Command{
	Use:   "distribution",
	Short: "View credential distribution activity",
	Long:  `Commands to view credential distribution history and attestation gate decisions.`,
}

var distributionHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Show credential distribution history",
	Long: `Display the history of credential distribution attempts.

Shows distribution outcomes including whether attestation gates blocked,
allowed, or were bypassed with --force.

Attestation status is displayed as:
  fresh   - attestation was less than 1 hour old at distribution time
  stale   - attestation was 1 hour or older at distribution time
  none    - no attestation record existed

Examples:
  bluectl distribution history
  bluectl distribution history --target bf3-lab-01
  bluectl distribution history --limit 50
  bluectl distribution history --target bf3-lab-01 -o json`,
	RunE: runDistributionHistory,
}

// DistributionHistoryEntry represents a single distribution record for JSON/YAML output.
type DistributionHistoryEntry struct {
	Timestamp            string  `json:"timestamp"`
	Target               string  `json:"target"`
	CredentialType       string  `json:"credential_type"`
	CredentialName       string  `json:"credential_name"`
	Outcome              string  `json:"outcome"`
	AttestationStatus    string  `json:"attestation_status"`
	AttestationAgeSecs   *int    `json:"attestation_age_seconds,omitempty"`
	InstalledPath        *string `json:"installed_path,omitempty"`
}

func runDistributionHistory(cmd *cobra.Command, args []string) error {
	targetFilter, _ := cmd.Flags().GetString("target")
	limit, _ := cmd.Flags().GetInt("limit")

	var distributions []*store.Distribution
	var err error

	if targetFilter != "" {
		distributions, err = dpuStore.GetDistributionHistory(targetFilter)
	} else {
		distributions, err = dpuStore.ListRecentDistributions(limit)
	}

	if err != nil {
		return fmt.Errorf("failed to retrieve distribution history: %w", err)
	}

	// Apply limit when filtering by target (GetDistributionHistory doesn't accept limit)
	if targetFilter != "" && len(distributions) > limit {
		distributions = distributions[:limit]
	}

	if outputFormat != "table" {
		entries := make([]DistributionHistoryEntry, 0, len(distributions))
		for _, d := range distributions {
			entry := DistributionHistoryEntry{
				Timestamp:          d.CreatedAt.Format(time.RFC3339),
				Target:             d.DPUName,
				CredentialType:     d.CredentialType,
				CredentialName:     d.CredentialName,
				Outcome:            mapOutcome(d.Outcome),
				AttestationStatus:  mapAttestationStatusJSON(d.AttestationStatus, d.AttestationAgeSecs),
				AttestationAgeSecs: d.AttestationAgeSecs,
				InstalledPath:      d.InstalledPath,
			}
			entries = append(entries, entry)
		}
		return formatOutput(entries)
	}

	if len(distributions) == 0 {
		fmt.Println("No distribution history. Use 'bluectl credential distribute' to distribute credentials.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tTARGET\tCREDENTIAL\tATTESTATION\tRESULT")
	for _, d := range distributions {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			d.CreatedAt.Format("2006-01-02 15:04:05"),
			d.DPUName,
			d.CredentialName,
			mapAttestationStatusTable(d.AttestationAgeSecs),
			mapOutcome(d.Outcome),
		)
	}
	w.Flush()
	return nil
}

// mapAttestationStatusTable converts attestation age to display status for table output.
// fresh: < 3600 seconds (1 hour)
// stale: >= 3600 seconds
// none: no attestation record
func mapAttestationStatusTable(ageSecs *int) string {
	if ageSecs == nil {
		return "none"
	}
	if *ageSecs < 3600 {
		return "fresh"
	}
	return "stale"
}

// mapAttestationStatusJSON converts attestation status for JSON output.
// Uses "verified" when attestation was present, "none" otherwise.
func mapAttestationStatusJSON(status *string, ageSecs *int) string {
	if status == nil || ageSecs == nil {
		return "none"
	}
	return "verified"
}

// mapOutcome converts the stored outcome to display value.
func mapOutcome(outcome store.DistributionOutcome) string {
	switch outcome {
	case store.DistributionOutcomeSuccess:
		return "success"
	case store.DistributionOutcomeBlockedStale:
		return "blocked"
	case store.DistributionOutcomeBlockedFailed:
		return "blocked"
	case store.DistributionOutcomeForced:
		return "forced"
	default:
		return string(outcome)
	}
}
