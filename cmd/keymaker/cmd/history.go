package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(historyCmd)

	// Flags for history
	historyCmd.Flags().String("target", "", "Filter by DPU name")
	historyCmd.Flags().String("operator", "", "Filter by operator email")
	historyCmd.Flags().String("tenant", "", "Filter by tenant")
	historyCmd.Flags().String("result", "", "Filter by outcome: success, blocked, forced")
	historyCmd.Flags().String("from", "", "Start date (YYYY-MM-DD)")
	historyCmd.Flags().String("to", "", "End date (YYYY-MM-DD)")
	historyCmd.Flags().Bool("verbose", false, "Show attestation details and reasons")
	historyCmd.Flags().Int("limit", 20, "Maximum results")
}

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show credential distribution history",
	Long: `Display the history of credential distributions.

Shows when credentials were distributed, to which DPUs, and whether
attestation gates allowed or blocked the operation.

Column meanings:
  ATTEST AGE  How old the attestation was at distribution time (e.g., "5m", "2h")
  RESULT      success (allowed), blocked (denied), forced (override used)

Use --verbose to see detailed reasons for blocked or forced distributions.

Examples:
  km history
  km history --target bf3-lab-01
  km history --result blocked --verbose`,
	RunE: runHistory,
}

// APIDistributionEntry represents a distribution record from the API.
type APIDistributionEntry struct {
	ID                string  `json:"id"`
	DPUName           string  `json:"target"`
	CredentialType    string  `json:"credential_type"`
	CredentialName    string  `json:"credential_name"`
	Outcome           string  `json:"outcome"`
	AttestationStatus string  `json:"attestation_status"`
	AttestationAge    *string `json:"attestation_age,omitempty"`
	InstalledPath     *string `json:"installed_path,omitempty"`
	ErrorMessage      *string `json:"error_message,omitempty"`
	OperatorID        string  `json:"operator_id"`
	OperatorEmail     string  `json:"operator_email"`
	TenantID          string  `json:"tenant_id"`
	BlockedReason     *string `json:"blocked_reason,omitempty"`
	CreatedAt         string  `json:"timestamp"`
}

// DistributionHistoryEntry represents a single distribution record for JSON/YAML output.
type DistributionHistoryEntry struct {
	Timestamp         string  `json:"timestamp"`
	Target            string  `json:"target"`
	Operator          string  `json:"operator"`
	CredentialType    string  `json:"credential_type"`
	CredentialName    string  `json:"credential_name"`
	Outcome           string  `json:"outcome"`
	AttestationStatus string  `json:"attestation_status"`
	AttestationAge    *string `json:"attestation_age,omitempty"`
	InstalledPath     *string `json:"installed_path,omitempty"`
	BlockedReason     *string `json:"blocked_reason,omitempty"`
}

func runHistory(cmd *cobra.Command, args []string) error {
	// Load config to get server URL
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("KeyMaker not initialized. Run 'km init' first")
	}

	// Get filter flags
	targetFilter, _ := cmd.Flags().GetString("target")
	operatorFilter, _ := cmd.Flags().GetString("operator")
	tenantFilter, _ := cmd.Flags().GetString("tenant")
	resultFilter, _ := cmd.Flags().GetString("result")
	fromStr, _ := cmd.Flags().GetString("from")
	toStr, _ := cmd.Flags().GetString("to")
	verbose, _ := cmd.Flags().GetBool("verbose")
	limit, _ := cmd.Flags().GetInt("limit")

	// Build query parameters
	params := url.Values{}

	if targetFilter != "" {
		params.Set("target", targetFilter)
	}
	if operatorFilter != "" {
		params.Set("operator", operatorFilter)
	}
	if tenantFilter != "" {
		params.Set("tenant", tenantFilter)
	}
	if resultFilter != "" {
		// Map user-friendly "blocked" to API outcome values
		apiResult := mapResultToAPI(resultFilter)
		if apiResult == "" {
			return fmt.Errorf("invalid result filter: %s. Valid values: success, blocked, forced", resultFilter)
		}
		params.Set("result", apiResult)
	}

	// Parse and convert dates to RFC3339
	if fromStr != "" {
		fromTime, err := parseDate(fromStr)
		if err != nil {
			return fmt.Errorf("invalid from date: %w", err)
		}
		params.Set("from", fromTime.Format(time.RFC3339))
	}
	if toStr != "" {
		toTime, err := parseDate(toStr)
		if err != nil {
			return fmt.Errorf("invalid to date: %w", err)
		}
		// Set to end of day
		toTime = toTime.Add(24*time.Hour - time.Second)
		params.Set("to", toTime.Format(time.RFC3339))
	}

	params.Set("limit", strconv.Itoa(limit))

	// Call the server API
	reqURL := config.ServerURL + "/api/distribution/history"
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	resp, err := http.Get(reqURL)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return fmt.Errorf("API error: %s", errResp.Error)
		}
		return fmt.Errorf("API error: HTTP %d", resp.StatusCode)
	}

	var distributions []APIDistributionEntry
	if err := json.NewDecoder(resp.Body).Decode(&distributions); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Handle non-table output formats
	if outputFormat != "table" {
		entries := make([]DistributionHistoryEntry, 0, len(distributions))
		for _, d := range distributions {
			entry := DistributionHistoryEntry{
				Timestamp:         d.CreatedAt,
				Target:            d.DPUName,
				Operator:          d.OperatorEmail,
				CredentialType:    d.CredentialType,
				CredentialName:    d.CredentialName,
				Outcome:           mapOutcomeDisplay(d.Outcome),
				AttestationStatus: mapAttestationStatusFromString(d.AttestationAge),
				AttestationAge:    d.AttestationAge,
				InstalledPath:     d.InstalledPath,
				BlockedReason:     d.BlockedReason,
			}
			entries = append(entries, entry)
		}
		return formatOutput(entries)
	}

	if len(distributions) == 0 {
		fmt.Println("No distribution records found matching criteria.")
		return nil
	}

	// Table output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	if verbose {
		// Verbose mode shows blocked reason
		fmt.Fprintln(w, "TIMESTAMP\tTARGET\tOPERATOR\tRESULT\tREASON")
		for _, d := range distributions {
			reason := ""
			if d.BlockedReason != nil {
				reason = *d.BlockedReason
			} else if d.AttestationAge != nil && *d.AttestationAge != "" {
				reason = formatAttestationDetailFromString(d.Outcome, *d.AttestationAge)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				formatTimestamp(d.CreatedAt),
				d.DPUName,
				d.OperatorEmail,
				mapOutcomeDisplay(d.Outcome),
				reason,
			)
		}
	} else {
		// Standard mode
		fmt.Fprintln(w, "TIMESTAMP\tOPERATOR\tTARGET\tCA\tATTEST AGE\tRESULT")
		for _, d := range distributions {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				formatTimestamp(d.CreatedAt),
				d.OperatorEmail,
				d.DPUName,
				d.CredentialName,
				formatAttestationAgeFromString(d.AttestationAge),
				mapOutcomeDisplay(d.Outcome),
			)
		}
	}
	w.Flush()
	return nil
}

// parseDate parses a YYYY-MM-DD date string.
func parseDate(dateStr string) (time.Time, error) {
	return time.Parse("2006-01-02", dateStr)
}

// mapResultToAPI converts user-friendly result names to API outcome values.
func mapResultToAPI(result string) string {
	switch result {
	case "success":
		return "success"
	case "blocked":
		// API uses OutcomePrefix matching for "blocked" to match both blocked-stale and blocked-failed
		return "blocked"
	case "forced":
		return "forced"
	default:
		return ""
	}
}

// mapOutcomeDisplay converts API outcome to display value.
func mapOutcomeDisplay(outcome string) string {
	switch outcome {
	case "success":
		return "success"
	case "blocked-stale", "blocked-failed":
		return "blocked"
	case "forced":
		return "forced"
	default:
		return outcome
	}
}

// mapAttestationStatusFromString converts attestation age string to status for JSON output.
func mapAttestationStatusFromString(ageStr *string) string {
	if ageStr == nil || *ageStr == "" {
		return "none"
	}
	// Just return the age string as-is since it's already formatted
	return *ageStr
}

// formatAttestationAgeFromString formats the attestation age for table display.
func formatAttestationAgeFromString(ageStr *string) string {
	if ageStr == nil || *ageStr == "" {
		return "none"
	}
	return *ageStr
}

// formatAttestationDetailFromString formats detailed attestation info for verbose mode.
func formatAttestationDetailFromString(outcome string, ageStr string) string {
	switch outcome {
	case "blocked-stale":
		return fmt.Sprintf("Attestation stale (%s)", ageStr)
	case "blocked-failed":
		return "Attestation verification failed"
	case "success":
		return fmt.Sprintf("Attestation verified (%s)", ageStr)
	case "forced":
		return "Override forced by operator"
	default:
		return ""
	}
}

// formatTimestamp formats an RFC3339 timestamp for table display.
func formatTimestamp(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return rfc3339
	}
	return t.Format("Jan 02, 15:04")
}
