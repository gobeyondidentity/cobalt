package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nmelo/secure-infra/pkg/clierror"
	"github.com/nmelo/secure-infra/pkg/sshscan"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Exit codes specific to discover scan (per spec)
const (
	ExitDiscoverSuccess       = 0 // All hosts succeeded
	ExitDiscoverAllFailed     = 1 // All hosts failed
	ExitDiscoverPartialFailed = 2 // Some hosts succeeded, some failed
	ExitDiscoverConfigError   = 3 // Configuration error
)

func init() {
	rootCmd.AddCommand(discoverCmd)
	discoverCmd.AddCommand(discoverScanCmd)

	// Flags for discover scan
	discoverScanCmd.Flags().Bool("all", false, "Scan all registered hosts")
	discoverScanCmd.Flags().Bool("ssh", false, "Force SSH mode for single host (bootstrap)")
	discoverScanCmd.Flags().Bool("ssh-fallback", false, "Use SSH fallback for hosts without agent")
	discoverScanCmd.Flags().String("ssh-user", "", "SSH username (default: current user)")
	discoverScanCmd.Flags().String("ssh-key", "", "SSH private key path")
	discoverScanCmd.Flags().Int("parallel", 10, "Max concurrent scans")
	discoverScanCmd.Flags().Int("timeout", 30, "Per-host timeout in seconds")
	discoverScanCmd.Flags().Bool("no-color", false, "Disable colored output")
}

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover SSH keys and configuration on hosts",
	Long: `Commands to discover SSH keys and configuration across registered hosts.

The discover command helps operators understand the current SSH key landscape
before migrating to certificate-based authentication.`,
}

var discoverScanCmd = &cobra.Command{
	Use:   "scan [HOST]",
	Short: "Scan hosts for SSH authorized_keys",
	Long: `Scan one or more hosts for SSH authorized_keys files.

By default, scans a single host via the host-agent. Use --all to scan all
registered hosts in parallel.

Examples:
  km discover scan gpu-node-01
  km discover scan --all
  km discover scan gpu-node-01 -o json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDiscoverScan,
}

// Host represents a registered host from the control plane
type Host struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	DPUName  string `json:"dpu_name,omitempty"`
	Tenant   string `json:"tenant,omitempty"`
	HasAgent bool   `json:"has_agent"`
	LastSeen string `json:"last_seen,omitempty"`
}

// ScanResult represents the result of scanning a single host
type ScanResult struct {
	Host     string         `json:"host"`
	Method   string         `json:"method"`
	Keys     []sshscan.SSHKey `json:"keys"`
	Error    string         `json:"error,omitempty"`
	ScannedAt string        `json:"scanned_at"`
}

// ScanSummary represents the aggregated scan results
type ScanSummary struct {
	ScanTime         string            `json:"scan_time"`
	HostsScanned     int               `json:"hosts_scanned"`
	HostsSucceeded   int               `json:"hosts_succeeded"`
	HostsFailed      int               `json:"hosts_failed"`
	TotalKeys        int               `json:"total_keys"`
	MethodBreakdown  map[string]int    `json:"method_breakdown"`
	Keys             []ScanResultKey   `json:"keys"`
	Failures         []ScanFailure     `json:"failures"`
}

// ScanResultKey is the JSON output format for a single key
type ScanResultKey struct {
	Host        string `json:"host"`
	Method      string `json:"method"`
	User        string `json:"user"`
	KeyType     string `json:"key_type"`
	KeyBits     int    `json:"key_bits"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
	FilePath    string `json:"file_path"`
}

// ScanFailure represents a failed host scan
type ScanFailure struct {
	Host  string `json:"host"`
	Error string `json:"error"`
}

func runDiscoverScan(cmd *cobra.Command, args []string) error {
	scanAll, _ := cmd.Flags().GetBool("all")
	sshMode, _ := cmd.Flags().GetBool("ssh")
	sshFallback, _ := cmd.Flags().GetBool("ssh-fallback")

	// Validate flag combinations
	if sshMode && scanAll {
		fmt.Fprintln(os.Stderr, "Error: --ssh flag not allowed with --all (use --ssh-fallback instead)")
		os.Exit(ExitDiscoverConfigError)
	}
	if sshMode && sshFallback {
		fmt.Fprintln(os.Stderr, "Error: --ssh and --ssh-fallback are mutually exclusive")
		os.Exit(ExitDiscoverConfigError)
	}

	// Validate arguments
	if !scanAll && len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: HOST argument required unless --all is specified")
		os.Exit(ExitDiscoverConfigError)
	}
	if scanAll && len(args) > 0 {
		fmt.Fprintln(os.Stderr, "Error: HOST argument not allowed with --all flag")
		os.Exit(ExitDiscoverConfigError)
	}

	// Load config to get control plane URL
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: operator not bound. Run 'km init' first.")
		os.Exit(ExitDiscoverConfigError)
	}

	if scanAll {
		return runScanAllHosts(cmd, config, sshFallback)
	}

	return runScanSingleHost(cmd, config, args[0], sshMode)
}

func runScanSingleHost(cmd *cobra.Command, config *KMConfig, hostArg string, sshMode bool) error {
	timeout, _ := cmd.Flags().GetInt("timeout")
	sshUser, _ := cmd.Flags().GetString("ssh-user")
	sshKeyPath, _ := cmd.Flags().GetString("ssh-key")

	// Use current user as default SSH user
	if sshUser == "" {
		sshUser = getDefaultSSHUser()
	}

	var result *ScanResult
	var err error

	if sshMode {
		// SSH bootstrap mode: print warning and scan directly via SSH
		fmt.Fprintln(os.Stderr, "Warning: Bootstrap mode. Install host-agent for production use.")

		result, err = scanHostSSH(hostArg, sshUser, sshKeyPath, time.Duration(timeout)*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s: %v\n", hostArg, err)
			os.Exit(ExitDiscoverAllFailed)
		}
	} else {
		// Agent mode: find host in registry and scan via control plane
		host, err := findHost(config, hostArg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(ExitDiscoverAllFailed)
		}

		result, err = scanHost(config, host, timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s: %v\n", host.Name, err)
			os.Exit(ExitDiscoverAllFailed)
		}
	}

	// Output results
	if outputFormat == "json" {
		return outputSingleHostJSON(result)
	}

	return outputSingleHostTable(result)
}

func runScanAllHosts(cmd *cobra.Command, config *KMConfig, sshFallback bool) error {
	timeout, _ := cmd.Flags().GetInt("timeout")
	noColor, _ := cmd.Flags().GetBool("no-color")
	sshUser, _ := cmd.Flags().GetString("ssh-user")
	sshKeyPath, _ := cmd.Flags().GetString("ssh-key")

	// Use current user as default SSH user
	if sshUser == "" {
		sshUser = getDefaultSSHUser()
	}

	// Get all hosts
	hosts, err := listHosts(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(ExitDiscoverConfigError)
	}

	if len(hosts) == 0 {
		fmt.Println("No hosts registered.")
		return nil
	}

	// Check if we should show progress (TTY and not JSON)
	showProgress := term.IsTerminal(int(os.Stderr.Fd())) && outputFormat != "json" && !noColor

	var results []ScanResult
	var failures []ScanFailure
	methodCounts := map[string]int{"agent": 0, "ssh": 0}
	totalKeys := 0
	bootstrapWarningShown := false

	// Scan hosts sequentially (parallel will be added later)
	for i, host := range hosts {
		if showProgress {
			fmt.Fprintf(os.Stderr, "\rScanning host %d/%d...", i+1, len(hosts))
		}

		// Try agent first
		result, err := scanHost(config, &host, timeout)
		if err != nil {
			// If SSH fallback enabled and host doesn't have agent, try SSH
			if sshFallback && !host.HasAgent {
				// Show bootstrap warning once per scan
				if !bootstrapWarningShown {
					// Clear progress line before warning if showing progress
					if showProgress {
						fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 40))
					}
					fmt.Fprintln(os.Stderr, "Warning: Bootstrap mode. Install host-agent for production use.")
					bootstrapWarningShown = true
				}

				// Determine hostname for SSH connection
				sshHostname := host.Hostname
				if sshHostname == "" {
					sshHostname = host.Name
				}

				result, err = scanHostSSH(sshHostname, sshUser, sshKeyPath, time.Duration(timeout)*time.Second)
				if err != nil {
					failures = append(failures, ScanFailure{
						Host:  host.Name,
						Error: err.Error(),
					})
					continue
				}
				// Update host name in result to match registry name
				result.Host = host.Name
			} else {
				failures = append(failures, ScanFailure{
					Host:  host.Name,
					Error: err.Error(),
				})
				continue
			}
		}

		results = append(results, *result)
		methodCounts[result.Method]++
		totalKeys += len(result.Keys)
	}

	// Clear progress line
	if showProgress {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 40))
	}

	// Output results
	if outputFormat == "json" {
		return outputAllHostsJSON(results, failures, methodCounts, totalKeys)
	}

	return outputAllHostsTable(results, failures, methodCounts, totalKeys)
}

func findHost(config *KMConfig, nameOrHostname string) (*Host, error) {
	hosts, err := listHosts(config)
	if err != nil {
		return nil, err
	}

	// Search by name first, then hostname
	for _, h := range hosts {
		if h.Name == nameOrHostname || h.Hostname == nameOrHostname {
			return &h, nil
		}
	}

	return nil, fmt.Errorf("host '%s' not found in registry", nameOrHostname)
}

func listHosts(config *KMConfig) ([]Host, error) {
	resp, err := http.Get(config.ControlPlaneURL + "/api/v1/hosts")
	if err != nil {
		return nil, clierror.ConnectionFailed("server")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("failed to list hosts: %s", errResp.Error)
		}
		return nil, fmt.Errorf("failed to list hosts: HTTP %d", resp.StatusCode)
	}

	// Response format: {"hosts": [...]}
	var hostsResp struct {
		Hosts []Host `json:"hosts"`
	}
	if err := json.Unmarshal(body, &hostsResp); err != nil {
		return nil, fmt.Errorf("failed to parse hosts response: %w", err)
	}

	return hostsResp.Hosts, nil
}

func scanHost(config *KMConfig, host *Host, timeout int) (*ScanResult, error) {
	// Build scan request URL
	scanURL := fmt.Sprintf("%s/api/v1/hosts/%s/scan", config.ControlPlaneURL, url.PathEscape(host.Name))

	// Create request with method specification
	reqBody := map[string]string{"method": "agent"}
	reqJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", scanURL, strings.NewReader(string(reqJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Create client with timeout
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		if os.IsTimeout(err) || strings.Contains(err.Error(), "timeout") {
			return nil, fmt.Errorf("timeout after %ds (check network)", timeout)
		}
		return nil, fmt.Errorf("connection refused (is host-agent running?)")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("scan failed: HTTP %d", resp.StatusCode)
	}

	// Parse response
	var scanResp struct {
		Host      string `json:"host"`
		Method    string `json:"method"`
		Keys      []struct {
			User        string `json:"user"`
			KeyType     string `json:"key_type"`
			KeyBits     int    `json:"key_bits"`
			Fingerprint string `json:"fingerprint"`
			Comment     string `json:"comment"`
			FilePath    string `json:"file_path"`
		} `json:"keys"`
		ScannedAt string `json:"scanned_at"`
	}
	if err := json.Unmarshal(body, &scanResp); err != nil {
		return nil, fmt.Errorf("failed to parse scan response: %w", err)
	}

	// Convert to ScanResult
	result := &ScanResult{
		Host:      scanResp.Host,
		Method:    scanResp.Method,
		ScannedAt: scanResp.ScannedAt,
		Keys:      make([]sshscan.SSHKey, 0, len(scanResp.Keys)),
	}

	for _, k := range scanResp.Keys {
		result.Keys = append(result.Keys, sshscan.SSHKey{
			User:        k.User,
			KeyType:     k.KeyType,
			KeyBits:     k.KeyBits,
			Fingerprint: k.Fingerprint,
			Comment:     k.Comment,
			FilePath:    k.FilePath,
		})
	}

	return result, nil
}

func outputSingleHostJSON(result *ScanResult) error {
	summary := ScanSummary{
		ScanTime:       result.ScannedAt,
		HostsScanned:   1,
		HostsSucceeded: 1,
		HostsFailed:    0,
		TotalKeys:      len(result.Keys),
		MethodBreakdown: map[string]int{
			result.Method: 1,
		},
		Keys:     make([]ScanResultKey, 0, len(result.Keys)),
		Failures: []ScanFailure{},
	}

	for _, k := range result.Keys {
		summary.Keys = append(summary.Keys, ScanResultKey{
			Host:        result.Host,
			Method:      result.Method,
			User:        k.User,
			KeyType:     k.KeyType,
			KeyBits:     k.KeyBits,
			Fingerprint: k.Fingerprint,
			Comment:     k.Comment,
			FilePath:    k.FilePath,
		})
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func outputSingleHostTable(result *ScanResult) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tMETHOD\tUSER\tTYPE\tFINGERPRINT\tCOMMENT")

	for _, k := range result.Keys {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			truncate(result.Host, 14),
			result.Method,
			truncate(k.User, 8),
			truncate(k.KeyType, 10),
			truncate(k.Fingerprint, 44),
			truncate(k.Comment, 20),
		)
	}
	w.Flush()

	fmt.Printf("\nFound %d keys on 1 host (%s)\n", len(result.Keys), result.Method)
	return nil
}

func outputAllHostsJSON(results []ScanResult, failures []ScanFailure, methodCounts map[string]int, totalKeys int) error {
	summary := ScanSummary{
		ScanTime:        time.Now().UTC().Format(time.RFC3339),
		HostsScanned:    len(results) + len(failures),
		HostsSucceeded:  len(results),
		HostsFailed:     len(failures),
		TotalKeys:       totalKeys,
		MethodBreakdown: methodCounts,
		Keys:            make([]ScanResultKey, 0, totalKeys),
		Failures:        failures,
	}

	for _, r := range results {
		for _, k := range r.Keys {
			summary.Keys = append(summary.Keys, ScanResultKey{
				Host:        r.Host,
				Method:      r.Method,
				User:        k.User,
				KeyType:     k.KeyType,
				KeyBits:     k.KeyBits,
				Fingerprint: k.Fingerprint,
				Comment:     k.Comment,
				FilePath:    k.FilePath,
			})
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return err
	}

	// Set exit code based on results
	if len(results) == 0 && len(failures) > 0 {
		os.Exit(ExitDiscoverAllFailed)
	} else if len(failures) > 0 {
		os.Exit(ExitDiscoverPartialFailed)
	}

	return nil
}

func outputAllHostsTable(results []ScanResult, failures []ScanFailure, methodCounts map[string]int, totalKeys int) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tMETHOD\tUSER\tTYPE\tFINGERPRINT\tCOMMENT")

	for _, r := range results {
		for _, k := range r.Keys {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				truncate(r.Host, 14),
				r.Method,
				truncate(k.User, 8),
				truncate(k.KeyType, 10),
				truncate(k.Fingerprint, 44),
				truncate(k.Comment, 20),
			)
		}
	}
	w.Flush()

	// Build method breakdown string
	var methodParts []string
	for method, count := range methodCounts {
		if count > 0 {
			methodParts = append(methodParts, fmt.Sprintf("%d %s", count, method))
		}
	}
	methodStr := strings.Join(methodParts, ", ")

	fmt.Printf("\nFound %d keys on %d hosts (%s)\n", totalKeys, len(results), methodStr)

	// Show failures if any
	if len(failures) > 0 {
		fmt.Printf("\nScan complete: %d/%d hosts succeeded\n", len(results), len(results)+len(failures))
		fmt.Println("\nFailed:")
		for _, f := range failures {
			fmt.Printf("  %s: %s\n", f.Host, f.Error)
		}
	}

	// Set exit code based on results
	if len(results) == 0 && len(failures) > 0 {
		os.Exit(ExitDiscoverAllFailed)
	} else if len(failures) > 0 {
		os.Exit(ExitDiscoverPartialFailed)
	}

	return nil
}

// truncate shortens a string to maxLen characters, adding "..." if truncated
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// getDefaultSSHUser returns the current username for SSH connections
func getDefaultSSHUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}
