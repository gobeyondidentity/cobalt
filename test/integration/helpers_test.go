//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
)

// Color formatters
var (
	stepFmt = color.New(color.FgBlue, color.Bold).SprintFunc()
	okFmt   = color.New(color.FgGreen).SprintFunc()
	infoFmt = color.New(color.FgYellow).SprintFunc()
	cmdFmt  = color.New(color.FgCyan).SprintFunc()
	dimFmt  = color.New(color.Faint).SprintFunc()
	errFmt  = color.New(color.FgRed, color.Bold).SprintFunc()
)

func init() {
	// Force colors even when output is not a TTY (e.g., over SSH)
	color.NoColor = false
}

// runCmd executes a command with timeout and returns output
func runCmd(ctx context.Context, t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	cmdStr := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	if t != nil {
		// Command in bold yellow to make it pop
		fmt.Printf("    %s %s\n", color.New(color.FgCyan, color.Bold).Sprint("$"), color.New(color.FgHiYellow, color.Bold).Sprint(cmdStr))
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	elapsed := time.Since(start)
	output := stdout.String() + stderr.String()

	if t != nil {
		// Output in dim gray for contrast
		if len(output) > 0 {
			// Truncate very long output
			logOutput := output
			if len(logOutput) > 500 {
				logOutput = logOutput[:500] + "... (truncated)"
			}
			fmt.Printf("      %s %s\n", dimFmt(fmt.Sprintf("[%v]", elapsed.Round(time.Millisecond))), dimFmt(strings.TrimSpace(logOutput)))
		} else {
			fmt.Printf("      %s\n", dimFmt(fmt.Sprintf("[%v] (no output)", elapsed.Round(time.Millisecond))))
		}
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return output, fmt.Errorf("%s after %v: %s", errFmt("TIMEOUT"), elapsed, cmdStr)
		}
		return output, fmt.Errorf("%w: %s", err, output)
	}
	return output, nil
}

// logStep logs a test step in blue bold
func logStep(t *testing.T, step int, msg string) {
	t.Helper()
	fmt.Printf("\n%s %s\n", stepFmt(fmt.Sprintf("[Step %d]", step)), msg)
}

// logOK logs a success message in green
func logOK(t *testing.T, msg string) {
	t.Helper()
	fmt.Printf("    %s %s\n", okFmt("✓"), msg)
}

// logInfo logs an info message
func logInfo(t *testing.T, format string, args ...interface{}) {
	t.Helper()
	fmt.Printf("    %s\n", fmt.Sprintf(format, args...))
}

// makeTestHostname generates a unique hostname for a test
// Format: qa-host-{shortname} where shortname is test name truncated and sanitized
func makeTestHostname(t *testing.T) string {
	t.Helper()
	name := t.Name()
	// Remove "Test" prefix and truncate for readability
	name = strings.TrimPrefix(name, "Test")
	// Sanitize: lowercase, replace non-alphanumeric with dash
	var sb strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	shortName := sb.String()
	if len(shortName) > 20 {
		shortName = shortName[:20]
	}
	return "qa-host-" + shortName
}

// min returns the smaller of a or b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extractInviteCode extracts an invite code from bluectl output.
// Looks for "Code: XXXX-XXXX-XXXX" pattern.
func extractInviteCode(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Code:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// countJSONArrayEntries counts entries in a JSON array string.
// Returns 0 if the string is not a valid JSON array or is empty.
func countJSONArrayEntries(jsonStr string) int {
	jsonStr = strings.TrimSpace(jsonStr)
	if jsonStr == "" || jsonStr == "[]" {
		return 0
	}

	// Simple counting by looking for objects in the array
	// This is a rough count based on "}," occurrences plus 1
	count := strings.Count(jsonStr, "{")
	return count
}

// initBluectl initializes bluectl on qa-server by enrolling as admin.
// This must be called after nexus starts and before any bluectl API operations.
// Phase 3 authorization layer requires DPoP authentication on all API endpoints.
func initBluectl(cfg *TestConfig, ctx context.Context, t *testing.T) error {
	t.Helper()
	logInfo(t, "Initializing bluectl (enrolling as admin)...")

	// Clear existing bluectl config to force fresh enrollment
	cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-rf", "/home/ubuntu/.config/bluectl")

	output, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"init", "--server", "http://localhost:18080", "--force")
	if err != nil {
		return fmt.Errorf("bluectl init failed: %w\nOutput: %s", err, output)
	}

	logOK(t, "bluectl initialized (admin enrolled)")
	return nil
}

