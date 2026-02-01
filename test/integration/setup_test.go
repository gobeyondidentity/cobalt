//go:build integration
// +build integration

// Package integration provides integration tests for secure-infra.
// These tests require the QA VM environment (qa-server, qa-dpu, qa-host).
//
// Run with: go test -tags=integration -v -timeout 15m ./test/integration/...
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
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

// TestConfig holds the test environment configuration
type TestConfig struct {
	WorkbenchIP    string
	UseWorkbench   bool
	ServerVM       string
	DPUVM          string
	HostVM         string
	TMFIFOPort     string
	CommandTimeout time.Duration
	t              *testing.T // for logging
}

func newTestConfig(t *testing.T) *TestConfig {
	return &TestConfig{
		WorkbenchIP:    os.Getenv("WORKBENCH_IP"),
		UseWorkbench:   os.Getenv("WORKBENCH_IP") != "",
		ServerVM:       "qa-server",
		DPUVM:          "qa-dpu",
		HostVM:         "qa-host",
		TMFIFOPort:     "54321",
		CommandTimeout: 30 * time.Second,
		t:              t,
	}
}

// runCmd executes a command with timeout and returns output
func runCmd(ctx context.Context, t *testing.T, name string, args ...string) (string, error) {
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

// runSSH runs a command on workbench via SSH
func (c *TestConfig) runSSH(ctx context.Context, cmd string) (string, error) {
	if !c.UseWorkbench {
		return runCmd(ctx, c.t, "bash", "-c", cmd)
	}
	return runCmd(ctx, c.t, "ssh", fmt.Sprintf("nmelo@%s", c.WorkbenchIP), cmd)
}

// multipassExec runs a command inside a VM
func (c *TestConfig) multipassExec(ctx context.Context, vm string, args ...string) (string, error) {
	fullArgs := append([]string{"exec", vm, "--"}, args...)
	if c.UseWorkbench {
		// Quote args that contain shell metacharacters
		quotedArgs := make([]string, len(fullArgs))
		for i, arg := range fullArgs {
			if strings.ContainsAny(arg, " <>|&;$`\"'\\") {
				quotedArgs[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\\''"))
			} else {
				quotedArgs[i] = arg
			}
		}
		cmd := fmt.Sprintf("multipass %s", strings.Join(quotedArgs, " "))
		return c.runSSH(ctx, cmd)
	}
	return runCmd(ctx, c.t, "multipass", fullArgs...)
}

// getVMIP gets the IP address of a VM
func (c *TestConfig) getVMIP(ctx context.Context, vm string) (string, error) {
	var output string
	var err error
	if c.UseWorkbench {
		output, err = c.runSSH(ctx, fmt.Sprintf("multipass info %s | grep IPv4 | awk '{print $2}'", vm))
	} else {
		output, err = runCmd(ctx, c.t, "bash", "-c",
			fmt.Sprintf("multipass info %s | grep IPv4 | awk '{print $2}'", vm))
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// killProcess kills a process in a VM (logs but ignores errors)
func (c *TestConfig) killProcess(ctx context.Context, vm, process string) {
	fmt.Printf("    %s\n", dimFmt(fmt.Sprintf("...killing %s on %s", process, vm)))
	c.multipassExec(ctx, vm, "sudo", "pkill", "-9", process)
}

// logStep logs a test step in blue bold
func logStep(t *testing.T, step int, msg string) {
	fmt.Printf("\n%s %s\n", stepFmt(fmt.Sprintf("[Step %d]", step)), msg)
}

// logOK logs a success message in green
func logOK(t *testing.T, msg string) {
	fmt.Printf("    %s %s\n", okFmt("OK"), msg)
}

// logInfo logs an info message
func logInfo(t *testing.T, format string, args ...interface{}) {
	fmt.Printf("    %s\n", fmt.Sprintf(format, args...))
}

// makeTestHostname generates a unique hostname for a test
// Format: qa-host-{shortname} where shortname is test name truncated and sanitized
func makeTestHostname(t *testing.T) string {
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

// minInt returns the smaller of a or b.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extractInviteCode extracts the invite code from bluectl output.
// Output format is "Code: XXXX-XXXX-XXXX" or similar.
func extractInviteCode(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Code:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
		// Also check for just the code pattern
		if strings.Contains(line, "-") && len(line) > 10 && len(line) < 30 {
			code := strings.TrimSpace(line)
			if !strings.Contains(code, " ") {
				return code
			}
		}
	}
	return ""
}

// countJSONArrayEntries counts entries in a JSON array string.
func countJSONArrayEntries(jsonStr string) int {
	var arr []interface{}
	if err := json.Unmarshal([]byte(jsonStr), &arr); err != nil {
		return 0
	}
	return len(arr)
}

// tryBindInvite attempts to bind an invite code.
func tryBindInvite(cfg *TestConfig, ctx context.Context, serverIP, inviteCode, fingerprint, deviceName string) (string, error) {
	curlCmd := fmt.Sprintf(
		`curl -s -X POST http://%s:18080/api/v1/operator/bind -H "Content-Type: application/json" -d '{"invite_code":"%s","device_fingerprint":"%s","device_name":"%s"}'`,
		serverIP, inviteCode, fingerprint, deviceName)

	return cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c", curlCmd)
}

// truncateForLog truncates a string for logging purposes.
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// TestVMsRunning verifies all VMs are accessible
func TestVMsRunning(t *testing.T) {
	cfg := newTestConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.CommandTimeout)
	defer cancel()

	vms := []string{cfg.ServerVM, cfg.DPUVM, cfg.HostVM}
	for _, vm := range vms {
		vm := vm // capture range variable
		t.Run(vm, func(t *testing.T) {
			output, err := cfg.multipassExec(ctx, vm, "echo", "ok")
			if err != nil {
				t.Fatalf("VM %s not accessible: %v", vm, err)
			}
			if !strings.Contains(output, "ok") {
				t.Fatalf("VM %s unexpected output: %s", vm, output)
			}
		})
	}
}
