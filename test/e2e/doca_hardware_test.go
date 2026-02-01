//go:build hardware

// Package main provides end-to-end hardware tests for DOCA ComCh transport.
// These tests require real BlueField-3 hardware and are intended for hardware validation.
// Tests run locally via exec.Command. CI handles placement on the appropriate runner.
//
// Run with: go test -tags=hardware -v -run TestDOCA
//
// Required environment variables:
//   - DOCA_PCI_ADDR: DPU PCI address (default: 03:00.0)
//   - DOCA_REP_PCI_ADDR: Representor PCI address (default: 01:00.0)
//   - DOCA_SERVER_NAME: ComCh server name (default: secure-infra)
package e2e

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

// Environment variable names for hardware test configuration
const (
	envDOCAPCIAddr    = "DOCA_PCI_ADDR"
	envDOCARepPCIAddr = "DOCA_REP_PCI_ADDR"
	envDOCAServerName = "DOCA_SERVER_NAME"
	envNexusAddr      = "NEXUS_ADDR"
	envWorkbenchIP    = "WORKBENCH_IP"
)

// Default values for hardware test configuration
const (
	defaultDOCAPCIAddr    = "03:00.0"
	defaultDOCARepPCIAddr = "01:00.0"
	defaultDOCAServerName = "secure-infra"
	defaultNexusPort      = "18080"
	defaultLocalAPIPort   = "9443"
	defaultGRPCPort       = "18051"
)

// Color formatters for test output
var (
	hwStepFmt = color.New(color.FgBlue, color.Bold).SprintFunc()
	hwOkFmt   = color.New(color.FgGreen).SprintFunc()
	hwInfoFmt = color.New(color.FgYellow).SprintFunc()
	hwCmdFmt  = color.New(color.FgCyan).SprintFunc()
	hwDimFmt  = color.New(color.Faint).SprintFunc()
	hwErrFmt  = color.New(color.FgRed, color.Bold).SprintFunc()
)

func init() {
	// Force colors even when output is not a TTY
	color.NoColor = false
}

// HardwareTestConfig holds the test environment configuration for real hardware tests.
type HardwareTestConfig struct {
	DOCAPCIAddr    string        // PCI address of DOCA device on DPU
	DOCARepPCIAddr string        // Representor PCI address for host connection
	DOCAServerName string        // ComCh server name
	NexusAddr      string        // Nexus control plane address (host:port)
	WorkbenchIP    string        // Workbench IP for running local processes
	CommandTimeout time.Duration // Timeout for individual commands
	t              *testing.T    // Test context for logging
}

// TestResult captures machine-readable test results for CI reporting.
type TestResult struct {
	Test       string   `json:"test"`
	Passed     bool     `json:"passed"`
	DurationMs int64    `json:"duration_ms"`
	Transport  string   `json:"transport"`
	HostID     string   `json:"host_id,omitempty"`
	DPUName    string   `json:"dpu_name,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// newHardwareTestConfig creates a test configuration from environment variables.
func newHardwareTestConfig(t *testing.T) *HardwareTestConfig {
	pciAddr := os.Getenv(envDOCAPCIAddr)
	if pciAddr == "" {
		pciAddr = defaultDOCAPCIAddr
	}

	repPCIAddr := os.Getenv(envDOCARepPCIAddr)
	if repPCIAddr == "" {
		repPCIAddr = defaultDOCARepPCIAddr
	}

	serverName := os.Getenv(envDOCAServerName)
	if serverName == "" {
		serverName = defaultDOCAServerName
	}

	workbenchIP := os.Getenv(envWorkbenchIP)
	if workbenchIP == "" {
		workbenchIP = "localhost"
	}

	nexusAddr := os.Getenv(envNexusAddr)
	if nexusAddr == "" {
		nexusAddr = fmt.Sprintf("%s:%s", workbenchIP, defaultNexusPort)
	}

	return &HardwareTestConfig{
		DOCAPCIAddr:    pciAddr,
		DOCARepPCIAddr: repPCIAddr,
		DOCAServerName: serverName,
		NexusAddr:      nexusAddr,
		WorkbenchIP:    workbenchIP,
		CommandTimeout: 30 * time.Second,
		t:              t,
	}
}

// skipIfNoHardware skips the test if DOCA hardware is not available locally.
func (c *HardwareTestConfig) skipIfNoHardware() {
	c.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if DOCA SDK is installed locally
	output, err := c.runLocalCmd(ctx, "ls /opt/mellanox/doca 2>/dev/null || echo 'not found'")
	if err != nil || strings.Contains(output, "not found") {
		c.t.Skip("DOCA SDK not available on this machine")
	}
}

// runCmd executes a command locally with timeout and returns output.
func (c *HardwareTestConfig) runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmdStr := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	if c.t != nil {
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

	if c.t != nil {
		if len(output) > 0 {
			logOutput := output
			if len(logOutput) > 500 {
				logOutput = logOutput[:500] + "... (truncated)"
			}
			fmt.Printf("      %s %s\n", hwDimFmt(fmt.Sprintf("[%v]", elapsed.Round(time.Millisecond))), hwDimFmt(strings.TrimSpace(logOutput)))
		} else {
			fmt.Printf("      %s\n", hwDimFmt(fmt.Sprintf("[%v] (no output)", elapsed.Round(time.Millisecond))))
		}
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return output, fmt.Errorf("%s after %v: %s", hwErrFmt("TIMEOUT"), elapsed, cmdStr)
		}
		return output, fmt.Errorf("%w: %s", err, output)
	}
	return output, nil
}

// runLocalCmd runs a command locally via shell.
func (c *HardwareTestConfig) runLocalCmd(ctx context.Context, cmd string) (string, error) {
	return c.runCmd(ctx, "sh", "-c", cmd)
}

// killProcess kills a process locally (logs but ignores errors).
func (c *HardwareTestConfig) killProcess(ctx context.Context, process string) {
	fmt.Printf("    %s\n", hwDimFmt(fmt.Sprintf("...killing %s", process)))
	c.runLocalCmd(ctx, fmt.Sprintf("sudo pkill -9 %s || true", process))
}

// hwLogStep logs a test step in blue bold.
func hwLogStep(t *testing.T, step int, msg string) {
	fmt.Printf("\n%s %s\n", hwStepFmt(fmt.Sprintf("[Step %d]", step)), msg)
}

// hwLogOK logs a success message in green.
func hwLogOK(t *testing.T, msg string) {
	fmt.Printf("    %s %s\n", hwOkFmt("[OK]"), msg)
}

// hwLogInfo logs an info message.
func hwLogInfo(t *testing.T, format string, args ...interface{}) {
	fmt.Printf("    %s\n", fmt.Sprintf(format, args...))
}

// writeTestResult writes a TestResult to stdout as JSON for CI parsing.
func writeTestResult(result *TestResult) {
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("\n=== TEST RESULT ===\n%s\n===================\n", string(data))
}

// TestDOCAComchEnrollmentE2E tests full enrollment flow via real DOCA ComCh hardware.
// Tests run locally on the DPU runner. CI handles test placement.
//
// Architecture (all processes run locally on DPU):
//
//	+---------------------------+
//	| nexus (:18080)            |
//	| aegis (DOCA ComCh server) |
//	| sentry (ComCh client)     |
//	| Test driver               |
//	+---------------------------+
func TestDOCAComchEnrollmentE2E(t *testing.T) {
	cfg := newHardwareTestConfig(t)
	cfg.skipIfNoHardware()

	result := &TestResult{
		Test:      "TestDOCAComchEnrollmentE2E",
		Transport: "doca_comch",
	}
	start := time.Now()

	defer func() {
		result.DurationMs = time.Since(start).Milliseconds()
		writeTestResult(result)
	}()

	t.Log("Starting DOCA ComCh enrollment E2E test")
	hwLogInfo(t, "DOCA PCI Addr: %s", cfg.DOCAPCIAddr)
	hwLogInfo(t, "DOCA Rep PCI Addr: %s", cfg.DOCARepPCIAddr)
	hwLogInfo(t, "DOCA Server Name: %s", cfg.DOCAServerName)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Unique identifiers for this test run
	testID := fmt.Sprintf("%d", time.Now().Unix())
	dpuName := fmt.Sprintf("hw-dpu-%s", testID)
	tenantName := fmt.Sprintf("hw-tenant-%s", testID)

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", hwDimFmt("Cleaning up processes..."))
		cfg.killProcess(cleanupCtx, "aegis")
		cfg.killProcess(cleanupCtx, "nexus")
		cfg.killProcess(cleanupCtx, "sentry")
	})

	// Step 1: Kill existing aegis
	hwLogStep(t, 1, "Killing existing aegis...")
	cfg.killProcess(ctx, "aegis")
	time.Sleep(1 * time.Second)
	hwLogOK(t, "Existing aegis processes terminated")

	// Step 2: Start aegis locally with DOCA ComCh flags
	hwLogStep(t, 2, "Starting aegis locally with DOCA ComCh...")

	aegisCmd := fmt.Sprintf(
		"sudo setsid aegis "+
			"-doca-pci-addr %s "+
			"-doca-rep-pci-addr %s "+
			"-doca-server-name %s "+
			"-local-api "+
			"-control-plane http://%s "+
			"-dpu-name %s "+
			"> /tmp/aegis.log 2>&1 < /dev/null &",
		cfg.DOCAPCIAddr,
		cfg.DOCARepPCIAddr,
		cfg.DOCAServerName,
		cfg.NexusAddr,
		dpuName,
	)

	_, err := cfg.runLocalCmd(ctx, aegisCmd)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to start aegis: %v", err))
		t.Fatalf("Failed to start aegis: %v", err)
	}
	time.Sleep(3 * time.Second)
	hwLogOK(t, "Aegis start command executed")

	// Step 3: Verify ComCh listener is active
	hwLogStep(t, 3, "Verifying ComCh listener active...")

	aegisLog, err := cfg.runLocalCmd(ctx, "cat /tmp/aegis.log")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read aegis log: %v", err))
		t.Fatalf("Failed to read aegis log: %v", err)
	}

	if !strings.Contains(aegisLog, "ComCh listener created") {
		// Also check for alternative log messages
		if !strings.Contains(aegisLog, "DOCA ComCh available") && !strings.Contains(aegisLog, "transport: ComCh") {
			fmt.Printf("    Aegis log:\n%s\n", aegisLog)
			result.Errors = append(result.Errors, "ComCh listener not active")
			t.Fatalf("Aegis ComCh listener not active. Check aegis log above.")
		}
	}
	hwLogOK(t, "ComCh listener created")

	// Step 4: Start nexus locally
	hwLogStep(t, 4, "Starting nexus locally...")
	cfg.killProcess(ctx, "nexus")

	// Start nexus in background
	_, err = cfg.runLocalCmd(ctx, "setsid ./bin/nexus --no-auth > /tmp/nexus.log 2>&1 < /dev/null &")
	if err != nil {
		// Try alternate path
		_, err = cfg.runLocalCmd(ctx, "setsid nexus --no-auth > /tmp/nexus.log 2>&1 < /dev/null &")
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to start nexus: %v", err))
			t.Fatalf("Failed to start nexus: %v", err)
		}
	}
	time.Sleep(2 * time.Second)

	// Verify nexus is running
	output, err := cfg.runLocalCmd(ctx, "pgrep -x nexus")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.runLocalCmd(ctx, "cat /tmp/nexus.log")
		result.Errors = append(result.Errors, "Nexus not running after start")
		t.Fatalf("Nexus not running. Logs:\n%s", logs)
	}
	hwLogOK(t, "Nexus started on localhost")

	// Step 5: Register DPU with nexus via bluectl
	hwLogStep(t, 5, "Registering DPU with nexus...")

	// Create tenant
	_, _ = cfg.runLocalCmd(ctx, fmt.Sprintf("./bin/bluectl tenant add %s --server http://localhost:18080", tenantName))

	// Remove stale DPU if exists
	_, _ = cfg.runLocalCmd(ctx, fmt.Sprintf("./bin/bluectl dpu remove %s --server http://localhost:18080", dpuName))

	// Register DPU with aegis's gRPC port
	grpcAddr := fmt.Sprintf("localhost:%s", defaultGRPCPort)
	_, err = cfg.runLocalCmd(ctx, fmt.Sprintf("./bin/bluectl dpu add %s --name %s --server http://localhost:18080", grpcAddr, dpuName))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to register DPU: %v", err))
		t.Fatalf("Failed to register DPU: %v", err)
	}
	hwLogOK(t, fmt.Sprintf("DPU '%s' registered", dpuName))

	// Step 6: Assign DPU to tenant
	hwLogStep(t, 6, "Assigning DPU to tenant...")

	_, err = cfg.runLocalCmd(ctx, fmt.Sprintf("./bin/bluectl tenant assign %s %s --server http://localhost:18080", tenantName, dpuName))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to assign DPU: %v", err))
		t.Fatalf("Failed to assign DPU to tenant: %v", err)
	}
	hwLogOK(t, fmt.Sprintf("DPU '%s' assigned to tenant '%s'", dpuName, tenantName))
	result.DPUName = dpuName

	// Step 7: Start sentry locally with --force-comch
	hwLogStep(t, 7, "Starting sentry with --force-comch...")
	cfg.killProcess(ctx, "sentry")

	sentryCmd := fmt.Sprintf(
		"setsid ./bin/sentry "+
			"--force-comch "+
			"--doca-pci-addr %s "+
			"--doca-server-name %s "+
			"--oneshot "+
			"> /tmp/sentry.log 2>&1",
		cfg.DOCAPCIAddr,
		cfg.DOCAServerName,
	)

	sentryCtx, sentryCancel := context.WithTimeout(ctx, 60*time.Second)
	defer sentryCancel()

	_, err = cfg.runLocalCmd(sentryCtx, sentryCmd)
	if err != nil {
		sentryLog, _ := cfg.runLocalCmd(ctx, "cat /tmp/sentry.log")
		aegisLog, _ := cfg.runLocalCmd(ctx, "tail -50 /tmp/aegis.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		result.Errors = append(result.Errors, fmt.Sprintf("Sentry enrollment failed: %v", err))
		t.Fatalf("Sentry enrollment failed: %v", err)
	}

	// Step 8: Verify enrollment completed via ComCh
	hwLogStep(t, 8, "Verifying enrollment via ComCh...")

	sentryLog, _ := cfg.runLocalCmd(ctx, "cat /tmp/sentry.log")

	if !strings.Contains(sentryLog, "Transport: doca_comch") {
		result.Errors = append(result.Errors, "Sentry did not use DOCA ComCh transport")
		t.Errorf("Sentry did not use DOCA ComCh transport")
	} else {
		hwLogOK(t, "Sentry used DOCA ComCh transport")
	}

	if !strings.Contains(sentryLog, "Enrolled") && !strings.Contains(sentryLog, "enrolled") {
		result.Errors = append(result.Errors, "Sentry did not complete enrollment")
		t.Errorf("Sentry did not complete enrollment")
	} else {
		hwLogOK(t, "Sentry enrollment completed")
	}

	// Extract host ID from sentry log if available
	if idx := strings.Index(sentryLog, "Host ID:"); idx >= 0 {
		line := sentryLog[idx:]
		if newline := strings.Index(line, "\n"); newline >= 0 {
			hostIDLine := strings.TrimSpace(line[:newline])
			parts := strings.Split(hostIDLine, ":")
			if len(parts) >= 2 {
				result.HostID = strings.TrimSpace(parts[1])
				hwLogInfo(t, "Host ID: %s", result.HostID)
			}
		}
	}

	// Step 9: Verify enrollment in nexus via API
	hwLogStep(t, 9, "Verifying enrollment in nexus...")

	// List hosts via bluectl
	hostList, err := cfg.runLocalCmd(ctx, "./bin/bluectl host list --server http://localhost:18080 -o json")
	if err != nil {
		hwLogInfo(t, "Could not list hosts (command may not exist): %v", err)
	} else {
		if strings.Contains(hostList, result.HostID) || strings.Contains(hostList, "hw-") {
			hwLogOK(t, "Host enrollment visible in nexus")
		} else {
			hwLogInfo(t, "Host list: %s", hostList)
		}
	}

	// Step 10: Test complete
	hwLogStep(t, 10, "Test complete")
	result.Passed = len(result.Errors) == 0

	if result.Passed {
		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("[PASSED] DOCA ComCh Enrollment E2E test"))
	} else {
		fmt.Printf("\n%s\n", color.New(color.FgRed, color.Bold).Sprint("[FAILED] DOCA ComCh Enrollment E2E test"))
		t.Fail()
	}
}

// TestDOCAComchCredentialDeliveryE2E tests credential push via real DOCA ComCh hardware.
// Tests run locally on the DPU runner. CI handles test placement.
func TestDOCAComchCredentialDeliveryE2E(t *testing.T) {
	cfg := newHardwareTestConfig(t)
	cfg.skipIfNoHardware()

	result := &TestResult{
		Test:      "TestDOCAComchCredentialDeliveryE2E",
		Transport: "doca_comch",
	}
	start := time.Now()

	defer func() {
		result.DurationMs = time.Since(start).Milliseconds()
		writeTestResult(result)
	}()

	t.Log("Starting DOCA ComCh credential delivery E2E test")
	hwLogInfo(t, "DOCA PCI Addr: %s", cfg.DOCAPCIAddr)
	hwLogInfo(t, "DOCA Server Name: %s", cfg.DOCAServerName)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Unique identifiers for this test run
	testID := fmt.Sprintf("%d", time.Now().Unix())
	dpuName := fmt.Sprintf("hw-cred-dpu-%s", testID)
	tenantName := fmt.Sprintf("hw-cred-tenant-%s", testID)
	caName := fmt.Sprintf("hw-test-ca-%s", testID)
	caPath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caName)

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", hwDimFmt("Cleaning up processes and test artifacts..."))
		cfg.killProcess(cleanupCtx, "aegis")
		cfg.killProcess(cleanupCtx, "nexus")
		cfg.killProcess(cleanupCtx, "sentry")

		// Clean up test CA file locally
		cfg.runLocalCmd(cleanupCtx, fmt.Sprintf("sudo rm -f %s", caPath))
	})

	// Step 1: Kill existing processes
	hwLogStep(t, 1, "Cleaning up existing processes...")
	cfg.killProcess(ctx, "aegis")
	cfg.killProcess(ctx, "nexus")
	cfg.killProcess(ctx, "sentry")
	time.Sleep(1 * time.Second)
	hwLogOK(t, "Existing processes terminated")

	// Step 2: Start aegis locally
	hwLogStep(t, 2, "Starting aegis locally with DOCA ComCh...")

	aegisCmd := fmt.Sprintf(
		"sudo setsid aegis "+
			"-doca-pci-addr %s "+
			"-doca-rep-pci-addr %s "+
			"-doca-server-name %s "+
			"-local-api "+
			"-control-plane http://%s "+
			"-dpu-name %s "+
			"> /tmp/aegis.log 2>&1 < /dev/null &",
		cfg.DOCAPCIAddr,
		cfg.DOCARepPCIAddr,
		cfg.DOCAServerName,
		cfg.NexusAddr,
		dpuName,
	)

	_, err := cfg.runLocalCmd(ctx, aegisCmd)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to start aegis: %v", err))
		t.Fatalf("Failed to start aegis: %v", err)
	}
	time.Sleep(3 * time.Second)

	// Verify ComCh listener
	aegisLog, _ := cfg.runLocalCmd(ctx, "cat /tmp/aegis.log")
	if !strings.Contains(aegisLog, "ComCh") && !strings.Contains(aegisLog, "transport") {
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		result.Errors = append(result.Errors, "ComCh listener may not be active")
	}
	hwLogOK(t, "Aegis started with ComCh")

	// Step 3: Start nexus locally
	hwLogStep(t, 3, "Starting nexus locally...")

	_, err = cfg.runLocalCmd(ctx, "setsid ./bin/nexus --no-auth > /tmp/nexus.log 2>&1 < /dev/null &")
	if err != nil {
		_, err = cfg.runLocalCmd(ctx, "setsid nexus --no-auth > /tmp/nexus.log 2>&1 < /dev/null &")
	}
	time.Sleep(2 * time.Second)

	output, err := cfg.runLocalCmd(ctx, "pgrep -x nexus")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.runLocalCmd(ctx, "cat /tmp/nexus.log")
		result.Errors = append(result.Errors, "Nexus not running")
		t.Fatalf("Nexus not running. Logs:\n%s", logs)
	}
	hwLogOK(t, "Nexus started")

	// Step 4: Register DPU
	hwLogStep(t, 4, "Registering DPU with nexus...")

	_, _ = cfg.runLocalCmd(ctx, fmt.Sprintf("./bin/bluectl tenant add %s --server http://localhost:18080", tenantName))
	_, _ = cfg.runLocalCmd(ctx, fmt.Sprintf("./bin/bluectl dpu remove %s --server http://localhost:18080", dpuName))

	grpcAddr := fmt.Sprintf("localhost:%s", defaultGRPCPort)
	_, err = cfg.runLocalCmd(ctx, fmt.Sprintf("./bin/bluectl dpu add %s --name %s --server http://localhost:18080", grpcAddr, dpuName))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to register DPU: %v", err))
		t.Fatalf("Failed to register DPU: %v", err)
	}

	_, err = cfg.runLocalCmd(ctx, fmt.Sprintf("./bin/bluectl tenant assign %s %s --server http://localhost:18080", tenantName, dpuName))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to assign DPU: %v", err))
		t.Fatalf("Failed to assign DPU: %v", err)
	}
	hwLogOK(t, fmt.Sprintf("DPU '%s' registered and assigned", dpuName))
	result.DPUName = dpuName

	// Step 5: Start sentry daemon with --force-comch
	hwLogStep(t, 5, "Starting sentry daemon with --force-comch...")

	sentryCmd := fmt.Sprintf(
		"setsid ./bin/sentry "+
			"--force-comch "+
			"--doca-pci-addr %s "+
			"--doca-server-name %s "+
			"> /tmp/sentry.log 2>&1 < /dev/null &",
		cfg.DOCAPCIAddr,
		cfg.DOCAServerName,
	)

	_, err = cfg.runLocalCmd(ctx, sentryCmd)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to start sentry: %v", err))
		t.Fatalf("Failed to start sentry: %v", err)
	}

	// Wait for enrollment
	time.Sleep(5 * time.Second)

	// Verify sentry is running
	output, err = cfg.runLocalCmd(ctx, "pgrep -x sentry")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.runLocalCmd(ctx, "cat /tmp/sentry.log")
		result.Errors = append(result.Errors, "Sentry not running")
		t.Fatalf("Sentry not running. Logs:\n%s", logs)
	}

	// Verify enrollment
	sentryLog, _ := cfg.runLocalCmd(ctx, "cat /tmp/sentry.log")
	if !strings.Contains(sentryLog, "Enrolled") && !strings.Contains(sentryLog, "enrolled") {
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		result.Errors = append(result.Errors, "Sentry did not enroll")
	}
	hwLogOK(t, "Sentry daemon started and enrolled")

	// Step 6: Create SSH CA credential via bluectl or API
	hwLogStep(t, 6, "Creating SSH CA credential...")

	// Clear logs before credential push
	_, _ = cfg.runLocalCmd(ctx, "sudo truncate -s 0 /tmp/aegis.log")
	_, _ = cfg.runLocalCmd(ctx, "sudo truncate -s 0 /tmp/sentry.log")

	// Try to create SSH CA via bluectl
	_, err = cfg.runLocalCmd(ctx, fmt.Sprintf("./bin/bluectl ssh-ca add %s --tenant %s --server http://localhost:18080", caName, tenantName))
	if err != nil {
		// Fall back to direct API call if bluectl command doesn't exist
		hwLogInfo(t, "bluectl ssh-ca add not available, using direct API call")

		// Push credential directly to aegis localapi
		testCAKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTa5xOvvKPh8rO5lDXm0G8dLJHBUGYT0NxXTTZ9R1Z2 test-ca@example.com"

		curlCmd := fmt.Sprintf(
			`curl -s -X POST http://localhost:%s/local/v1/credential -H "Content-Type: application/json" -d '{"credential_type":"ssh-ca","credential_name":"%s","data":"%s"}'`,
			defaultLocalAPIPort, caName, testCAKey,
		)
		output, err = cfg.runLocalCmd(ctx, curlCmd)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to push credential: %v", err))
			t.Fatalf("Failed to push credential: %v", err)
		}
		if !strings.Contains(output, "success") {
			result.Errors = append(result.Errors, fmt.Sprintf("Credential push failed: %s", output))
			t.Fatalf("Credential push failed: %s", output)
		}
	}
	hwLogOK(t, fmt.Sprintf("SSH CA credential '%s' created", caName))

	// Wait for credential to propagate
	time.Sleep(5 * time.Second)

	// Step 7: Verify credential delivery logs
	hwLogStep(t, 7, "Verifying credential delivery logs...")

	aegisLog, _ = cfg.runLocalCmd(ctx, "cat /tmp/aegis.log")
	sentryLog, _ = cfg.runLocalCmd(ctx, "cat /tmp/sentry.log")

	// Check for credential delivery markers
	if strings.Contains(aegisLog, "[CRED-DELIVERY]") || strings.Contains(aegisLog, "CREDENTIAL_PUSH") {
		hwLogOK(t, "Aegis logged credential delivery")
	} else {
		hwLogInfo(t, "No credential delivery markers in aegis log")
	}

	if strings.Contains(sentryLog, "[CRED-DELIVERY]") || strings.Contains(sentryLog, "CREDENTIAL_PUSH") {
		hwLogOK(t, "Sentry received credential push")
	} else {
		hwLogInfo(t, "No credential delivery markers in sentry log")
	}

	// Step 8: Verify credential file exists on host
	hwLogStep(t, 8, "Verifying credential installation on host...")

	output, err = cfg.runLocalCmd(ctx, fmt.Sprintf("ls -la %s", caPath))
	if err != nil {
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		result.Errors = append(result.Errors, fmt.Sprintf("Credential file not found at %s", caPath))
		t.Errorf("Credential file not found at %s: %v", caPath, err)
	} else {
		hwLogOK(t, fmt.Sprintf("Credential file exists: %s", strings.TrimSpace(output)))

		// Verify permissions
		if strings.Contains(output, "-rw-r--r--") {
			hwLogOK(t, "Permissions are correct (0644)")
		} else {
			result.Errors = append(result.Errors, "Incorrect file permissions")
			t.Errorf("Incorrect permissions: %s", output)
		}

		// Verify content
		content, _ := cfg.runLocalCmd(ctx, fmt.Sprintf("cat %s", caPath))
		if strings.HasPrefix(strings.TrimSpace(content), "ssh-") {
			hwLogOK(t, "Credential contains valid SSH public key")
		} else {
			result.Errors = append(result.Errors, "Invalid SSH key content")
			t.Errorf("Invalid SSH key content: %s", content[:50])
		}
	}

	// Step 9: Test complete
	hwLogStep(t, 9, "Test complete")
	result.Passed = len(result.Errors) == 0

	if result.Passed {
		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("[PASSED] DOCA ComCh Credential Delivery E2E test"))
	} else {
		fmt.Printf("\n%s\n", color.New(color.FgRed, color.Bold).Sprint("[FAILED] DOCA ComCh Credential Delivery E2E test"))
		t.Fail()
	}
}

// TestDOCAComchHardwareDetection verifies that DOCA hardware is available locally.
// This is a quick smoke test to run before the full E2E tests.
// Tests run locally on the DPU runner. CI handles test placement.
func TestDOCAComchHardwareDetection(t *testing.T) {
	cfg := newHardwareTestConfig(t)

	t.Log("Checking DOCA hardware availability")
	hwLogInfo(t, "DOCA PCI Addr: %s", cfg.DOCAPCIAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: Check DOCA availability
	hwLogStep(t, 1, "Checking DOCA SDK availability...")

	output, err := cfg.runLocalCmd(ctx, "ls -la /opt/mellanox/doca 2>/dev/null || echo 'DOCA not found'")
	if err != nil || strings.Contains(output, "DOCA not found") {
		t.Skip("DOCA SDK not installed on this machine")
	}
	hwLogOK(t, "DOCA SDK found at /opt/mellanox/doca")

	// Step 2: Check for ComCh device
	hwLogStep(t, 2, "Checking for ComCh-capable device...")

	output, _ = cfg.runLocalCmd(ctx, "ls -la /dev/infiniband 2>/dev/null || echo 'No IB devices'")
	if strings.Contains(output, "No IB devices") {
		hwLogInfo(t, "No /dev/infiniband found, ComCh may not be available")
	} else {
		hwLogOK(t, "InfiniBand devices found")
	}

	// Step 3: Check PCI device
	hwLogStep(t, 3, "Checking PCI device...")

	output, _ = cfg.runLocalCmd(ctx, fmt.Sprintf("lspci -s %s 2>/dev/null || echo 'Device not found'", cfg.DOCAPCIAddr))
	if strings.Contains(output, "Device not found") || strings.TrimSpace(output) == "" {
		hwLogInfo(t, "PCI device %s not found, check DOCA_PCI_ADDR", cfg.DOCAPCIAddr)
	} else {
		hwLogOK(t, fmt.Sprintf("PCI device found: %s", strings.TrimSpace(output)))
	}

	// Step 4: Check aegis binary
	hwLogStep(t, 4, "Checking aegis binary...")

	output, _ = cfg.runLocalCmd(ctx, "which aegis 2>/dev/null || ls -la ./bin/aegis 2>/dev/null || echo 'aegis not found'")
	if strings.Contains(output, "aegis not found") {
		t.Skip("aegis binary not found, build with: go build -o bin/aegis ./cmd/aegis")
	}
	hwLogOK(t, "aegis binary found")

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("[PASSED] Hardware detection complete"))
}
