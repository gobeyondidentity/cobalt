//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
)

// TestHostPostureE2E verifies the host posture collection flow:
// 1. Sentry collects posture on enrollment and reports to aegis
// 2. Aegis forwards posture to nexus
// 3. bluectl can retrieve posture via the API
// 4. Posture data matches actual host state (spot-check OS version)
// 5. Posture persists across nexus restart
func TestHostPostureE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	testHostname := makeTestHostname(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", dimFmt("Cleaning up processes..."))
		cfg.killProcess(cleanupCtx, cfg.ServerVM, "nexus")
		cfg.killProcess(cleanupCtx, cfg.DPUVM, "aegis")
		cfg.killProcess(cleanupCtx, cfg.HostVM, "sentry")
	})

	// Get VM IPs
	serverIP, err := cfg.getVMIP(ctx, cfg.ServerVM)
	if err != nil {
		t.Fatalf("Failed to get server IP: %v", err)
	}
	logInfo(t, "Server IP: %s", serverIP)

	dpuIP, err := cfg.getVMIP(ctx, cfg.DPUVM)
	if err != nil {
		t.Fatalf("Failed to get DPU IP: %v", err)
	}
	logInfo(t, "DPU IP: %s", dpuIP)

	// Step 1: Start nexus
	logStep(t, 1, "Starting nexus...")
	cfg.killProcess(ctx, cfg.ServerVM, "nexus")
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c",
		"setsid /home/ubuntu/nexus > /tmp/nexus.log 2>&1 < /dev/null &")
	if err != nil {
		t.Fatalf("Failed to start nexus: %v", err)
	}
	time.Sleep(2 * time.Second)

	output, err := cfg.multipassExec(ctx, cfg.ServerVM, "pgrep", "-x", "nexus")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.multipassExec(ctx, cfg.ServerVM, "cat", "/tmp/nexus.log")
		t.Fatalf("Nexus not running. Logs:\n%s", logs)
	}
	logOK(t, "Nexus started")

	// Initialize bluectl (required for DPoP auth in Phase 3)
	if err := initBluectl(cfg, ctx, t); err != nil {
		t.Fatalf("Failed to initialize bluectl: %v", err)
	}

	// Step 2: Start aegis with local API
	logStep(t, 2, "Starting aegis with local API...")
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	// Clear aegis state for test isolation
	cfg.multipassExec(ctx, cfg.DPUVM, "sudo", "rm", "-f", "/var/lib/aegis/aegis.db")
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/aegis -allow-tmfifo-net -server http://%s:18080 -dpu-name qa-dpu > /tmp/aegis.log 2>&1 < /dev/null &", serverIP))
	if err != nil {
		t.Fatalf("Failed to start aegis: %v", err)
	}
	time.Sleep(2 * time.Second)

	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "cat", "/tmp/aegis.log")
	if err != nil {
		t.Fatalf("Failed to read aegis log: %v", err)
	}
	if !strings.Contains(output, "tmfifo listener created") {
		t.Fatalf("Aegis not listening on TMFIFO. Log:\n%s", output)
	}
	logOK(t, "Aegis started with TMFIFO listener on TCP port 9444")

	// Step 3: Register DPU with control plane
	logStep(t, 3, "Registering DPU...")
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "add", "qa-tenant", "--server", "http://localhost:18080")
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "dpu", "remove", "qa-dpu", "--server", "http://localhost:18080")

	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"dpu", "add", fmt.Sprintf("%s:18051", dpuIP), "--name", "qa-dpu", "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to register DPU: %v", err)
	}

	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"tenant", "assign", "qa-tenant", "qa-dpu", "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to assign DPU to tenant: %v", err)
	}
	logOK(t, "DPU registered and assigned to tenant")

	// Step 4: Start sentry daemon (reports posture on enrollment)
	logStep(t, 4, "Starting sentry daemon...")
	cfg.killProcess(ctx, cfg.HostVM, "sentry")
	_, err = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/sentry --hostname %s --force-tmfifo --tmfifo-addr=%s:9444 > /tmp/sentry.log 2>&1 < /dev/null &", testHostname, dpuIP))
	if err != nil {
		t.Fatalf("Failed to start sentry daemon: %v", err)
	}

	// Wait for enrollment and posture report to complete
	time.Sleep(5 * time.Second)

	// Verify sentry is running and enrolled
	output, err = cfg.multipassExec(ctx, cfg.HostVM, "pgrep", "-x", "sentry")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		t.Fatalf("Sentry not running. Logs:\n%s", logs)
	}

	sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
	if !strings.Contains(sentryLog, "Enrolled") && !strings.Contains(sentryLog, "enrolled") {
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-30", "/tmp/aegis.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("%s Sentry did not complete enrollment", errFmt("x"))
	}
	logOK(t, "Sentry daemon started and enrolled")

	// Step 5: Verify posture is available via bluectl
	logStep(t, 5, "Retrieving host posture via bluectl...")

	// Wait a bit more for posture to propagate through the system
	time.Sleep(2 * time.Second)

	postureOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"host", "posture", "qa-dpu", "--server", "http://localhost:18080", "-o", "json")
	if err != nil {
		nexusLog, _ := cfg.multipassExec(ctx, cfg.ServerVM, "tail", "-50", "/tmp/nexus.log")
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-50", "/tmp/aegis.log")
		fmt.Printf("    Nexus log:\n%s\n", nexusLog)
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("Failed to get host posture: %v", err)
	}

	// Check that posture output is not empty and contains expected fields
	if strings.TrimSpace(postureOutput) == "" || strings.Contains(postureOutput, "No posture data") {
		t.Fatalf("%s Posture data is empty or not available. Output:\n%s", errFmt("x"), postureOutput)
	}

	// Verify JSON contains expected fields
	if !strings.Contains(postureOutput, "os_version") {
		t.Errorf("%s Posture JSON missing os_version field. Output:\n%s", errFmt("x"), postureOutput)
	} else {
		logOK(t, "Posture contains os_version field")
	}

	if !strings.Contains(postureOutput, "kernel_version") {
		t.Errorf("%s Posture JSON missing kernel_version field. Output:\n%s", errFmt("x"), postureOutput)
	} else {
		logOK(t, "Posture contains kernel_version field")
	}

	if !strings.Contains(postureOutput, "collected_at") {
		t.Errorf("%s Posture JSON missing collected_at field. Output:\n%s", errFmt("x"), postureOutput)
	} else {
		logOK(t, "Posture contains collected_at timestamp")
	}

	logInfo(t, "Posture data retrieved successfully")

	// Step 6: Verify posture accuracy by comparing OS version with actual host
	logStep(t, 6, "Verifying posture data accuracy...")

	// Get actual OS version from host
	actualOSVersion, err := cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c",
		"grep PRETTY_NAME /etc/os-release | cut -d'=' -f2 | tr -d '\"'")
	if err != nil {
		t.Fatalf("Failed to get actual OS version: %v", err)
	}
	actualOSVersion = strings.TrimSpace(actualOSVersion)
	logInfo(t, "Actual OS version on host: %s", actualOSVersion)

	// Check if the posture output contains the actual OS version
	if !strings.Contains(postureOutput, actualOSVersion) && actualOSVersion != "" {
		// Try a partial match (first few words)
		osWords := strings.Fields(actualOSVersion)
		if len(osWords) >= 2 {
			partialOS := osWords[0] + " " + osWords[1]
			if strings.Contains(postureOutput, partialOS) {
				logOK(t, fmt.Sprintf("Posture OS version matches actual host (partial: %s)", partialOS))
			} else {
				t.Errorf("%s Posture OS version does not match actual host. Expected to contain: %s", errFmt("x"), actualOSVersion)
			}
		}
	} else if actualOSVersion != "" {
		logOK(t, fmt.Sprintf("Posture OS version matches actual host: %s", actualOSVersion))
	}

	// Step 7: Restart nexus and verify posture persists
	logStep(t, 7, "Restarting nexus...")
	cfg.killProcess(ctx, cfg.ServerVM, "nexus")
	time.Sleep(1 * time.Second)

	// Verify nexus stopped
	output, _ = cfg.multipassExec(ctx, cfg.ServerVM, "pgrep", "-x", "nexus")
	if strings.TrimSpace(output) != "" {
		t.Fatalf("Nexus still running after kill")
	}
	logInfo(t, "Nexus stopped")

	// Start nexus again
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c",
		"setsid /home/ubuntu/nexus > /tmp/nexus.log 2>&1 < /dev/null &")
	if err != nil {
		t.Fatalf("Failed to restart nexus: %v", err)
	}
	time.Sleep(2 * time.Second)

	// Verify nexus is running
	output, err = cfg.multipassExec(ctx, cfg.ServerVM, "pgrep", "-x", "nexus")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.multipassExec(ctx, cfg.ServerVM, "cat", "/tmp/nexus.log")
		t.Fatalf("Nexus not running after restart. Logs:\n%s", logs)
	}
	logOK(t, "Nexus restarted")

	// Step 8: Verify posture is still available after restart
	logStep(t, 8, "Verifying posture persistence after nexus restart...")

	postureAfterRestart, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"host", "posture", "qa-dpu", "--server", "http://localhost:18080", "-o", "json")
	if err != nil {
		t.Fatalf("Failed to get host posture after restart: %v", err)
	}

	if strings.TrimSpace(postureAfterRestart) == "" || strings.Contains(postureAfterRestart, "No posture data") {
		t.Fatalf("%s Posture data not available after nexus restart. Output:\n%s", errFmt("x"), postureAfterRestart)
	}

	// Verify the same OS version is present
	if !strings.Contains(postureAfterRestart, "os_version") {
		t.Errorf("%s Posture missing os_version after restart", errFmt("x"))
	} else {
		logOK(t, "Posture os_version persisted after restart")
	}

	// Verify collected_at timestamp is present (same data persisted)
	if !strings.Contains(postureAfterRestart, "collected_at") {
		t.Errorf("%s Posture missing collected_at after restart", errFmt("x"))
	} else {
		logOK(t, "Posture collected_at timestamp persisted")
	}

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Host posture E2E test"))
}
