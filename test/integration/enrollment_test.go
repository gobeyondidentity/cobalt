//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
)

// TestTMFIFOTransportIntegration is the main integration test
func TestTMFIFOTransportIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	testHostname := makeTestHostname(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Cleanup on exit (runs even on panic/timeout)
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

	// Use setsid to create a new session that survives multipass exec exit
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c",
		"setsid /home/ubuntu/nexus > /tmp/nexus.log 2>&1 < /dev/null &")
	if err != nil {
		t.Fatalf("Failed to start nexus: %v", err)
	}
	time.Sleep(2 * time.Second)

	// Verify nexus is running
	output, err := cfg.multipassExec(ctx, cfg.ServerVM, "pgrep", "-x", "nexus")
	if err != nil || strings.TrimSpace(output) == "" {
		// Check logs for clues
		logs, _ := cfg.multipassExec(ctx, cfg.ServerVM, "cat", "/tmp/nexus.log")
		t.Fatalf("Nexus not running after start. Logs:\n%s", logs)
	}
	logOK(t, "Nexus started")

	// Step 2: Start aegis (listens on TCP port 9444 for tmfifo transport)
	logStep(t, 2, "Starting aegis...")
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	// Clear aegis state for test isolation
	cfg.multipassExec(ctx, cfg.DPUVM, "sudo", "rm", "-f", "/var/lib/aegis/aegis.db")
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/aegis -local-api -allow-tmfifo-net -control-plane http://%s:18080 -dpu-name qa-dpu > /tmp/aegis.log 2>&1 < /dev/null &", serverIP))
	if err != nil {
		t.Fatalf("Failed to start aegis: %v", err)
	}
	time.Sleep(2 * time.Second)

	// Verify aegis is running and listening on TMFIFO
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

	// Create tenant (ignore error if already exists)
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "add", "qa-tenant", "--server", "http://localhost:18080")

	// Remove stale DPU registration if exists
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "dpu", "remove", "qa-dpu", "--server", "http://localhost:18080")

	// Register DPU with aegis's gRPC port (default 18051)
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"dpu", "add", fmt.Sprintf("%s:18051", dpuIP), "--name", "qa-dpu", "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to register DPU: %v", err)
	}

	// Assign DPU to tenant
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"tenant", "assign", "qa-tenant", "qa-dpu", "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to assign DPU to tenant: %v", err)
	}
	logOK(t, "DPU registered and assigned to tenant")

	// Step 4: Run sentry enrollment (connects directly to aegis via TCP)
	logStep(t, 4, "Running sentry enrollment...")
	sentryCtx, sentryCancel := context.WithTimeout(ctx, 30*time.Second)
	defer sentryCancel()

	output, err = cfg.multipassExec(sentryCtx, cfg.HostVM, "sudo", "/home/ubuntu/sentry", "--hostname", testHostname, "--force-tmfifo", fmt.Sprintf("--tmfifo-addr=%s:9444", dpuIP), "--oneshot")

	// Check results
	if err != nil {
		// Check aegis log for more context
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-30", "/tmp/aegis.log")
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("%s Sentry enrollment failed: %v", errFmt("x"), err)
	}

	// Verify expected output
	if !strings.Contains(output, "Transport: tmfifo_net") {
		t.Errorf("%s Sentry did not use TMFIFO transport", errFmt("x"))
	}
	if !strings.Contains(output, "Enrolled") {
		t.Errorf("%s Sentry did not complete enrollment", errFmt("x"))
	}

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Integration test"))
}

// TestSentryRestartReEnrollment verifies that sentry automatically re-enrolls
// when it restarts (crash, upgrade, host reboot). This is critical for production:
// hosts must rejoin the fleet without manual intervention after restarts.
func TestSentryRestartReEnrollment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	testHostname := makeTestHostname(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Unique CA name for this test run
	testID := fmt.Sprintf("%d", time.Now().Unix())
	caName := fmt.Sprintf("sentry-restart-ca-%s", testID)
	caPath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caName)

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", dimFmt("Cleaning up processes and test artifacts..."))
		cfg.killProcess(cleanupCtx, cfg.ServerVM, "nexus")
		cfg.killProcess(cleanupCtx, cfg.DPUVM, "aegis")
		cfg.killProcess(cleanupCtx, cfg.HostVM, "sentry")

		// Clean up test CA file
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caPath)
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

	// Step 2: Start aegis with local API
	logStep(t, 2, "Starting aegis with local API...")
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	cfg.multipassExec(ctx, cfg.DPUVM, "sudo", "rm", "-f", "/var/lib/aegis/aegis.db")
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/aegis -local-api -allow-tmfifo-net -control-plane http://%s:18080 -dpu-name qa-dpu > /tmp/aegis.log 2>&1 < /dev/null &", serverIP))
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

	// Step 4: Start sentry daemon (first enrollment)
	logStep(t, 4, "Starting sentry daemon (first enrollment)...")
	cfg.killProcess(ctx, cfg.HostVM, "sentry")
	_, err = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/sentry --hostname %s --force-tmfifo --tmfifo-addr=%s:9444 > /tmp/sentry.log 2>&1 < /dev/null &", testHostname, dpuIP))
	if err != nil {
		t.Fatalf("Failed to start sentry daemon: %v", err)
	}

	time.Sleep(5 * time.Second)

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
		t.Fatalf("%s Sentry did not complete first enrollment", errFmt("x"))
	}
	logOK(t, "Sentry daemon started and enrolled (first time)")

	// Step 5: Kill sentry (simulating restart)
	logStep(t, 5, "Killing sentry (simulating restart)...")
	cfg.killProcess(ctx, cfg.HostVM, "sentry")
	time.Sleep(1 * time.Second)

	output, _ = cfg.multipassExec(ctx, cfg.HostVM, "pgrep", "-x", "sentry")
	if strings.TrimSpace(output) != "" {
		t.Fatalf("Sentry still running after kill")
	}
	logOK(t, "Sentry stopped")

	// Step 6: Restart sentry (should re-enroll automatically)
	logStep(t, 6, "Restarting sentry (should re-enroll)...")
	restartTime := time.Now()

	_, _ = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c", "sudo truncate -s 0 /tmp/sentry.log")

	_, err = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/sentry --hostname %s --force-tmfifo --tmfifo-addr=%s:9444 > /tmp/sentry.log 2>&1 < /dev/null &", testHostname, dpuIP))
	if err != nil {
		t.Fatalf("Failed to restart sentry: %v", err)
	}

	time.Sleep(2 * time.Second)
	output, err = cfg.multipassExec(ctx, cfg.HostVM, "pgrep", "-x", "sentry")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		t.Fatalf("Sentry not running after restart. Logs:\n%s", logs)
	}
	logOK(t, "Sentry restarted")

	// Step 7: Verify re-enrollment within 30s
	logStep(t, 7, "Verifying re-enrollment within 30s...")
	reEnrolled := false
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		if strings.Contains(sentryLog, "Enrolled") || strings.Contains(sentryLog, "enrolled") {
			reEnrolled = true
			elapsed := time.Since(restartTime)
			logOK(t, fmt.Sprintf("Re-enrollment completed in %v", elapsed.Round(time.Second)))
			break
		}
	}
	if !reEnrolled {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-50", "/tmp/aegis.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("%s Sentry did not re-enroll within 30s", errFmt("x"))
	}

	// Step 8: Push credential after re-enrollment
	logStep(t, 8, "Pushing credential after re-enrollment...")

	_, _ = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", "sudo truncate -s 0 /tmp/aegis.log")
	_, _ = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c", "sudo truncate -s 0 /tmp/sentry.log")

	testCAKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTa5xOvvKPh8rO5lDXm0G8dLJHBUGYT0NxXTTZ9R1Z2 test-ca@example.com"
	testCAKeyB64 := base64.StdEncoding.EncodeToString([]byte(testCAKey))

	curlCmd := fmt.Sprintf(`curl -s -X POST http://localhost:9443/local/v1/credential -H "Content-Type: application/json" -d '{"credential_type":"ssh-ca","credential_name":"%s","data":"%s"}'`, caName, testCAKeyB64)
	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", curlCmd)
	if err != nil {
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-50", "/tmp/aegis.log")
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("Failed to push credential via localapi: %v", err)
	}
	if !strings.Contains(output, `"success":true`) {
		t.Fatalf("Credential push failed: %s", output)
	}
	logOK(t, "Credential push initiated")

	// Wait for credential file
	logStep(t, 9, "Waiting for credential to be installed...")
	credentialTimeout := 15 * time.Second
	pollInterval := 500 * time.Millisecond
	deadline := time.Now().Add(credentialTimeout)
	var credContent string

	for time.Now().Before(deadline) {
		output, err := cfg.multipassExec(ctx, cfg.HostVM, "cat", caPath)
		if err == nil {
			credContent = strings.TrimSpace(output)
			if strings.HasPrefix(credContent, "ssh-") || strings.HasPrefix(credContent, "ecdsa-") {
				break
			}
		}
		time.Sleep(pollInterval)
	}

	if credContent == "" || (!strings.HasPrefix(credContent, "ssh-") && !strings.HasPrefix(credContent, "ecdsa-")) {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Fatalf("Credential file not found or invalid after re-enrollment at %s", caPath)
	}
	logOK(t, fmt.Sprintf("Credential delivered to %s", caPath))

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Sentry restart re-enrollment test"))
}
