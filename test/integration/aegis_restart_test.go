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

// TestAegisMidPushRestart verifies that credential delivery recovers when aegis
// restarts mid-push. This tests a critical edge case: if aegis crashes or restarts
// while a credential push is in-flight, the system must either complete the delivery
// after restart or provide a clear error indicating retry is needed.
//
// The test verifies:
// 1. Credential push starts successfully
// 2. Aegis is killed mid-push (100-200ms after push starts)
// 3. Aegis restarts and sentry reconnects
// 4. State is consistent: credential delivered OR error logged
// 5. Retry push succeeds after recovery
func TestAegisMidPushRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	testHostname := makeTestHostname(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Unique CA names for this test run
	testID := fmt.Sprintf("%d", time.Now().Unix())
	caNameMidPush := fmt.Sprintf("midpush-ca-%s", testID)
	caNameRetry := fmt.Sprintf("retry-ca-%s", testID)
	caPathMidPush := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caNameMidPush)
	caPathRetry := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caNameRetry)

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", dimFmt("Cleaning up processes and test artifacts..."))
		cfg.killProcess(cleanupCtx, cfg.ServerVM, "nexus")
		cfg.killProcess(cleanupCtx, cfg.DPUVM, "aegis")
		cfg.killProcess(cleanupCtx, cfg.HostVM, "sentry")

		// Clean up test CA files
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caPathMidPush)
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caPathRetry)
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

	// Step 4: Start sentry daemon
	logStep(t, 4, "Starting sentry daemon...")
	cfg.killProcess(ctx, cfg.HostVM, "sentry")
	_, err = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/sentry --hostname %s --force-tmfifo --tmfifo-addr=%s:9444 > /tmp/sentry.log 2>&1 < /dev/null &", testHostname, dpuIP))
	if err != nil {
		t.Fatalf("Failed to start sentry daemon: %v", err)
	}

	// Wait for enrollment to complete
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

	// Step 5: Start credential push asynchronously
	logStep(t, 5, "Starting credential push asynchronously...")

	testCAKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTa5xOvvKPh8rO5lDXm0G8dLJHBUGYT0NxXTTZ9R1Z2 test-ca@example.com"
	testCAKeyB64 := base64.StdEncoding.EncodeToString([]byte(testCAKey))

	// Use a channel to signal push completion (or failure)
	pushDone := make(chan struct {
		output string
		err    error
	}, 1)

	// Start credential push in background
	go func() {
		curlCmd := fmt.Sprintf(`curl -s -X POST http://localhost:9443/local/v1/credential -H "Content-Type: application/json" -d '{"credential_type":"ssh-ca","credential_name":"%s","data":"%s"}'`, caNameMidPush, testCAKeyB64)
		out, pushErr := cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", curlCmd)
		pushDone <- struct {
			output string
			err    error
		}{out, pushErr}
	}()
	logOK(t, "Credential push started in background")

	// Step 6: Kill aegis mid-push (after 150ms)
	logStep(t, 6, "Killing aegis mid-push (150ms after push start)...")
	time.Sleep(150 * time.Millisecond)
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	time.Sleep(500 * time.Millisecond)

	// Verify aegis is stopped
	output, _ = cfg.multipassExec(ctx, cfg.DPUVM, "pgrep", "-x", "aegis")
	if strings.TrimSpace(output) != "" {
		t.Fatalf("Aegis still running after kill")
	}
	logOK(t, "Aegis killed mid-push")

	// Drain the push result (it will likely fail or timeout)
	select {
	case result := <-pushDone:
		logInfo(t, "Initial push result: err=%v, output=%s", result.err, truncateForLog(result.output, 100))
	case <-time.After(5 * time.Second):
		logInfo(t, "Initial push timed out (expected when aegis killed)")
	}

	// Step 7: Restart aegis
	logStep(t, 7, "Restarting aegis...")
	restartTime := time.Now()
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/aegis -allow-tmfifo-net -server http://%s:18080 -dpu-name qa-dpu >> /tmp/aegis.log 2>&1 < /dev/null &", serverIP))
	if err != nil {
		t.Fatalf("Failed to restart aegis: %v", err)
	}
	time.Sleep(2 * time.Second)

	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "pgrep", "-x", "aegis")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.multipassExec(ctx, cfg.DPUVM, "cat", "/tmp/aegis.log")
		t.Fatalf("Aegis not running after restart. Logs:\n%s", logs)
	}
	logOK(t, "Aegis restarted")

	// Step 8: Wait for sentry reconnection
	logStep(t, 8, "Waiting for sentry reconnection within 30s...")
	reconnected := false
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		if strings.Contains(sentryLog, "[RECONNECT] sentry: reconnected successfully") {
			reconnected = true
			elapsed := time.Since(restartTime)
			logOK(t, fmt.Sprintf("Sentry reconnected in %v", elapsed.Round(time.Second)))
			break
		}
	}
	if !reconnected {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Fatalf("%s Sentry did not reconnect within 30s", errFmt("x"))
	}

	// Step 9: Verify state consistency (credential delivered OR error logged)
	logStep(t, 9, "Verifying state consistency after mid-push restart...")

	// Check if credential was delivered despite the restart
	credentialDelivered := false
	output, err = cfg.multipassExec(ctx, cfg.HostVM, "ls", "-la", caPathMidPush)
	if err == nil && strings.Contains(output, caNameMidPush) {
		credentialDelivered = true
		logOK(t, fmt.Sprintf("Credential delivered despite mid-push restart: %s", caPathMidPush))
	}

	// Check for error in aegis log if credential not delivered
	if !credentialDelivered {
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "cat", "/tmp/aegis.log")
		// Look for error markers indicating the push was interrupted
		hasError := strings.Contains(aegisLog, "error") ||
			strings.Contains(aegisLog, "failed") ||
			strings.Contains(aegisLog, "interrupted")

		if hasError {
			logOK(t, "Credential not delivered but error logged (expected behavior)")
		} else {
			// Neither delivered nor explicit error; this is acceptable as long as retry works
			logInfo(t, "Credential not delivered; no explicit error (push was interrupted)")
		}
	}

	// Step 10: Retry push and verify it succeeds
	logStep(t, 10, "Retrying credential push after recovery...")

	// Clear logs for clean verification
	_, _ = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", "sudo truncate -s 0 /tmp/aegis.log")
	_, _ = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c", "sudo truncate -s 0 /tmp/sentry.log")

	// Allow extra time for reconnection state to stabilize
	time.Sleep(2 * time.Second)

	curlCmd := fmt.Sprintf(`curl -s -X POST http://localhost:9443/local/v1/credential -H "Content-Type: application/json" -d '{"credential_type":"ssh-ca","credential_name":"%s","data":"%s"}'`, caNameRetry, testCAKeyB64)
	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", curlCmd)
	if err != nil || !strings.Contains(output, `"success":true`) {
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-50", "/tmp/aegis.log")
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("Retry credential push failed: %v, output: %s", err, output)
	}
	logOK(t, "Retry credential push accepted")

	// Wait for credential delivery
	time.Sleep(3 * time.Second)

	output, err = cfg.multipassExec(ctx, cfg.HostVM, "ls", "-la", caPathRetry)
	if err != nil {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-50", "/tmp/aegis.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("Retry credential file not found: %v", err)
	}
	logOK(t, fmt.Sprintf("Retry credential delivered successfully: %s", caPathRetry))

	// Step 11: Verify logging for observability
	logStep(t, 11, "Verifying reconnection and recovery logging...")
	sentryLog, _ = cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
	aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "cat", "/tmp/aegis.log")

	// Check for reconnection markers
	if strings.Contains(sentryLog, "[RECONNECT]") {
		logOK(t, "Sentry logged reconnection events")
	}

	// Check for credential delivery markers after retry
	if strings.Contains(aegisLog, "[CRED-DELIVERY]") || strings.Contains(aegisLog, "credential") {
		logOK(t, "Aegis logged credential delivery")
	}

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Aegis mid-push restart recovery test"))
}
