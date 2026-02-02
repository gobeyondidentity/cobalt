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

// TestAegisRestartSentryReconnection verifies that sentry automatically reconnects
// when aegis restarts. This is critical for production: at 1000+ hosts, manual
// intervention after every aegis restart is unworkable.
//
// The test verifies:
// 1. Sentry detects disconnect within 10s of aegis stopping
// 2. Sentry reconnects automatically within 30s of aegis restart
// 3. Reconnection succeeds without re-enrollment (session state preserved)
// 4. Credentials continue to work after reconnection
// 5. Multiple reconnections in sequence all succeed
// 6. All reconnection events are logged for observability
func TestAegisRestartSentryReconnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	testHostname := makeTestHostname(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout (longer due to multiple restart cycles)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// Unique CA names for this test run
	testID := fmt.Sprintf("%d", time.Now().Unix())
	caName1 := fmt.Sprintf("reconnect-ca1-%s", testID)
	caName2 := fmt.Sprintf("reconnect-ca2-%s", testID)
	caName3 := fmt.Sprintf("reconnect-ca3-%s", testID)
	caPath1 := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caName1)
	caPath2 := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caName2)
	caPath3 := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caName3)

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", dimFmt("Cleaning up processes and test artifacts..."))
		cfg.killProcess(cleanupCtx, cfg.ServerVM, "nexus")
		cfg.killProcess(cleanupCtx, cfg.DPUVM, "aegis")
		cfg.killProcess(cleanupCtx, cfg.HostVM, "sentry")

		// Clean up test CA files
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caPath1)
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caPath2)
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caPath3)
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

	// Step 2: Start aegis with local API (listens on TCP port 9444 for tmfifo transport)
	logStep(t, 2, "Starting aegis (initial)...")
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

	// Step 4: Start sentry daemon (connects directly to aegis via TCP)
	logStep(t, 4, "Starting sentry daemon (will enroll on connect)...")
	cfg.killProcess(ctx, cfg.HostVM, "sentry")
	_, err = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/sentry --hostname %s --force-tmfifo --tmfifo-addr=%s:9444 > /tmp/sentry.log 2>&1 < /dev/null &", testHostname, dpuIP))
	if err != nil {
		t.Fatalf("Failed to start sentry daemon: %v", err)
	}

	// Wait for enrollment to complete (sentry enrolls on first connect)
	time.Sleep(5 * time.Second)

	// Verify sentry is running and enrolled
	output, err = cfg.multipassExec(ctx, cfg.HostVM, "pgrep", "-x", "sentry")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		t.Fatalf("Sentry not running. Logs:\n%s", logs)
	}

	// Check sentry log for enrollment confirmation
	sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
	if !strings.Contains(sentryLog, "Enrolled") && !strings.Contains(sentryLog, "enrolled") {
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-30", "/tmp/aegis.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("%s Sentry did not complete enrollment", errFmt("x"))
	}
	logOK(t, "Sentry daemon started and enrolled")

	// Step 5: Push first credential (before any restart) to verify baseline
	logStep(t, 5, "Pushing first credential (baseline)...")
	_, _ = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", "sudo truncate -s 0 /tmp/aegis.log")
	_, _ = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c", "sudo truncate -s 0 /tmp/sentry.log")

	testCAKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTa5xOvvKPh8rO5lDXm0G8dLJHBUGYT0NxXTTZ9R1Z2 test-ca@example.com"
	testCAKeyB64 := base64.StdEncoding.EncodeToString([]byte(testCAKey))

	curlCmd := fmt.Sprintf(`curl -s -X POST http://localhost:9443/local/v1/credential -H "Content-Type: application/json" -d '{"credential_type":"ssh-ca","credential_name":"%s","data":"%s"}'`, caName1, testCAKeyB64)
	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", curlCmd)
	if err != nil || !strings.Contains(output, `"success":true`) {
		t.Fatalf("First credential push failed: %v, output: %s", err, output)
	}
	time.Sleep(3 * time.Second)

	output, err = cfg.multipassExec(ctx, cfg.HostVM, "ls", "-la", caPath1)
	if err != nil {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Fatalf("First credential file not found: %v", err)
	}
	logOK(t, "First credential delivered successfully (baseline)")

	// Step 6: Kill aegis (simulate restart)
	logStep(t, 6, "Killing aegis (simulating restart)...")
	killTime := time.Now()
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	time.Sleep(1 * time.Second)

	// Verify aegis is stopped
	output, _ = cfg.multipassExec(ctx, cfg.DPUVM, "pgrep", "-x", "aegis")
	if strings.TrimSpace(output) != "" {
		t.Fatalf("Aegis still running after kill")
	}
	logOK(t, "Aegis stopped")

	// Step 7: Verify sentry detects disconnect within 10s
	logStep(t, 7, "Verifying sentry detects disconnect within 10s...")
	disconnectDetected := false
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		if strings.Contains(sentryLog, "[RECONNECT] sentry: transport") {
			disconnectDetected = true
			elapsed := time.Since(killTime)
			logOK(t, fmt.Sprintf("Disconnect detected in %v", elapsed.Round(time.Second)))
			break
		}
	}
	if !disconnectDetected {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Errorf("%s Sentry did not detect disconnect within 10s", errFmt("x"))
	}

	// Step 8: Restart aegis
	logStep(t, 8, "Restarting aegis...")
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

	// Step 9: Verify sentry reconnects within 30s
	logStep(t, 9, "Verifying sentry reconnects within 30s...")
	reconnected := false
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		if strings.Contains(sentryLog, "[RECONNECT] sentry: reconnected successfully") {
			reconnected = true
			elapsed := time.Since(restartTime)
			logOK(t, fmt.Sprintf("Reconnected in %v", elapsed.Round(time.Second)))
			break
		}
	}
	if !reconnected {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Fatalf("%s Sentry did not reconnect within 30s", errFmt("x"))
	}

	// Step 10: Verify sentry did NOT re-enroll (session resumed)
	logStep(t, 10, "Verifying session resumed (no re-enrollment)...")
	sentryLog, _ = cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")

	// After initial enrollment, there should be no new "Enrolling" or "Enrolled" messages
	// We count occurrences - there should only be 1 from initial enrollment
	enrollCount := strings.Count(sentryLog, "Enrolled via")
	if enrollCount > 1 {
		t.Errorf("%s Sentry re-enrolled after reconnection (found %d 'Enrolled via' messages)", errFmt("x"), enrollCount)
	} else {
		logOK(t, "Session resumed without re-enrollment")
	}

	// Step 11: Push second credential (after first reconnection)
	logStep(t, 11, "Pushing second credential (after reconnection)...")
	curlCmd = fmt.Sprintf(`curl -s -X POST http://localhost:9443/local/v1/credential -H "Content-Type: application/json" -d '{"credential_type":"ssh-ca","credential_name":"%s","data":"%s"}'`, caName2, testCAKeyB64)
	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", curlCmd)
	if err != nil || !strings.Contains(output, `"success":true`) {
		t.Fatalf("Second credential push failed: %v, output: %s", err, output)
	}
	time.Sleep(3 * time.Second)

	output, err = cfg.multipassExec(ctx, cfg.HostVM, "ls", "-la", caPath2)
	if err != nil {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Fatalf("Second credential file not found after reconnection: %v", err)
	}
	logOK(t, "Second credential delivered after reconnection")

	// Step 12-13: Second restart cycle (test sequential reconnections)
	logStep(t, 12, "Second restart cycle: killing aegis...")
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	time.Sleep(1 * time.Second)
	logOK(t, "Aegis stopped (second time)")

	logStep(t, 13, "Second restart cycle: restarting aegis...")
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/aegis -allow-tmfifo-net -server http://%s:18080 -dpu-name qa-dpu >> /tmp/aegis.log 2>&1 < /dev/null &", serverIP))
	if err != nil {
		t.Fatalf("Failed to restart aegis (second time): %v", err)
	}
	time.Sleep(2 * time.Second)

	// Wait for reconnection
	reconnected = false
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		reconnectCount := strings.Count(sentryLog, "[RECONNECT] sentry: reconnected successfully")
		if reconnectCount >= 2 {
			reconnected = true
			logOK(t, "Reconnected (second time)")
			break
		}
	}
	if !reconnected {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Fatalf("%s Second reconnection failed", errFmt("x"))
	}

	// Step 14-15: Third restart cycle
	logStep(t, 14, "Third restart cycle: killing aegis...")
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	time.Sleep(1 * time.Second)
	logOK(t, "Aegis stopped (third time)")

	logStep(t, 15, "Third restart cycle: restarting aegis...")
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/aegis -allow-tmfifo-net -server http://%s:18080 -dpu-name qa-dpu >> /tmp/aegis.log 2>&1 < /dev/null &", serverIP))
	if err != nil {
		t.Fatalf("Failed to restart aegis (third time): %v", err)
	}
	time.Sleep(2 * time.Second)

	// Wait for reconnection
	reconnected = false
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		reconnectCount := strings.Count(sentryLog, "[RECONNECT] sentry: reconnected successfully")
		if reconnectCount >= 3 {
			reconnected = true
			logOK(t, "Reconnected (third time)")
			break
		}
	}
	if !reconnected {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Fatalf("%s Third reconnection failed", errFmt("x"))
	}

	// Step 16: Push third credential (after multiple reconnections)
	logStep(t, 16, "Pushing third credential (after multiple reconnections)...")
	curlCmd = fmt.Sprintf(`curl -s -X POST http://localhost:9443/local/v1/credential -H "Content-Type: application/json" -d '{"credential_type":"ssh-ca","credential_name":"%s","data":"%s"}'`, caName3, testCAKeyB64)
	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", curlCmd)
	if err != nil || !strings.Contains(output, `"success":true`) {
		t.Fatalf("Third credential push failed: %v, output: %s", err, output)
	}
	time.Sleep(3 * time.Second)

	output, err = cfg.multipassExec(ctx, cfg.HostVM, "ls", "-la", caPath3)
	if err != nil {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Fatalf("Third credential file not found after multiple reconnections: %v", err)
	}
	logOK(t, "Third credential delivered after multiple reconnections")

	// Step 17: Verify all reconnection events are logged
	logStep(t, 17, "Verifying reconnection logging for observability...")
	sentryLog, _ = cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")

	expectedMarkers := []string{
		"[RECONNECT] sentry: transport",                // disconnect detected
		"[RECONNECT] sentry: transport disconnected",   // starting reconnection
		"[RECONNECT] sentry: reconnected successfully", // reconnection complete
	}

	for _, marker := range expectedMarkers {
		if !strings.Contains(sentryLog, marker) {
			t.Errorf("%s Missing log marker: %s", errFmt("x"), marker)
		} else {
			logOK(t, fmt.Sprintf("Found log marker: %s", marker))
		}
	}

	// Verify we had exactly 3 successful reconnections
	reconnectCount := strings.Count(sentryLog, "[RECONNECT] sentry: reconnected successfully")
	if reconnectCount != 3 {
		t.Errorf("%s Expected 3 reconnections, got %d", errFmt("x"), reconnectCount)
	} else {
		logOK(t, fmt.Sprintf("All %d reconnections logged", reconnectCount))
	}

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Aegis restart sentry reconnection test"))
}
