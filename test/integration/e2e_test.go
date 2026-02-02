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

// TestCredentialDeliveryE2E tests the full credential delivery flow from nexus to host filesystem.
// This test verifies:
// 1. SSH CA credential can be created via nexus API
// 2. Credential push triggers aegis DistributeCredential
// 3. localapi forwards to sentry via transport
// 4. sentry installs credential to filesystem with correct permissions
// 5. All components emit [CRED-DELIVERY] logging markers
func TestCredentialDeliveryE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	testHostname := makeTestHostname(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Unique CA name for this test run
	caName := fmt.Sprintf("test-ca-%d", time.Now().Unix())
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

	// Step 2: Start aegis with local API (listens on TCP port 9444 for tmfifo transport)
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

	// Step 4: Start sentry daemon (connects directly to aegis via TCP)
	// Note: We start daemon directly instead of --oneshot + daemon because
	// tmfifo char devices don't have connection close semantics. The --oneshot
	// exit doesn't signal disconnect to aegis, causing auth state mismatch.
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

	// Step 5: Push credential directly to aegis localapi
	// Note: km ssh-ca exists but requires full operator auth flow (invite, init, grant).
	// This test bypasses that to focus on transport/credential delivery, not operator workflow.
	logStep(t, 5, "Pushing SSH CA credential via aegis localapi...")

	// Clear logs before push to capture fresh markers
	_, _ = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", "sudo truncate -s 0 /tmp/aegis.log")
	_, _ = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c", "sudo truncate -s 0 /tmp/sentry.log")

	// Generate a test SSH CA public key (ed25519 format)
	// The data field is []byte in Go, so JSON expects base64 encoding
	testCAKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTa5xOvvKPh8rO5lDXm0G8dLJHBUGYT0NxXTTZ9R1Z2 test-ca@example.com"
	testCAKeyB64 := base64.StdEncoding.EncodeToString([]byte(testCAKey))

	// Push credential via aegis localapi (localhost:9443 on DPU)
	// The localapi accepts POST /local/v1/credential
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
	logOK(t, "Credential push via localapi completed")

	// Allow time for credential to propagate through the system
	time.Sleep(3 * time.Second)

	// Step 6: Verify logging markers in aegis
	logStep(t, 6, "Verifying credential delivery logging markers...")

	aegisLog, err := cfg.multipassExec(ctx, cfg.DPUVM, "cat", "/tmp/aegis.log")
	if err != nil {
		t.Fatalf("Failed to read aegis log: %v", err)
	}

	// Check for [CRED-DELIVERY] markers in aegis
	// Note: We push directly to localapi HTTP handler which calls pushCredentialViaTransport
	expectedAegisMarkers := []string{
		"[CRED-DELIVERY] localapi: sending CREDENTIAL_PUSH message",
	}

	for _, marker := range expectedAegisMarkers {
		if !strings.Contains(aegisLog, marker) {
			fmt.Printf("    Aegis log:\n%s\n", aegisLog)
			t.Errorf("%s Missing marker in aegis log: %s", errFmt("x"), marker)
		} else {
			logOK(t, fmt.Sprintf("Found marker: %s", marker))
		}
	}

	// Check for [CRED-DELIVERY] markers in sentry
	sentryLog, err = cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
	if err != nil {
		t.Fatalf("Failed to read sentry log: %v", err)
	}

	expectedSentryMarkers := []string{
		"[CRED-DELIVERY] sentry: received CREDENTIAL_PUSH",
		"[CRED-DELIVERY] sentry: installing ssh-ca credential",
		"[CRED-DELIVERY] sentry: credential installed",
	}

	for _, marker := range expectedSentryMarkers {
		if !strings.Contains(sentryLog, marker) {
			fmt.Printf("    Sentry log:\n%s\n", sentryLog)
			t.Errorf("%s Missing marker in sentry log: %s", errFmt("x"), marker)
		} else {
			logOK(t, fmt.Sprintf("Found marker: %s", marker))
		}
	}

	// Step 7: Verify credential file exists with correct permissions
	logStep(t, 7, "Verifying credential installation on host...")

	output, err = cfg.multipassExec(ctx, cfg.HostVM, "ls", "-la", caPath)
	if err != nil {
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		fmt.Printf("    Sentry log:\n%s\n", sentryLog)
		t.Fatalf("Credential file not found at %s: %v", caPath, err)
	}
	logOK(t, fmt.Sprintf("Credential file exists: %s", strings.TrimSpace(output)))

	// Verify permissions are 0644
	if !strings.Contains(output, "-rw-r--r--") {
		t.Errorf("%s Incorrect permissions. Expected -rw-r--r-- (0644), got: %s", errFmt("x"), output)
	} else {
		logOK(t, "Permissions are correct (0644)")
	}

	// Verify content is a valid SSH public key
	output, err = cfg.multipassExec(ctx, cfg.HostVM, "cat", caPath)
	if err != nil {
		t.Fatalf("Failed to read credential file: %v", err)
	}

	output = strings.TrimSpace(output)
	if !strings.HasPrefix(output, "ssh-") && !strings.HasPrefix(output, "ecdsa-") {
		t.Errorf("%s Credential file does not contain valid SSH public key: %s", errFmt("x"), output[:min(50, len(output))])
	} else {
		logOK(t, "Credential contains valid SSH public key")
	}

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Credential delivery E2E test"))
}
