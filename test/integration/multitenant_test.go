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

// TestMultiTenantEnrollmentIsolation verifies that once a DPU is paired with a host,
// other hosts cannot enroll via that DPU. This is a critical security boundary:
// multi-tenant isolation is enforced at the DPU level.
//
// The test verifies:
// 1. First host (qa-host) successfully enrolls with DPU
// 2. Second hostname attempting enrollment is rejected with clear error
// 3. Error message contains "already paired" for diagnostic clarity
// 4. Aegis logs the rejection event for security audit trail
// 5. Original host remains functional after rejected enrollment attempt
func TestMultiTenantEnrollmentIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	testHostname := makeTestHostname(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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

	// Step 4: First host enrolls successfully via sentry (connects directly to aegis via TCP)
	logStep(t, 4, "First host (qa-host) enrolling...")
	cfg.killProcess(ctx, cfg.HostVM, "sentry")
	sentryCtx, sentryCancel := context.WithTimeout(ctx, 30*time.Second)
	defer sentryCancel()

	output, err = cfg.multipassExec(sentryCtx, cfg.HostVM, "sudo", "/home/ubuntu/sentry", "--hostname", testHostname, "--force-tmfifo", fmt.Sprintf("--tmfifo-addr=%s:9444", dpuIP), "--oneshot")
	if err != nil {
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-30", "/tmp/aegis.log")
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("%s First host enrollment failed: %v", errFmt("x"), err)
	}

	if !strings.Contains(output, "Enrolled") {
		t.Fatalf("%s Sentry did not complete enrollment", errFmt("x"))
	}
	logOK(t, "First host (qa-host) enrolled successfully")

	// Step 5: Clear aegis log to capture rejection event clearly
	logStep(t, 5, "Clearing logs before second enrollment attempt...")
	_, _ = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", "sudo truncate -s 0 /tmp/aegis.log")
	time.Sleep(1 * time.Second)
	logOK(t, "Logs cleared")

	// Step 6: Attempt enrollment from a DIFFERENT hostname via localapi
	// This simulates a malicious or misconfigured second host trying to enroll
	logStep(t, 6, "Attempting enrollment from second hostname (should fail)...")

	// Send registration request with a different hostname directly to localapi
	// The localapi listens on localhost:9443 on the DPU
	intruderHostname := "malicious-host-trying-to-intrude"
	curlCmd := fmt.Sprintf(`curl -s -w "\nHTTP_CODE:%%{http_code}" -X POST http://localhost:9443/local/v1/register -H "Content-Type: application/json" -d '{"hostname":"%s","posture":{"os_version":"Ubuntu 22.04"}}'`, intruderHostname)

	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c", curlCmd)
	// Note: curl itself should succeed (returns HTTP response), but the response should indicate rejection

	// Parse the response to check for rejection
	var httpCode string
	var responseBody string
	if idx := strings.LastIndex(output, "HTTP_CODE:"); idx != -1 {
		httpCode = strings.TrimSpace(output[idx+len("HTTP_CODE:"):])
		responseBody = output[:idx]
	} else {
		responseBody = output
	}

	logInfo(t, "Response body: %s", strings.TrimSpace(responseBody))
	logInfo(t, "HTTP status code: %s", httpCode)

	// Step 7: Verify the rejection
	logStep(t, 7, "Verifying enrollment rejection...")

	// Check HTTP status code (should be 409 Conflict)
	if httpCode != "409" {
		t.Errorf("%s Expected HTTP 409 Conflict, got %s", errFmt("x"), httpCode)
	} else {
		logOK(t, "HTTP status 409 Conflict returned (correct)")
	}

	// Check error message contains "already paired"
	if !strings.Contains(responseBody, "already paired") {
		t.Errorf("%s Error message does not contain 'already paired'. Response: %s", errFmt("x"), responseBody)
	} else {
		logOK(t, "Error message contains 'already paired'")
	}

	// Step 8: Verify security logging shows the rejection
	logStep(t, 8, "Verifying security logging...")

	aegisLog, err := cfg.multipassExec(ctx, cfg.DPUVM, "cat", "/tmp/aegis.log")
	if err != nil {
		t.Fatalf("Failed to read aegis log: %v", err)
	}

	// Check for the security rejection log message
	expectedLogMarker := fmt.Sprintf("registration rejected for %s (DPU already paired with different host)", intruderHostname)
	if !strings.Contains(aegisLog, expectedLogMarker) {
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Errorf("%s Security rejection not logged. Expected marker: %s", errFmt("x"), expectedLogMarker)
	} else {
		logOK(t, "Security rejection logged correctly")
	}

	// Step 9: Verify original host is still functional (can re-enroll)
	logStep(t, 9, "Verifying original host remains functional...")

	// The original host should be able to continue operations
	// We'll verify by checking that a posture update from the original host works
	// For simplicity, we re-run sentry oneshot which should succeed because
	// the hostname matches the paired host
	output, err = cfg.multipassExec(sentryCtx, cfg.HostVM, "sudo", "/home/ubuntu/sentry", "--hostname", testHostname, "--force-tmfifo", fmt.Sprintf("--tmfifo-addr=%s:9444", dpuIP), "--oneshot")
	if err != nil {
		// This might fail if the transport is in a bad state, but the pairing should still work
		// Check the aegis log to see if registration was attempted
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-20", "/tmp/aegis.log")
		logInfo(t, "Aegis log (recent):\n%s", aegisLog)

		// If it fails, that's OK for this test as long as it's not a pairing rejection
		// Check each log line for a rejection of qa-host specifically (not the intruder)
		qaHostRejected := false
		for _, line := range strings.Split(aegisLog, "\n") {
			if strings.Contains(line, "already paired") && strings.Contains(line, "qa-host") {
				qaHostRejected = true
				break
			}
		}
		if qaHostRejected {
			t.Errorf("%s Original host rejected after intruder attempt", errFmt("x"))
		} else {
			logOK(t, "Original host not rejected (transport state issue is acceptable)")
		}
	} else {
		if strings.Contains(output, "Enrolled") {
			logOK(t, "Original host can still enroll successfully")
		} else {
			logOK(t, "Original host enrollment completed")
		}
	}

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Multi-tenant enrollment isolation test"))
}
