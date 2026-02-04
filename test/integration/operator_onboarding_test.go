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

// TestOperatorOnboardingE2E validates the complete operator onboarding flow:
// 1. Admin creates tenant and invite code via bluectl
// 2. Operator initializes KeyMaker with km init
// 3. Operator creates SSH CA with km ssh-ca create
// 4. Admin grants operator permission via bluectl operator grant
// 5. Operator pushes credentials via km push
// 6. Credential file appears on target host
//
// This is a regression test for v0.6.9 where bluectl operator grant silently failed.
func TestOperatorOnboardingE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	testHostname := makeTestHostname(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Test-unique identifiers
	testID := fmt.Sprintf("%d", time.Now().Unix())
	tenantName := fmt.Sprintf("onboard-tenant-%s", testID)
	dpuName := "qa-dpu"
	operatorEmail := fmt.Sprintf("onboard-op-%s@test.local", testID)
	caName := fmt.Sprintf("onboard-ca-%s", testID)
	caPath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caName)

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", dimFmt("Cleaning up processes and test artifacts..."))
		cfg.killProcess(cleanupCtx, cfg.ServerVM, "nexus")
		cfg.killProcess(cleanupCtx, cfg.DPUVM, "aegis")
		cfg.killProcess(cleanupCtx, cfg.HostVM, "sentry")

		// Clean up km config on qa-server
		cfg.multipassExec(cleanupCtx, cfg.ServerVM, "rm", "-rf", "/home/ubuntu/.km")

		// Clean up test CA file on qa-host
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

	// =========================================================================
	// SCENARIO 1: Happy path - full onboarding to credential delivery
	// =========================================================================
	t.Run("HappyPath", func(t *testing.T) {
		// Step 1: Start nexus
		logStep(t, 1, "Starting nexus...")
		cfg.killProcess(ctx, cfg.ServerVM, "nexus")

		// Remove existing database to ensure fresh start
		cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-f", "/home/ubuntu/.local/share/bluectl/dpus.db")
		cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-f", "/home/ubuntu/.local/share/bluectl/dpus.db-wal")
		cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-f", "/home/ubuntu/.local/share/bluectl/dpus.db-shm")

		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c",
			"setsid /home/ubuntu/nexus > /tmp/nexus.log 2>&1 < /dev/null &")
		if err != nil {
			t.Fatalf("Failed to start nexus: %v", err)
		}
		time.Sleep(2 * time.Second)

		output, err := cfg.multipassExec(ctx, cfg.ServerVM, "pgrep", "-x", "nexus")
		if err != nil || strings.TrimSpace(output) == "" {
			logs, _ := cfg.multipassExec(ctx, cfg.ServerVM, "cat", "/tmp/nexus.log")
			t.Fatalf("Nexus not running after start. Logs:\n%s", logs)
		}
		logOK(t, "Nexus started")

		// Initialize bluectl (required for DPoP auth in Phase 3)
		if err := initBluectl(cfg, ctx, t); err != nil {
			t.Fatalf("Failed to initialize bluectl: %v", err)
		}

		// Step 2: Start aegis on qa-dpu
		logStep(t, 2, "Starting aegis on qa-dpu...")
		cfg.killProcess(ctx, cfg.DPUVM, "aegis")
		cfg.multipassExec(ctx, cfg.DPUVM, "sudo", "rm", "-f", "/var/lib/aegis/aegis.db")

		_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
			fmt.Sprintf("sudo setsid /home/ubuntu/aegis -allow-tmfifo-net -server http://%s:18080 -dpu-name %s > /tmp/aegis.log 2>&1 < /dev/null &", serverIP, dpuName))
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
		logOK(t, "Aegis started with TMFIFO listener")

		// Step 3: Create tenant
		// NOTE: Must create tenant and register DPU BEFORE starting sentry,
		// otherwise sentry enrollment fails (aegis rejects unregistered DPUs)
		logStep(t, 3, "Creating tenant...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"tenant", "add", tenantName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("Failed to create tenant: %v", err)
		}
		logOK(t, fmt.Sprintf("Created tenant '%s'", tenantName))

		// Step 4: Register DPU and assign to tenant
		logStep(t, 4, "Registering DPU...")
		// Remove stale DPU registration if exists
		cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "dpu", "remove", dpuName, "--server", "http://localhost:18080")

		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"dpu", "add", fmt.Sprintf("%s:18051", dpuIP), "--name", dpuName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("Failed to register DPU: %v", err)
		}

		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"tenant", "assign", tenantName, dpuName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("Failed to assign DPU to tenant: %v", err)
		}
		logOK(t, fmt.Sprintf("DPU '%s' registered and assigned to tenant", dpuName))

		// Step 5: Start sentry daemon on qa-host (now that DPU is registered)
		logStep(t, 5, "Starting sentry daemon on qa-host...")
		cfg.killProcess(ctx, cfg.HostVM, "sentry")
		_, err = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c",
			fmt.Sprintf("sudo setsid /home/ubuntu/sentry --hostname %s --force-tmfifo --tmfifo-addr=%s:9444 > /tmp/sentry.log 2>&1 < /dev/null &", testHostname, dpuIP))
		if err != nil {
			t.Fatalf("Failed to start sentry daemon: %v", err)
		}
		time.Sleep(5 * time.Second)

		// Verify sentry enrolled
		sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
		if !strings.Contains(sentryLog, "Enrolled") && !strings.Contains(sentryLog, "enrolled") {
			aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-30", "/tmp/aegis.log")
			fmt.Printf("    Sentry log:\n%s\n", sentryLog)
			fmt.Printf("    Aegis log:\n%s\n", aegisLog)
			t.Fatalf("%s Sentry did not complete enrollment", errFmt("x"))
		}
		logOK(t, "Sentry daemon started and enrolled")

		// Step 6: Create invite code
		logStep(t, 6, "Creating invite code...")
		inviteOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "invite", operatorEmail, tenantName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("Failed to create invite: %v", err)
		}

		inviteCode := extractInviteCode(inviteOutput)
		if inviteCode == "" {
			t.Fatalf("Could not extract invite code from output:\n%s", inviteOutput)
		}
		logOK(t, fmt.Sprintf("Created invite code: %s", inviteCode))

		// Step 7: Initialize km with invite code
		logStep(t, 7, "Initializing KeyMaker (km init)...")
		// Clear existing km config
		cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-rf", "/home/ubuntu/.km")

		kmInitOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"init", "--invite-code", inviteCode, "--control-plane", "http://localhost:18080", "--force")
		if err != nil {
			t.Fatalf("km init failed: %v\nOutput: %s", err, kmInitOutput)
		}
		if !strings.Contains(kmInitOutput, "Bound successfully") {
			t.Fatalf("km init did not complete successfully. Output:\n%s", kmInitOutput)
		}
		logOK(t, "KeyMaker initialized and bound to server")

		// Step 8: Create SSH CA
		logStep(t, 8, "Creating SSH CA (km ssh-ca create)...")
		caCreateOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", caName)
		if err != nil {
			t.Fatalf("km ssh-ca create failed: %v\nOutput: %s", err, caCreateOutput)
		}
		logOK(t, fmt.Sprintf("Created SSH CA '%s'", caName))

		// Step 9: Grant operator access
		logStep(t, 9, "Granting operator access (bluectl operator grant)...")
		grantOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "grant", operatorEmail, tenantName, caName, dpuName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator grant failed: %v\nOutput: %s", err, grantOutput)
		}
		logOK(t, fmt.Sprintf("Granted access: %s -> %s -> %s", operatorEmail, caName, dpuName))

		// Step 10: Push credential
		logStep(t, 10, "Pushing SSH CA credential (km push)...")
		pushOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"push", "ssh-ca", caName, dpuName, "--force")
		if err != nil {
			nexusLog, _ := cfg.multipassExec(ctx, cfg.ServerVM, "tail", "-50", "/tmp/nexus.log")
			aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-50", "/tmp/aegis.log")
			fmt.Printf("    Nexus log:\n%s\n", nexusLog)
			fmt.Printf("    Aegis log:\n%s\n", aegisLog)
			t.Fatalf("km push failed: %v\nOutput: %s", err, pushOutput)
		}
		if !strings.Contains(pushOutput, "CA installed") {
			t.Fatalf("km push did not indicate success. Output:\n%s", pushOutput)
		}
		logOK(t, "Credential pushed successfully")

		// Step 11: Wait for credential file to appear with content (async delivery)
		// The API returns success when the message is sent, but sentry still needs to
		// receive and write the file. Poll with timeout instead of fixed sleep.
		logStep(t, 11, "Waiting for credential installation on qa-host...")
		var content string
		credentialTimeout := 15 * time.Second
		pollInterval := 500 * time.Millisecond
		deadline := time.Now().Add(credentialTimeout)

		for time.Now().Before(deadline) {
			output, err := cfg.multipassExec(ctx, cfg.HostVM, "cat", caPath)
			if err == nil {
				content = strings.TrimSpace(output)
				if strings.HasPrefix(content, "ssh-") || strings.HasPrefix(content, "ecdsa-") {
					break // File exists with valid SSH key content
				}
			}
			time.Sleep(pollInterval)
		}

		if content == "" {
			sentryLog, _ := cfg.multipassExec(ctx, cfg.HostVM, "cat", "/tmp/sentry.log")
			aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-30", "/tmp/aegis.log")
			fmt.Printf("    Sentry log:\n%s\n", sentryLog)
			fmt.Printf("    Aegis log:\n%s\n", aegisLog)
			t.Fatalf("Credential file not found or empty at %s after %v", caPath, credentialTimeout)
		}
		if !strings.HasPrefix(content, "ssh-") && !strings.HasPrefix(content, "ecdsa-") {
			t.Fatalf("Credential file does not contain valid SSH public key. Content: %s", content[:min(50, len(content))])
		}
		logOK(t, fmt.Sprintf("Credential installed at %s", caPath))

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 1 - Happy path complete"))
	})

	// =========================================================================
	// SCENARIO 2: Authorization failure without grant
	// =========================================================================
	t.Run("NoGrantFails", func(t *testing.T) {
		// Use different identifiers to avoid conflict with happy path
		noGrantEmail := fmt.Sprintf("nogrant-op-%s@test.local", testID)
		noGrantCA := fmt.Sprintf("nogrant-ca-%s", testID)
		noGrantCAPath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", noGrantCA)

		// Create invite for new operator
		logStep(t, 1, "Creating new operator without grant...")
		inviteOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "invite", noGrantEmail, tenantName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("Failed to create invite: %v", err)
		}
		inviteCode := extractInviteCode(inviteOutput)
		if inviteCode == "" {
			t.Fatalf("Could not extract invite code from output:\n%s", inviteOutput)
		}
		logOK(t, fmt.Sprintf("Created invite for %s", noGrantEmail))

		// Initialize km with the new invite (different config dir needed)
		logStep(t, 2, "Initializing KeyMaker for no-grant operator...")
		cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-rf", "/home/ubuntu/.km")
		kmInitOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"init", "--invite-code", inviteCode, "--control-plane", "http://localhost:18080", "--force")
		if err != nil {
			t.Fatalf("km init failed: %v\nOutput: %s", err, kmInitOutput)
		}
		logOK(t, "KeyMaker initialized (no grant yet)")

		// Create SSH CA
		logStep(t, 3, "Creating SSH CA...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", noGrantCA)
		if err != nil {
			t.Fatalf("km ssh-ca create failed: %v", err)
		}
		logOK(t, fmt.Sprintf("Created SSH CA '%s'", noGrantCA))

		// Skip the grant step intentionally

		// Attempt to push credential (should fail)
		logStep(t, 4, "Attempting push WITHOUT grant (should fail)...")
		pushOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"push", "ssh-ca", noGrantCA, dpuName)

		// Verify push failed
		if err == nil && strings.Contains(pushOutput, "CA installed") {
			t.Fatalf("km push should have failed without grant, but succeeded. Output:\n%s", pushOutput)
		}

		// Check for authorization error
		if !strings.Contains(pushOutput, "not authorized") && !strings.Contains(pushOutput, "403") && !strings.Contains(pushOutput, "Forbidden") && !strings.Contains(pushOutput, "permission") {
			t.Fatalf("Expected authorization error, got: %s", pushOutput)
		}
		logOK(t, fmt.Sprintf("Push correctly rejected: %s", truncateForLog(pushOutput, 80)))

		// Verify credential file does NOT exist
		logStep(t, 5, "Verifying credential was NOT installed...")
		_, err = cfg.multipassExec(ctx, cfg.HostVM, "ls", "-la", noGrantCAPath)
		if err == nil {
			t.Fatalf("Credential file should NOT exist at %s (no grant was given)", noGrantCAPath)
		}
		logOK(t, "Credential file correctly not present")

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 2 - Authorization failure without grant"))
	})

	// =========================================================================
	// SCENARIO 3: Invalid invite code
	// =========================================================================
	t.Run("InvalidInviteCode", func(t *testing.T) {
		logStep(t, 1, "Attempting km init with invalid invite code...")
		cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-rf", "/home/ubuntu/.km")

		invalidCode := "XXXX-GARBAGE-XXXX"
		kmInitOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"init", "--invite-code", invalidCode, "--control-plane", "http://localhost:18080", "--force")

		// Verify init failed
		if err == nil && strings.Contains(kmInitOutput, "Bound successfully") {
			t.Fatalf("km init should have failed with invalid code, but succeeded. Output:\n%s", kmInitOutput)
		}

		// Check for invalid/expired error message
		if !strings.Contains(kmInitOutput, "invalid") && !strings.Contains(kmInitOutput, "expired") && !strings.Contains(kmInitOutput, "401") && !strings.Contains(kmInitOutput, "403") {
			t.Fatalf("Expected invalid/expired invite code error, got: %s", kmInitOutput)
		}
		logOK(t, fmt.Sprintf("km init correctly rejected: %s", truncateForLog(kmInitOutput, 80)))

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 3 - Invalid invite code rejected"))
	})

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: TestOperatorOnboardingE2E - All scenarios"))
}
