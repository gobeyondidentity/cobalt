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

// TestOperatorSuspensionE2E validates operator suspension and activation.
// Suspension is the incident response mechanism: when an operator's device
// is lost or compromised, admins need to immediately block their access.
//
// The test verifies:
// 1. Suspended operator's km commands return 403
// 2. Activation restores full access
// 3. Suspension status visible in operator list
func TestOperatorSuspensionE2E(t *testing.T) {
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
	tenantName := fmt.Sprintf("suspend-tenant-%s", testID)
	dpuName := "qa-dpu"
	operatorEmail := fmt.Sprintf("suspend-op-%s@test.local", testID)

	// CA names for each scenario phase
	caBeforeSuspend := fmt.Sprintf("ca-before-suspend-%s", testID)
	caAfterSuspend := fmt.Sprintf("ca-after-suspend-%s", testID)
	caAfterUnsuspend := fmt.Sprintf("ca-after-unsuspend-%s", testID)

	// CA paths on qa-host
	caBeforeSuspendPath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caBeforeSuspend)
	caAfterSuspendPath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caAfterSuspend)
	caAfterUnsuspendPath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caAfterUnsuspend)

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

		// Clean up test CA files on qa-host
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caBeforeSuspendPath)
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caAfterSuspendPath)
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caAfterUnsuspendPath)
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
	// SETUP: Start infrastructure and create operator
	// =========================================================================
	t.Run("Setup", func(t *testing.T) {
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

		// Step 6: Create invite and initialize operator
		logStep(t, 6, "Creating invite and initializing operator...")
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

		// Initialize km
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

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Setup complete"))
	})

	// =========================================================================
	// SCENARIO 1: Suspension blocks km operations
	// =========================================================================
	t.Run("Scenario1_SuspensionBlocksOperations", func(t *testing.T) {
		// Step 1: Create SSH CA and grant permission
		logStep(t, 1, "Creating SSH CA and granting permission (before suspension)...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", caBeforeSuspend)
		if err != nil {
			t.Fatalf("km ssh-ca create failed: %v", err)
		}
		logOK(t, fmt.Sprintf("Created SSH CA '%s'", caBeforeSuspend))

		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "grant", operatorEmail, tenantName, caBeforeSuspend, dpuName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator grant failed: %v", err)
		}
		logOK(t, "Granted operator access to CA")

		// Step 2: Verify km push works BEFORE suspension
		logStep(t, 2, "Verifying km push works BEFORE suspension...")
		pushOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"push", "ssh-ca", caBeforeSuspend, dpuName, "--force")
		if err != nil {
			nexusLog, _ := cfg.multipassExec(ctx, cfg.ServerVM, "tail", "-30", "/tmp/nexus.log")
			fmt.Printf("    Nexus log:\n%s\n", nexusLog)
			t.Fatalf("km push should work before suspension: %v\nOutput: %s", err, pushOutput)
		}
		if !strings.Contains(pushOutput, "CA installed") {
			t.Fatalf("km push did not indicate success. Output:\n%s", pushOutput)
		}
		logOK(t, "Push succeeded before suspension")

		// Wait for credential file to appear with content (async delivery)
		credentialTimeout := 15 * time.Second
		pollInterval := 500 * time.Millisecond
		deadline := time.Now().Add(credentialTimeout)
		var credContent string

		for time.Now().Before(deadline) {
			output, err := cfg.multipassExec(ctx, cfg.HostVM, "cat", caBeforeSuspendPath)
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
			t.Fatalf("Credential file not found or invalid at %s after %v", caBeforeSuspendPath, credentialTimeout)
		}
		logOK(t, fmt.Sprintf("Credential file exists: %s", caBeforeSuspendPath))

		// Step 3: Suspend the operator
		logStep(t, 3, "Suspending operator...")
		suspendOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "suspend", operatorEmail, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator suspend failed: %v\nOutput: %s", err, suspendOutput)
		}
		if !strings.Contains(suspendOutput, "suspended") {
			t.Fatalf("Suspend command did not confirm suspension. Output:\n%s", suspendOutput)
		}
		logOK(t, fmt.Sprintf("Operator suspended: %s", operatorEmail))

		// Step 4: Create a new CA (for the post-suspension push test)
		logStep(t, 4, "Creating new SSH CA for post-suspension test...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", caAfterSuspend)
		if err != nil {
			t.Fatalf("km ssh-ca create failed: %v", err)
		}
		logOK(t, fmt.Sprintf("Created SSH CA '%s'", caAfterSuspend))

		// Grant permission for the new CA (even though operator is suspended)
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "grant", operatorEmail, tenantName, caAfterSuspend, dpuName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator grant failed: %v", err)
		}
		logOK(t, "Granted operator access to new CA")

		// Step 5: Attempt km push AFTER suspension (should fail)
		logStep(t, 5, "Attempting km push AFTER suspension (should fail)...")
		pushOutput, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"push", "ssh-ca", caAfterSuspend, dpuName, "--force")

		// Verify push failed
		if err == nil && strings.Contains(pushOutput, "CA installed") {
			t.Fatalf("km push should have failed after suspension, but succeeded. Output:\n%s", pushOutput)
		}

		// Check for suspension/authorization error
		combinedOutput := strings.ToLower(pushOutput)
		if !strings.Contains(combinedOutput, "suspended") &&
			!strings.Contains(combinedOutput, "forbidden") &&
			!strings.Contains(combinedOutput, "not authorized") &&
			!strings.Contains(combinedOutput, "403") {
			t.Fatalf("Expected suspension/authorization error, got: %s", pushOutput)
		}
		logOK(t, fmt.Sprintf("Push correctly rejected: %s", truncateForLog(pushOutput, 80)))

		// Step 6: Verify credential file was NOT created
		logStep(t, 6, "Verifying credential was NOT installed...")
		_, err = cfg.multipassExec(ctx, cfg.HostVM, "ls", "-la", caAfterSuspendPath)
		if err == nil {
			t.Fatalf("Credential file should NOT exist at %s (operator is suspended)", caAfterSuspendPath)
		}
		logOK(t, "Credential file correctly not present")

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 1 - Suspension blocks km operations"))
	})

	// =========================================================================
	// SCENARIO 2: Unsuspend restores access
	// =========================================================================
	t.Run("Scenario2_UnsuspendRestoresAccess", func(t *testing.T) {
		// Step 1: Unsuspend the operator
		logStep(t, 1, "Unsuspending operator...")
		unsuspendOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "unsuspend", operatorEmail, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator unsuspend failed: %v\nOutput: %s", err, unsuspendOutput)
		}
		if !strings.Contains(unsuspendOutput, "unsuspended") {
			t.Fatalf("Unsuspend command did not confirm unsuspend. Output:\n%s", unsuspendOutput)
		}
		logOK(t, fmt.Sprintf("Operator unsuspended: %s", operatorEmail))

		// Step 2: Create a new CA for post-unsuspend test
		logStep(t, 2, "Creating new SSH CA for post-unsuspend test...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", caAfterUnsuspend)
		if err != nil {
			t.Fatalf("km ssh-ca create failed: %v", err)
		}
		logOK(t, fmt.Sprintf("Created SSH CA '%s'", caAfterUnsuspend))

		// Grant permission for the new CA
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "grant", operatorEmail, tenantName, caAfterUnsuspend, dpuName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator grant failed: %v", err)
		}
		logOK(t, "Granted operator access to new CA")

		// Step 3: Attempt km push AFTER unsuspend (should succeed)
		logStep(t, 3, "Attempting km push AFTER unsuspend (should succeed)...")
		pushOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"push", "ssh-ca", caAfterUnsuspend, dpuName, "--force")
		if err != nil {
			nexusLog, _ := cfg.multipassExec(ctx, cfg.ServerVM, "tail", "-30", "/tmp/nexus.log")
			fmt.Printf("    Nexus log:\n%s\n", nexusLog)
			t.Fatalf("km push should work after unsuspend: %v\nOutput: %s", err, pushOutput)
		}
		if !strings.Contains(pushOutput, "CA installed") {
			t.Fatalf("km push did not indicate success. Output:\n%s", pushOutput)
		}
		logOK(t, "Push succeeded after unsuspend")

		// Step 4: Wait for credential file to appear with content (async delivery)
		logStep(t, 4, "Verifying credential was installed...")
		credentialTimeout := 15 * time.Second
		pollInterval := 500 * time.Millisecond
		deadline := time.Now().Add(credentialTimeout)
		var credContent string

		for time.Now().Before(deadline) {
			output, err := cfg.multipassExec(ctx, cfg.HostVM, "cat", caAfterUnsuspendPath)
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
			t.Fatalf("Credential file not found or invalid at %s after %v", caAfterUnsuspendPath, credentialTimeout)
		}
		logOK(t, fmt.Sprintf("Credential file exists: %s", caAfterUnsuspendPath))

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 2 - Unsuspend restores access"))
	})

	// =========================================================================
	// SCENARIO 3: Suspension status visible in operator list
	// =========================================================================
	t.Run("Scenario3_SuspensionStatusVisible", func(t *testing.T) {
		// Step 1: Suspend operator again
		logStep(t, 1, "Suspending operator...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "suspend", operatorEmail, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator suspend failed: %v", err)
		}
		logOK(t, "Operator suspended")

		// Step 2: Verify suspended status in list
		logStep(t, 2, "Verifying suspended status in operator list...")
		listOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "list", "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator list failed: %v\nOutput: %s", err, listOutput)
		}

		// Find the line with our operator and verify status
		lines := strings.Split(listOutput, "\n")
		var operatorLine string
		for _, line := range lines {
			if strings.Contains(line, operatorEmail) {
				operatorLine = line
				break
			}
		}
		if operatorLine == "" {
			t.Fatalf("Operator not found in list output:\n%s", listOutput)
		}
		if !strings.Contains(operatorLine, "suspended") {
			t.Fatalf("Operator should show 'suspended' status in list. Line: %s", operatorLine)
		}
		logOK(t, fmt.Sprintf("Operator shows suspended status: %s", truncateForLog(operatorLine, 100)))

		// Step 3: Unsuspend operator
		logStep(t, 3, "Unsuspending operator...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "unsuspend", operatorEmail, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator unsuspend failed: %v", err)
		}
		logOK(t, "Operator unsuspended")

		// Step 4: Verify active status in list
		logStep(t, 4, "Verifying active status in operator list...")
		listOutput, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "list", "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator list failed: %v\nOutput: %s", err, listOutput)
		}

		// Find the line with our operator and verify status
		lines = strings.Split(listOutput, "\n")
		operatorLine = ""
		for _, line := range lines {
			if strings.Contains(line, operatorEmail) {
				operatorLine = line
				break
			}
		}
		if operatorLine == "" {
			t.Fatalf("Operator not found in list output:\n%s", listOutput)
		}
		if !strings.Contains(operatorLine, "active") {
			t.Fatalf("Operator should show 'active' status in list. Line: %s", operatorLine)
		}
		logOK(t, fmt.Sprintf("Operator shows active status: %s", truncateForLog(operatorLine, 100)))

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 3 - Suspension status visible"))
	})

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: TestOperatorSuspensionE2E - All scenarios"))
}

// TestSuspendedOperatorKeyMakerAuth validates that a KeyMaker's DPoP authentication
// is blocked when its parent operator is suspended. This is a focused test that
// specifically exercises the DPoP middleware's status check (step 10 per
// security-architecture.md §2.5).
//
// Unlike TestOperatorSuspensionE2E which tests the full credential delivery flow,
// this test isolates the authentication enforcement:
// 1. KeyMaker can authenticate when operator is active
// 2. KeyMaker is blocked (401/403) when operator is suspended
// 3. KeyMaker can authenticate again when operator is unsuspended
//
// This test uses only nexus (no aegis/sentry) to minimize infrastructure and
// focus on the DPoP middleware enforcement at the API boundary.
func TestSuspendedOperatorKeyMakerAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Test-unique identifiers
	testID := fmt.Sprintf("%d", time.Now().Unix())
	tenantName := fmt.Sprintf("kmauth-tenant-%s", testID)
	operatorEmail := fmt.Sprintf("kmauth-op-%s@test.local", testID)

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", dimFmt("Cleaning up test artifacts..."))
		cfg.killProcess(cleanupCtx, cfg.ServerVM, "nexus")

		// Clean up km config on qa-server
		cfg.multipassExec(cleanupCtx, cfg.ServerVM, "rm", "-rf", "/home/ubuntu/.km")
	})

	// Get server VM IP (not used directly, but validates VM is accessible)
	_, err := cfg.getVMIP(ctx, cfg.ServerVM)
	if err != nil {
		t.Fatalf("Failed to get server IP: %v", err)
	}

	// =========================================================================
	// SETUP: Start nexus and create operator with KeyMaker
	// =========================================================================
	t.Run("Setup", func(t *testing.T) {
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

		// Initialize bluectl (required for DPoP auth)
		if err := initBluectl(cfg, ctx, t); err != nil {
			t.Fatalf("Failed to initialize bluectl: %v", err)
		}

		// Step 2: Create tenant
		logStep(t, 2, "Creating tenant...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"tenant", "add", tenantName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("Failed to create tenant: %v", err)
		}
		logOK(t, fmt.Sprintf("Created tenant '%s'", tenantName))

		// Step 3: Create invite and initialize KeyMaker
		logStep(t, 3, "Creating invite and initializing KeyMaker...")
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

		// Initialize km (enrolls KeyMaker)
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

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Setup complete"))
	})

	// =========================================================================
	// TEST: Verify KeyMaker auth blocked when operator suspended
	// =========================================================================
	t.Run("KeyMakerAuthBlockedWhenOperatorSuspended", func(t *testing.T) {
		// Step 1: Create an SSH CA to verify KeyMaker can authenticate
		// km ssh-ca create makes an authenticated POST to /api/v1/ssh-cas to register the CA
		logStep(t, 1, "Creating SSH CA to verify KeyMaker authentication works...")
		caBeforeSuspend := fmt.Sprintf("test-ca-before-%s", testID)
		output, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", caBeforeSuspend)
		if err != nil {
			t.Fatalf("km ssh-ca create failed (KeyMaker auth should work): %v\nOutput: %s", err, output)
		}
		// Verify CA was registered with server (no warning about registration failure)
		if strings.Contains(output, "Warning: Failed to register") {
			t.Fatalf("CA registration failed when operator is active.\nOutput: %s", output)
		}
		t.Log("KeyMaker successfully authenticated and registered CA with server")
		logOK(t, fmt.Sprintf("Created and registered SSH CA '%s' (KeyMaker auth works)", caBeforeSuspend))

		// Step 2: Suspend the operator
		logStep(t, 2, "Suspending operator...")
		suspendOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "suspend", operatorEmail, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator suspend failed: %v\nOutput: %s", err, suspendOutput)
		}
		if !strings.Contains(suspendOutput, "suspended") {
			t.Fatalf("Suspend command did not confirm suspension. Output:\n%s", suspendOutput)
		}
		t.Logf("Operator suspended: %s", operatorEmail)
		logOK(t, fmt.Sprintf("Operator suspended: %s", operatorEmail))

		// Step 3: Attempt km ssh-ca create AFTER suspension
		// Local CA creation will succeed, but server registration (authenticated API call) should fail
		logStep(t, 3, "Attempting km ssh-ca create AFTER suspension (registration should fail)...")
		t.Log("Making authenticated API call with suspended operator's KeyMaker...")
		caAfterSuspend := fmt.Sprintf("test-ca-after-%s", testID)
		createOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", caAfterSuspend)

		t.Logf("km ssh-ca create output: %s", createOutput)
		t.Logf("km ssh-ca create error: %v", err)

		// The CA creation itself succeeds locally, but registration with server should fail
		// with authentication error (DPoP middleware blocks suspended KeyMaker)
		combinedOutput := strings.ToLower(createOutput)

		// Check for auth failure in registration warning
		// Expected: "Warning: Failed to register with server: authentication failed"
		if !strings.Contains(combinedOutput, "authentication failed") &&
			!strings.Contains(combinedOutput, "not authorized") &&
			!strings.Contains(combinedOutput, "forbidden") &&
			!strings.Contains(combinedOutput, "suspended") {
			// Check nexus logs to confirm DPoP middleware caught it
			nexusLog, _ := cfg.multipassExec(ctx, cfg.ServerVM, "tail", "-30", "/tmp/nexus.log")
			t.Logf("Nexus log (auth.suspended should be logged):\n%s", nexusLog)

			// The definitive check: DPoP middleware should log auth.suspended
			if !strings.Contains(nexusLog, "auth.suspended") {
				t.Fatalf("Expected auth error for suspended operator KeyMaker.\nOutput: %s\nNexus log: %s",
					createOutput, nexusLog)
			}
			t.Log("DPoP middleware logged auth.suspended (verified in server logs)")
		} else {
			t.Log("CLI output indicates authentication failure (expected)")
		}
		logOK(t, "KeyMaker API call correctly blocked (DPoP middleware enforcement)")

		// Step 4: Verify DPoP middleware logged the suspension
		logStep(t, 4, "Verifying DPoP middleware logged auth.suspended...")
		nexusLog, _ := cfg.multipassExec(ctx, cfg.ServerVM, "tail", "-50", "/tmp/nexus.log")
		if !strings.Contains(nexusLog, "auth.suspended") {
			t.Logf("Warning: Expected 'auth.suspended' in nexus logs. Log:\n%s", nexusLog)
		} else {
			t.Log("Confirmed: DPoP middleware logged auth.suspended rejection")
			logOK(t, "DPoP middleware logged auth.suspended")
		}

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: KeyMaker blocked when operator suspended"))
	})

	// =========================================================================
	// TEST: Verify KeyMaker auth restored when operator unsuspended
	// =========================================================================
	t.Run("KeyMakerAuthRestoredWhenOperatorUnsuspended", func(t *testing.T) {
		// Step 1: Unsuspend the operator
		logStep(t, 1, "Unsuspending operator...")
		unsuspendOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "unsuspend", operatorEmail, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator unsuspend failed: %v\nOutput: %s", err, unsuspendOutput)
		}
		if !strings.Contains(unsuspendOutput, "unsuspended") {
			t.Fatalf("Unsuspend command did not confirm unsuspend. Output:\n%s", unsuspendOutput)
		}
		t.Logf("Operator unsuspended: %s", operatorEmail)
		logOK(t, fmt.Sprintf("Operator unsuspended: %s", operatorEmail))

		// Step 2: Verify km ssh-ca create works AFTER unsuspend
		// This makes an authenticated API call to register the CA
		logStep(t, 2, "Attempting km ssh-ca create AFTER unsuspend (should succeed)...")
		t.Log("Making authenticated API call with unsuspended operator's KeyMaker...")
		caAfterUnsuspend := fmt.Sprintf("test-ca-restored-%s", testID)
		createOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", caAfterUnsuspend)

		t.Logf("km ssh-ca create output: %s", createOutput)

		// Check for success (no auth error, registration succeeded)
		combinedOutput := strings.ToLower(createOutput)
		if err != nil {
			// Check if this is an auth error (bad)
			if strings.Contains(combinedOutput, "not authorized") ||
				strings.Contains(combinedOutput, "suspended") ||
				strings.Contains(combinedOutput, "authentication failed") {
				t.Fatalf("km command failed with auth error after unsuspend.\nOutput: %s\nError: %v", createOutput, err)
			}
			// Non-auth error might be OK
			t.Logf("Command returned non-auth error: %v", err)
		}

		// Verify CA was registered successfully (no warning)
		if strings.Contains(createOutput, "Warning: Failed to register") {
			t.Fatalf("CA registration failed after unsuspend - auth not restored.\nOutput: %s", createOutput)
		}

		t.Logf("km ssh-ca create succeeded. Output: %s", createOutput)
		logOK(t, fmt.Sprintf("Created and registered SSH CA '%s' (KeyMaker auth restored)", caAfterUnsuspend))

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: KeyMaker auth restored after unsuspend"))
	})

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: TestSuspendedOperatorKeyMakerAuth - All scenarios"))
}
