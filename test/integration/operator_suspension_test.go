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
	caAfterActivate := fmt.Sprintf("ca-after-activate-%s", testID)

	// CA paths on qa-host
	caBeforeSuspendPath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caBeforeSuspend)
	caAfterSuspendPath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caAfterSuspend)
	caAfterActivatePath := fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", caAfterActivate)

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
		cfg.multipassExec(cleanupCtx, cfg.HostVM, "sudo", "rm", "-f", caAfterActivatePath)
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
	// SCENARIO 2: Activation restores access
	// =========================================================================
	t.Run("Scenario2_ActivationRestoresAccess", func(t *testing.T) {
		// Step 1: Activate the operator
		logStep(t, 1, "Activating operator...")
		activateOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "activate", operatorEmail, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator activate failed: %v\nOutput: %s", err, activateOutput)
		}
		if !strings.Contains(activateOutput, "activated") {
			t.Fatalf("Activate command did not confirm activation. Output:\n%s", activateOutput)
		}
		logOK(t, fmt.Sprintf("Operator activated: %s", operatorEmail))

		// Step 2: Create a new CA for post-activation test
		logStep(t, 2, "Creating new SSH CA for post-activation test...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", caAfterActivate)
		if err != nil {
			t.Fatalf("km ssh-ca create failed: %v", err)
		}
		logOK(t, fmt.Sprintf("Created SSH CA '%s'", caAfterActivate))

		// Grant permission for the new CA
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "grant", operatorEmail, tenantName, caAfterActivate, dpuName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator grant failed: %v", err)
		}
		logOK(t, "Granted operator access to new CA")

		// Step 3: Attempt km push AFTER activation (should succeed)
		logStep(t, 3, "Attempting km push AFTER activation (should succeed)...")
		pushOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"push", "ssh-ca", caAfterActivate, dpuName, "--force")
		if err != nil {
			nexusLog, _ := cfg.multipassExec(ctx, cfg.ServerVM, "tail", "-30", "/tmp/nexus.log")
			fmt.Printf("    Nexus log:\n%s\n", nexusLog)
			t.Fatalf("km push should work after activation: %v\nOutput: %s", err, pushOutput)
		}
		if !strings.Contains(pushOutput, "CA installed") {
			t.Fatalf("km push did not indicate success. Output:\n%s", pushOutput)
		}
		logOK(t, "Push succeeded after activation")

		// Step 4: Wait for credential file to appear with content (async delivery)
		logStep(t, 4, "Verifying credential was installed...")
		credentialTimeout := 15 * time.Second
		pollInterval := 500 * time.Millisecond
		deadline := time.Now().Add(credentialTimeout)
		var credContent string

		for time.Now().Before(deadline) {
			output, err := cfg.multipassExec(ctx, cfg.HostVM, "cat", caAfterActivatePath)
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
			t.Fatalf("Credential file not found or invalid at %s after %v", caAfterActivatePath, credentialTimeout)
		}
		logOK(t, fmt.Sprintf("Credential file exists: %s", caAfterActivatePath))

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 2 - Activation restores access"))
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

		// Step 3: Activate operator
		logStep(t, 3, "Activating operator...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "activate", operatorEmail, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator activate failed: %v", err)
		}
		logOK(t, "Operator activated")

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
