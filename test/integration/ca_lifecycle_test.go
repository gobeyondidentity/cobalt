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

// TestCALifecycleE2E validates the SSH CA lifecycle operations.
// This test is critical because SSH CA is the cryptographic foundation for SSH access.
// If CA operations are broken, the entire SSH credential flow fails.
//
// The test verifies:
// 1. CA creation and listing
// 2. Certificate signing with valid CA
// 3. CA deletion
// 4. Signing with deleted CA fails
// 5. Duplicate CA creation is idempotent
func TestCALifecycleE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Test-unique identifiers
	testID := fmt.Sprintf("%d", time.Now().Unix())
	tenantName := fmt.Sprintf("ca-lifecycle-tenant-%s", testID)
	operatorEmail := fmt.Sprintf("ca-lifecycle-op-%s@test.local", testID)
	dpuName := "qa-dpu" // Reuse existing DPU

	// CA names for each scenario
	lifecycleCA := fmt.Sprintf("lifecycle-ca-%s", testID)
	dupCA := fmt.Sprintf("dup-ca-%s", testID)

	// Test keypair paths on qa-server
	testKeyPath := fmt.Sprintf("/tmp/test_key_%s", testID)

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", dimFmt("Cleaning up test artifacts..."))
		// Clean up test key files
		cfg.multipassExec(cleanupCtx, cfg.ServerVM, "rm", "-f", testKeyPath)
		cfg.multipassExec(cleanupCtx, cfg.ServerVM, "rm", "-f", testKeyPath+".pub")
		cfg.multipassExec(cleanupCtx, cfg.ServerVM, "rm", "-f", testKeyPath+"-cert.pub")
		// Clear km config
		cfg.multipassExec(cleanupCtx, cfg.ServerVM, "rm", "-rf", "/home/ubuntu/.km")
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
	// SETUP: Start nexus and configure operator access
	// =========================================================================
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

	// Create tenant
	logStep(t, 2, "Creating tenant...")
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "add", tenantName, "--server", "http://localhost:18080")
	logOK(t, fmt.Sprintf("Created tenant '%s'", tenantName))

	// Ensure DPU is registered and assigned
	logStep(t, 3, "Ensuring DPU is registered...")
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "dpu", "remove", dpuName, "--server", "http://localhost:18080")
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"dpu", "add", fmt.Sprintf("%s:18051", dpuIP), "--name", dpuName, "--server", "http://localhost:18080")
	if err != nil {
		// DPU might already exist, try to continue
		logInfo(t, "DPU add returned: %v (may already exist)", err)
	}
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"tenant", "assign", tenantName, dpuName, "--server", "http://localhost:18080")
	logOK(t, "DPU registered/assigned")

	// Create invite and initialize km
	logStep(t, 4, "Creating operator and initializing km...")
	inviteOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"operator", "invite", operatorEmail, tenantName, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to create invite: %v", err)
	}
	inviteCode := extractInviteCode(inviteOutput)
	if inviteCode == "" {
		t.Fatalf("Could not extract invite code from output:\n%s", inviteOutput)
	}

	// Initialize km
	cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-rf", "/home/ubuntu/.km")
	kmInitOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
		"init", "--invite-code", inviteCode, "--control-plane", "http://localhost:18080", "--force")
	if err != nil {
		t.Fatalf("km init failed: %v\nOutput: %s", err, kmInitOutput)
	}
	logOK(t, "KeyMaker initialized")

	// Generate test SSH keypair
	logStep(t, 5, "Generating test SSH keypair...")
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "ssh-keygen", "-t", "ed25519",
		"-f", testKeyPath, "-N", "", "-q")
	if err != nil {
		t.Fatalf("Failed to generate test keypair: %v", err)
	}
	logOK(t, fmt.Sprintf("Generated test keypair at %s", testKeyPath))

	// =========================================================================
	// SCENARIO 1: CA creation and listing
	// =========================================================================
	t.Run("Scenario1_CreateAndList", func(t *testing.T) {
		logStep(t, 1, "Creating SSH CA...")
		output, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", lifecycleCA)
		if err != nil {
			t.Fatalf("km ssh-ca create failed: %v\nOutput: %s", err, output)
		}
		logOK(t, fmt.Sprintf("Created SSH CA '%s'", lifecycleCA))

		logStep(t, 2, "Listing SSH CAs...")
		listOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "list")
		if err != nil {
			t.Fatalf("km ssh-ca list failed: %v\nOutput: %s", err, listOutput)
		}

		if !strings.Contains(listOutput, lifecycleCA) {
			t.Fatalf("CA '%s' not found in list output:\n%s", lifecycleCA, listOutput)
		}
		logOK(t, fmt.Sprintf("CA '%s' appears in list", lifecycleCA))

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 1 - CA creation and listing"))
	})

	// =========================================================================
	// SCENARIO 2: Certificate signing with valid CA
	// =========================================================================
	t.Run("Scenario2_CertificateSigning", func(t *testing.T) {
		certPath := testKeyPath + "-cert.pub"

		// Grant operator permission to use the CA before signing
		logStep(t, 1, "Granting operator permission to use CA...")
		grantOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
			"operator", "grant", operatorEmail, tenantName, lifecycleCA, dpuName, "--server", "http://localhost:18080")
		if err != nil {
			t.Fatalf("bluectl operator grant failed: %v\nOutput: %s", err, grantOutput)
		}
		logOK(t, fmt.Sprintf("Granted operator access to CA '%s'", lifecycleCA))

		logStep(t, 2, "Signing certificate with valid CA...")
		signOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "sign", lifecycleCA, "--principal", "testuser", "--pubkey", testKeyPath+".pub")
		if err != nil {
			t.Fatalf("km ssh-ca sign failed: %v\nOutput: %s", err, signOutput)
		}

		// Save certificate output to file
		logStep(t, 3, "Saving certificate to file...")
		_, err = cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c",
			fmt.Sprintf("/home/ubuntu/km ssh-ca sign %s --principal testuser --pubkey %s.pub > %s",
				lifecycleCA, testKeyPath, certPath))
		if err != nil {
			t.Fatalf("Failed to save certificate: %v", err)
		}
		logOK(t, fmt.Sprintf("Certificate saved to %s", certPath))

		logStep(t, 4, "Inspecting certificate with ssh-keygen...")
		inspectOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "ssh-keygen", "-L", "-f", certPath)
		if err != nil {
			t.Fatalf("Failed to inspect certificate: %v\nOutput: %s", err, inspectOutput)
		}

		// Verify certificate type
		if !strings.Contains(inspectOutput, "cert") {
			t.Fatalf("Certificate type not found in output:\n%s", inspectOutput)
		}
		logOK(t, "Certificate type verified")

		// Verify principal
		if !strings.Contains(inspectOutput, "testuser") {
			t.Fatalf("Principal 'testuser' not found in certificate:\n%s", inspectOutput)
		}
		logOK(t, "Principal 'testuser' verified")

		// Verify validity period
		if !strings.Contains(inspectOutput, "Valid:") {
			t.Fatalf("Validity period not found in certificate:\n%s", inspectOutput)
		}
		logOK(t, "Validity period present")

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 2 - Certificate signing"))
	})

	// =========================================================================
	// SCENARIO 3: CA deletion
	// =========================================================================
	t.Run("Scenario3_CADeletion", func(t *testing.T) {
		logStep(t, 1, "Deleting SSH CA...")
		output, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "delete", lifecycleCA, "--force")
		if err != nil {
			t.Fatalf("km ssh-ca delete failed: %v\nOutput: %s", err, output)
		}
		logOK(t, fmt.Sprintf("Deleted SSH CA '%s'", lifecycleCA))

		logStep(t, 2, "Verifying CA no longer in list...")
		listOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "list")
		if err != nil {
			// Empty list might return exit code, check if CA is absent
			logInfo(t, "km ssh-ca list returned: %v", err)
		}

		if strings.Contains(listOutput, lifecycleCA) {
			t.Fatalf("CA '%s' should NOT appear in list after deletion:\n%s", lifecycleCA, listOutput)
		}
		logOK(t, fmt.Sprintf("CA '%s' no longer appears in list", lifecycleCA))

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 3 - CA deletion"))
	})

	// =========================================================================
	// SCENARIO 4: Signing with deleted CA fails
	// =========================================================================
	t.Run("Scenario4_SignWithDeletedCAFails", func(t *testing.T) {
		logStep(t, 1, "Attempting to sign with deleted CA (should fail)...")
		signOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "sign", lifecycleCA, "--principal", "testuser", "--pubkey", testKeyPath+".pub")

		// Verify command failed
		if err == nil {
			t.Fatalf("km ssh-ca sign should have failed with deleted CA, but succeeded. Output:\n%s", signOutput)
		}
		logOK(t, "Command failed as expected")

		// Verify error message indicates CA not found or not authorized
		combinedOutput := signOutput + err.Error()
		if !strings.Contains(strings.ToLower(combinedOutput), "not found") &&
			!strings.Contains(strings.ToLower(combinedOutput), "no such") &&
			!strings.Contains(strings.ToLower(combinedOutput), "does not exist") &&
			!strings.Contains(strings.ToLower(combinedOutput), "not authorized") &&
			!strings.Contains(strings.ToLower(combinedOutput), "unknown") {
			t.Fatalf("Expected 'not found' or 'not authorized' error, got: %s", combinedOutput)
		}
		logOK(t, fmt.Sprintf("Error indicates CA not available: %s", truncateForLog(combinedOutput, 80)))

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 4 - Signing with deleted CA fails"))
	})

	// =========================================================================
	// SCENARIO 5: Duplicate CA creation is idempotent
	// =========================================================================
	t.Run("Scenario5_DuplicateCAIdempotent", func(t *testing.T) {
		logStep(t, 1, "Creating SSH CA (first time)...")
		output, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", dupCA)
		if err != nil {
			t.Fatalf("First km ssh-ca create failed: %v\nOutput: %s", err, output)
		}
		logOK(t, fmt.Sprintf("Created SSH CA '%s' (first time)", dupCA))

		logStep(t, 2, "Creating SSH CA (second time, same name)...")
		output2, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "create", dupCA)
		if err != nil {
			t.Fatalf("Second km ssh-ca create failed: %v\nOutput: %s", err, output2)
		}
		logOK(t, fmt.Sprintf("Created SSH CA '%s' (second time) - command succeeded", dupCA))

		logStep(t, 3, "Verifying only ONE CA with that name exists...")
		listOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km",
			"ssh-ca", "list")
		if err != nil {
			t.Fatalf("km ssh-ca list failed: %v\nOutput: %s", err, listOutput)
		}

		// Count occurrences of the CA name in the list
		count := strings.Count(listOutput, dupCA)
		if count != 1 {
			t.Fatalf("Expected exactly 1 occurrence of '%s' in list, found %d:\n%s", dupCA, count, listOutput)
		}
		logOK(t, fmt.Sprintf("Exactly 1 CA named '%s' exists (idempotent)", dupCA))

		// Cleanup: delete the dup CA
		cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/km", "ssh-ca", "delete", dupCA, "--force")

		fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Scenario 5 - Duplicate CA creation is idempotent"))
	})

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: TestCALifecycleE2E - All scenarios"))
}
