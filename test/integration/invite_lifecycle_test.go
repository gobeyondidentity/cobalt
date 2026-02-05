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

// TestInviteCodeLifecycle verifies invite code creation, usage, and error handling.
// This is a regression test for the v0.6.7 issue where invites didn't work until nexus restart.
//
// Acceptance Criteria (si-jgp.13):
// 1. Create invite -> invite usable immediately (no restart needed)
// 2. Use invite -> operator enrolled successfully
// 3. Use invite twice -> second use rejected with "already used" error
// 4. Expired invite -> rejected with "invite code has expired" error
// 5. Revoked invite -> rejected with "already been used" error
// 6. Invite for deleted tenant -> rejected appropriately
func TestInviteCodeLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	t.Log("Testing invite code lifecycle (v0.6.7 regression test)")
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Test-unique identifiers
	testID := fmt.Sprintf("%d", time.Now().Unix())
	tenantName := fmt.Sprintf("invite-test-%s", testID)
	dbPath := "/home/ubuntu/.local/share/bluectl/dpus.db"

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", dimFmt("Cleaning up processes..."))
		cfg.killProcess(cleanupCtx, cfg.ServerVM, "nexus")
	})

	// Get server IP
	serverIP, err := cfg.getVMIP(ctx, cfg.ServerVM)
	if err != nil {
		t.Fatalf("Failed to get server IP: %v", err)
	}
	logInfo(t, "Server IP: %s", serverIP)

	// Step 1: Start nexus with fresh state
	logStep(t, 1, "Starting nexus with fresh database...")
	cfg.killProcess(ctx, cfg.ServerVM, "nexus")

	// Remove existing database for clean start
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-f", dbPath)
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-f", dbPath+"-wal")
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-f", dbPath+"-shm")

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

	// Step 2: Create tenant
	logStep(t, 2, "Creating tenant...")
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "add", tenantName, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to create tenant: %v", err)
	}
	logOK(t, fmt.Sprintf("Created tenant '%s'", tenantName))

	// =========================================================================
	// Criterion 1 & 2: Create invite -> usable immediately -> operator enrolled
	// =========================================================================
	logStep(t, 3, "Testing invite creation and immediate use (regression test)...")

	operatorEmail1 := fmt.Sprintf("op1-%s@test.local", testID)
	inviteOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"operator", "invite", operatorEmail1, tenantName, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to create invite: %v", err)
	}

	inviteCode1 := extractInviteCode(inviteOutput)
	if inviteCode1 == "" {
		t.Fatalf("Could not extract invite code from output:\n%s", inviteOutput)
	}
	t.Logf("Created invite code: %s for %s", inviteCode1, operatorEmail1)

	// Use invite IMMEDIATELY (no restart!) - this is the v0.6.7 regression test
	bindResult, err := tryBindInvite(cfg, ctx, serverIP, inviteCode1, "fp-1", "device-1")
	if err != nil {
		t.Fatalf("Failed to call bind API: %v", err)
	}

	if !strings.Contains(bindResult, "keymaker_id") {
		t.Fatalf("Criterion 1 FAILED: Invite not usable immediately. Response: %s", bindResult)
	}
	logOK(t, "Criterion 1: Invite usable immediately after creation (v0.6.7 regression PASSED)")
	logOK(t, "Criterion 2: Operator enrolled successfully")

	// =========================================================================
	// Criterion 3: Use invite twice -> rejected (generic error to prevent enumeration)
	// =========================================================================
	logStep(t, 4, "Testing double-use rejection...")

	bindResult2, _ := tryBindInvite(cfg, ctx, serverIP, inviteCode1, "fp-2", "device-2")

	if !strings.Contains(bindResult2, "invalid or expired invite code") {
		t.Fatalf("Criterion 3 FAILED: Expected 'invalid or expired invite code' error, got: %s", bindResult2)
	}
	logOK(t, "Criterion 3: Second use rejected with generic error (prevents enumeration)")

	// =========================================================================
	// Criterion 4: Expired invite -> rejected "expired"
	// =========================================================================
	logStep(t, 5, "Testing expired invite rejection...")

	operatorEmail2 := fmt.Sprintf("op2-%s@test.local", testID)
	inviteOutput2, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"operator", "invite", operatorEmail2, tenantName, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to create second invite: %v", err)
	}

	inviteCode2 := extractInviteCode(inviteOutput2)
	if inviteCode2 == "" {
		t.Fatalf("Could not extract invite code from output:\n%s", inviteOutput2)
	}
	t.Logf("Created invite code: %s for %s", inviteCode2, operatorEmail2)

	// Expire the invite via direct database update
	expireCmd := fmt.Sprintf(`sqlite3 '%s' "UPDATE invite_codes SET expires_at = strftime('%%s', 'now', '-1 hour') WHERE operator_email = '%s' AND status = 'pending'"`,
		dbPath, operatorEmail2)
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c", expireCmd)
	if err != nil {
		t.Fatalf("Failed to expire invite in database: %v", err)
	}
	t.Log("Manually expired invite in database")

	// Try to use expired invite
	bindResult3, _ := tryBindInvite(cfg, ctx, serverIP, inviteCode2, "fp-3", "device-3")

	if !strings.Contains(bindResult3, "invalid or expired invite code") {
		t.Fatalf("Criterion 4 FAILED: Expected 'invalid or expired invite code' error, got: %s", bindResult3)
	}
	logOK(t, "Criterion 4: Expired invite rejected with generic error (prevents enumeration)")

	// =========================================================================
	// Criterion 5: Revoked invite -> rejected (generic error to prevent enumeration)
	// =========================================================================
	logStep(t, 6, "Testing revoked invite rejection...")

	operatorEmail3 := fmt.Sprintf("op3-%s@test.local", testID)
	inviteOutput3, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"operator", "invite", operatorEmail3, tenantName, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to create third invite: %v", err)
	}

	inviteCode3 := extractInviteCode(inviteOutput3)
	if inviteCode3 == "" {
		t.Fatalf("Could not extract invite code from output:\n%s", inviteOutput3)
	}
	t.Logf("Created invite code: %s for %s", inviteCode3, operatorEmail3)

	// Revoke the invite via direct database update
	revokeCmd := fmt.Sprintf(`sqlite3 '%s' "UPDATE invite_codes SET status = 'revoked' WHERE operator_email = '%s' AND status = 'pending'"`,
		dbPath, operatorEmail3)
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c", revokeCmd)
	if err != nil {
		t.Fatalf("Failed to revoke invite in database: %v", err)
	}
	t.Log("Manually revoked invite in database")

	// Try to use revoked invite
	bindResult4, _ := tryBindInvite(cfg, ctx, serverIP, inviteCode3, "fp-4", "device-4")

	// Revoked invites now return generic error to prevent enumeration
	if !strings.Contains(bindResult4, "invalid or expired invite code") {
		t.Fatalf("Criterion 5 FAILED: Expected 'invalid or expired invite code' error for revoked invite, got: %s", bindResult4)
	}
	logOK(t, "Criterion 5: Revoked invite rejected with generic error (prevents enumeration)")

	// =========================================================================
	// Criterion 6: Invite for deleted tenant -> rejected
	// =========================================================================
	logStep(t, 7, "Testing invite for deleted tenant...")

	tenantName2 := fmt.Sprintf("invite-del-%s", testID)
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "add", tenantName2, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to create second tenant: %v", err)
	}
	t.Logf("Created tenant '%s'", tenantName2)

	operatorEmail4 := fmt.Sprintf("op4-%s@test.local", testID)
	inviteOutput4, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"operator", "invite", operatorEmail4, tenantName2, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to create invite for second tenant: %v", err)
	}

	inviteCode4 := extractInviteCode(inviteOutput4)
	if inviteCode4 == "" {
		t.Fatalf("Could not extract invite code from output:\n%s", inviteOutput4)
	}
	t.Logf("Created invite code: %s for %s", inviteCode4, operatorEmail4)

	// Delete the tenant
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "remove", tenantName2, "--server", "http://localhost:18080")
	if err != nil {
		t.Logf("Tenant deletion result: %v (may have constraints)", err)
	} else {
		t.Logf("Deleted tenant '%s'", tenantName2)
	}

	// Try to use invite for deleted tenant
	bindResult5, _ := tryBindInvite(cfg, ctx, serverIP, inviteCode4, "fp-5", "device-5")

	// The invite should fail - either tenant not found or orphaned invite cleaned up
	if strings.Contains(bindResult5, "keymaker_id") {
		t.Fatalf("Criterion 6 FAILED: Invite succeeded for deleted tenant. Response: %s", bindResult5)
	}
	logOK(t, fmt.Sprintf("Criterion 6: Invite for deleted tenant rejected: %s", truncateForLog(bindResult5, 80)))

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: Invite code lifecycle test"))
	t.Log("All invite code lifecycle acceptance criteria verified")
}

// tryBindInvite attempts to bind an invite code via curl to the nexus API.
func tryBindInvite(cfg *TestConfig, ctx context.Context, serverIP, inviteCode, fingerprint, deviceName string) (string, error) {
	testPubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTa5xOvvKPh8rO5lDXm0G8dLJHBUGYT0NxXTTZ9R1Z2 test@test"

	bindJSON := fmt.Sprintf(`{"invite_code":"%s","public_key":"%s","platform":"linux","secure_element":"software","device_fingerprint":"%s","device_name":"%s"}`,
		inviteCode, testPubKey, fingerprint, deviceName)

	curlCmd := fmt.Sprintf(`curl -s -X POST http://%s:18080/api/v1/keymakers/bind -H "Content-Type: application/json" -d '%s'`,
		serverIP, bindJSON)

	output, err := cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c", curlCmd)
	return output, err
}

// truncateForLog truncates a string for logging.
func truncateForLog(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
