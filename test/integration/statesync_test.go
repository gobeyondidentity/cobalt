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

// TestStateSyncConsistency verifies that all commands read from a consistent data source.
// This is a regression test for v0.6.8 where different commands were reading from different
// databases (local vs server), causing "not found" errors for resources that clearly exist.
//
// Bug example: "tenant list reads server but operator invite reads local db" - so tenant
// shows in list but invite fails with "tenant not found".
//
// The test verifies:
// 1. Create tenant -> tenant list shows it IMMEDIATELY (no delay)
// 2. Create tenant -> operator invite for that tenant succeeds IMMEDIATELY
// 3. Register DPU -> dpu list shows it IMMEDIATELY
// 4. Register DPU -> tenant assign with that DPU succeeds IMMEDIATELY
// 5. All read operations use consistent data source (no local/server mismatch)
//
// NOTE: This is a simpler test than others - it only needs nexus running on qa-server VM.
// No aegis, sentry, socat, or tmfifo needed. This is purely a control plane test.
func TestStateSyncConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout (shorter since this is a simple control plane test)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Test-unique identifiers to avoid collisions
	testID := fmt.Sprintf("%d", time.Now().Unix())
	tenantName := fmt.Sprintf("sync-tenant-%s", testID)
	dpuName := fmt.Sprintf("sync-dpu-%s", testID)
	operatorEmail := fmt.Sprintf("sync-op-%s@test.local", testID)

	// Cleanup on exit
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		fmt.Printf("\n%s\n", dimFmt("Cleaning up processes..."))
		cfg.killProcess(cleanupCtx, cfg.ServerVM, "nexus")
		// Also cleanup DPU processes in case DPU registration test ran aegis
		cfg.killProcess(cleanupCtx, cfg.DPUVM, "aegis")
	})

	// Get server VM IP
	serverIP, err := cfg.getVMIP(ctx, cfg.ServerVM)
	if err != nil {
		t.Fatalf("Failed to get server IP: %v", err)
	}
	logInfo(t, "Server IP: %s", serverIP)

	// Step 1: Start nexus with fresh state
	logStep(t, 1, "Starting nexus with fresh database...")
	cfg.killProcess(ctx, cfg.ServerVM, "nexus")

	// Remove existing database to ensure fresh start
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-f", "/home/ubuntu/.local/share/bluectl/dpus.db")
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-f", "/home/ubuntu/.local/share/bluectl/dpus.db-wal")
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "rm", "-f", "/home/ubuntu/.local/share/bluectl/dpus.db-shm")

	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c",
		"setsid /home/ubuntu/nexus > /tmp/nexus.log 2>&1 < /dev/null &")
	if err != nil {
		t.Fatalf("Failed to start nexus: %v", err)
	}
	time.Sleep(2 * time.Second)

	// Verify nexus is running
	output, err := cfg.multipassExec(ctx, cfg.ServerVM, "pgrep", "-x", "nexus")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.multipassExec(ctx, cfg.ServerVM, "cat", "/tmp/nexus.log")
		t.Fatalf("Nexus not running after start. Logs:\n%s", logs)
	}
	logOK(t, "Nexus started with fresh database")

	// Step 2: Create tenant and IMMEDIATELY verify it in list (no delay)
	logStep(t, 2, "Creating tenant and verifying IMMEDIATE visibility...")
	t.Log("Creating tenant via bluectl tenant add")
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "add", tenantName, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to create tenant: %v", err)
	}

	// IMMEDIATELY verify tenant appears in list (the bug was that list worked but other ops failed)
	t.Log("IMMEDIATELY checking tenant list (no delay)")
	tenantList, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "list", "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to list tenants: %v", err)
	}

	if !strings.Contains(tenantList, tenantName) {
		t.Fatalf("SYNC BUG: Tenant '%s' not visible in list immediately after creation. List:\n%s", tenantName, tenantList)
	}
	logOK(t, fmt.Sprintf("Tenant '%s' visible in list immediately after creation", tenantName))

	// Step 3: IMMEDIATELY create operator invite for that tenant (no delay)
	logStep(t, 3, "Creating operator invite IMMEDIATELY after tenant creation...")
	t.Log("Creating operator invite (this was the failing operation in the bug)")
	inviteOutput, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"operator", "invite", operatorEmail, tenantName, "--server", "http://localhost:18080")
	if err != nil {
		// This was the exact bug: tenant exists in list but invite fails with "tenant not found"
		t.Fatalf("SYNC BUG: Operator invite failed immediately after tenant creation: %v\nOutput: %s", err, inviteOutput)
	}

	// Extract invite code to verify it was actually created
	inviteCode := extractInviteCode(inviteOutput)
	if inviteCode == "" {
		t.Fatalf("Operator invite command succeeded but no invite code in output:\n%s", inviteOutput)
	}
	logOK(t, fmt.Sprintf("Operator invite created immediately (code: %s)", inviteCode))

	// Step 4: Verify operator appears in list immediately
	logStep(t, 4, "Verifying operator visible in list IMMEDIATELY...")
	t.Log("Checking operator list (no delay)")
	operatorList, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "operator", "list", "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to list operators: %v", err)
	}

	if !strings.Contains(operatorList, operatorEmail) {
		t.Fatalf("SYNC BUG: Operator '%s' not visible in list immediately after invite. List:\n%s", operatorEmail, operatorList)
	}
	logOK(t, fmt.Sprintf("Operator '%s' visible in list immediately after invite", operatorEmail))

	// Step 5: Start aegis for DPU registration test (listens on TCP port 9444 for tmfifo transport)
	// DPU registration requires aegis to be running
	logStep(t, 5, "Setting up DPU for registration test...")

	dpuIP, err := cfg.getVMIP(ctx, cfg.DPUVM)
	if err != nil {
		t.Fatalf("Failed to get DPU IP: %v", err)
	}
	logInfo(t, "DPU IP: %s", dpuIP)

	// Start aegis
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	// Clear aegis state for test isolation
	cfg.multipassExec(ctx, cfg.DPUVM, "sudo", "rm", "-f", "/var/lib/aegis/aegis.db")
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/aegis -allow-tmfifo-net -server http://%s:18080 -dpu-name %s > /tmp/aegis.log 2>&1 < /dev/null &", serverIP, dpuName))
	if err != nil {
		t.Fatalf("Failed to start aegis: %v", err)
	}
	time.Sleep(2 * time.Second)

	// Verify aegis is running
	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "pgrep", "-x", "aegis")
	if err != nil || strings.TrimSpace(output) == "" {
		logs, _ := cfg.multipassExec(ctx, cfg.DPUVM, "cat", "/tmp/aegis.log")
		t.Fatalf("Aegis not running. Logs:\n%s", logs)
	}
	logOK(t, "Aegis started for DPU registration")

	// Step 6: Register DPU and IMMEDIATELY verify it in list
	logStep(t, 6, "Registering DPU and verifying IMMEDIATE visibility...")
	t.Log("Registering DPU via bluectl dpu add")
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"dpu", "add", fmt.Sprintf("%s:18051", dpuIP), "--name", dpuName, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to register DPU: %v", err)
	}

	// IMMEDIATELY verify DPU appears in list (no delay)
	t.Log("IMMEDIATELY checking DPU list (no delay)")
	dpuList, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "dpu", "list", "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to list DPUs: %v", err)
	}

	if !strings.Contains(dpuList, dpuName) {
		t.Fatalf("SYNC BUG: DPU '%s' not visible in list immediately after registration. List:\n%s", dpuName, dpuList)
	}
	logOK(t, fmt.Sprintf("DPU '%s' visible in list immediately after registration", dpuName))

	// Step 7: IMMEDIATELY assign DPU to tenant (no delay)
	logStep(t, 7, "Assigning DPU to tenant IMMEDIATELY after registration...")
	t.Log("Assigning DPU to tenant (this tests read consistency between list and assign)")
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"tenant", "assign", tenantName, dpuName, "--server", "http://localhost:18080")
	if err != nil {
		// This would be a sync bug: DPU exists in list but assign fails with "dpu not found"
		t.Fatalf("SYNC BUG: Tenant assign failed immediately after DPU registration: %v", err)
	}
	logOK(t, fmt.Sprintf("DPU '%s' assigned to tenant '%s' immediately", dpuName, tenantName))

	// Step 8: Verify tenant assignment persisted (final consistency check)
	logStep(t, 8, "Verifying tenant assignment persisted...")
	t.Log("Checking tenant show output for DPU assignment")
	tenantShow, err := cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"tenant", "show", tenantName, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to show tenant: %v", err)
	}

	if !strings.Contains(tenantShow, "DPU Count:    1") {
		t.Fatalf("SYNC BUG: DPU assignment not visible in tenant show (expected DPU Count: 1). Output:\n%s", tenantShow)
	}
	logOK(t, "Tenant assignment persisted and visible (DPU Count: 1)")

	// Step 9: Cross-check all operations use same data source
	logStep(t, 9, "Running cross-check: verifying all operations use consistent data source...")

	// Create a second tenant and do the full flow in rapid succession
	tenant2 := fmt.Sprintf("sync-tenant2-%s", testID)
	operator2 := fmt.Sprintf("sync-op2-%s@test.local", testID)

	t.Log("Creating second tenant for cross-check")
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "add", tenant2, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to create second tenant: %v", err)
	}

	// Immediately do ALL operations in rapid succession
	t.Log("Running rapid-fire operations (list, invite, show) with no delays")

	// List should work
	tenantList, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "list", "--server", "http://localhost:18080")
	if err != nil || !strings.Contains(tenantList, tenant2) {
		t.Fatalf("SYNC BUG: Second tenant not in list. Error: %v, List:\n%s", err, tenantList)
	}

	// Invite should work
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"operator", "invite", operator2, tenant2, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("SYNC BUG: Second operator invite failed: %v", err)
	}

	// Show should work
	tenantShow, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"tenant", "show", tenant2, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("SYNC BUG: Tenant show failed for second tenant: %v", err)
	}

	// Assign existing DPU to second tenant (reassignment)
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"tenant", "assign", tenant2, dpuName, "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("SYNC BUG: DPU reassignment to second tenant failed: %v", err)
	}

	logOK(t, "All cross-check operations completed successfully")

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("PASSED: State sync consistency test"))
	t.Log("All read operations use consistent data source (no local/server mismatch)")
}
