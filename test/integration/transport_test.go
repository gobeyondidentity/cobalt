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

// TestTMFIFOTransportIntegration is the main integration test
func TestTMFIFOTransportIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
	testHostname := makeTestHostname(t)
	logInfo(t, "Test config: UseWorkbench=%v, WorkbenchIP=%s", cfg.UseWorkbench, cfg.WorkbenchIP)

	// Overall test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Cleanup on exit (runs even on panic/timeout)
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

	// Use setsid to create a new session that survives multipass exec exit
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "bash", "-c",
		"setsid /home/ubuntu/nexus > /tmp/nexus.log 2>&1 < /dev/null &")
	if err != nil {
		t.Fatalf("Failed to start nexus: %v", err)
	}
	time.Sleep(2 * time.Second)

	// Verify nexus is running
	output, err := cfg.multipassExec(ctx, cfg.ServerVM, "pgrep", "-x", "nexus")
	if err != nil || strings.TrimSpace(output) == "" {
		// Check logs for clues
		logs, _ := cfg.multipassExec(ctx, cfg.ServerVM, "cat", "/tmp/nexus.log")
		t.Fatalf("Nexus not running after start. Logs:\n%s", logs)
	}
	logOK(t, "Nexus started")

	// Step 2: Start aegis (listens on TCP port 9444 for tmfifo transport)
	logStep(t, 2, "Starting aegis...")
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	// Clear aegis state for test isolation
	cfg.multipassExec(ctx, cfg.DPUVM, "sudo", "rm", "-f", "/var/lib/aegis/aegis.db")
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/aegis -allow-tmfifo-net -server http://%s:18080 -dpu-name qa-dpu > /tmp/aegis.log 2>&1 < /dev/null &", serverIP))
	if err != nil {
		t.Fatalf("Failed to start aegis: %v", err)
	}
	time.Sleep(2 * time.Second)

	// Verify aegis is running and listening on TMFIFO
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

	// Create tenant (ignore error if already exists)
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "add", "qa-tenant", "--server", "http://localhost:18080")

	// Remove stale DPU registration if exists
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "dpu", "remove", "qa-dpu", "--server", "http://localhost:18080")

	// Register DPU with aegis's gRPC port (default 18051)
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"dpu", "add", fmt.Sprintf("%s:18051", dpuIP), "--name", "qa-dpu", "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to register DPU: %v", err)
	}

	// Assign DPU to tenant
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"tenant", "assign", "qa-tenant", "qa-dpu", "--server", "http://localhost:18080")
	if err != nil {
		t.Fatalf("Failed to assign DPU to tenant: %v", err)
	}
	logOK(t, "DPU registered and assigned to tenant")

	// Step 4: Run sentry enrollment (connects directly to aegis via TCP)
	logStep(t, 4, "Running sentry enrollment...")
	sentryCtx, sentryCancel := context.WithTimeout(ctx, 30*time.Second)
	defer sentryCancel()

	output, err = cfg.multipassExec(sentryCtx, cfg.HostVM, "sudo", "/home/ubuntu/sentry", "--hostname", testHostname, "--force-tmfifo", fmt.Sprintf("--tmfifo-addr=%s:9444", dpuIP), "--oneshot")

	// Check results
	if err != nil {
		// Check aegis log for more context
		aegisLog, _ := cfg.multipassExec(ctx, cfg.DPUVM, "tail", "-30", "/tmp/aegis.log")
		fmt.Printf("    Aegis log:\n%s\n", aegisLog)
		t.Fatalf("%s Sentry enrollment failed: %v", errFmt("✗"), err)
	}

	// Verify expected output
	if !strings.Contains(output, "Transport: tmfifo_net") {
		t.Errorf("%s Sentry did not use TMFIFO transport", errFmt("✗"))
	}
	if !strings.Contains(output, "Enrolled") {
		t.Errorf("%s Sentry did not complete enrollment", errFmt("✗"))
	}

	fmt.Printf("\n%s\n", color.New(color.FgGreen, color.Bold).Sprint("✓ Integration test PASSED"))
}
