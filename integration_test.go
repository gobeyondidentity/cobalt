// +build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
)

// Color formatters
var (
	stepFmt = color.New(color.FgBlue, color.Bold).SprintFunc()
	okFmt   = color.New(color.FgGreen).SprintFunc()
	infoFmt = color.New(color.FgYellow).SprintFunc()
	cmdFmt  = color.New(color.FgCyan).SprintFunc()
	dimFmt  = color.New(color.Faint).SprintFunc()
	errFmt  = color.New(color.FgRed, color.Bold).SprintFunc()
)

func init() {
	// Force colors even when output is not a TTY (e.g., over SSH)
	color.NoColor = false
}

// TestConfig holds the test environment configuration
type TestConfig struct {
	WorkbenchIP    string
	UseWorkbench   bool
	ServerVM       string
	DPUVM          string
	HostVM         string
	TMFIFOPort     string
	CommandTimeout time.Duration
	t              *testing.T // for logging
}

func newTestConfig(t *testing.T) *TestConfig {
	return &TestConfig{
		WorkbenchIP:    os.Getenv("WORKBENCH_IP"),
		UseWorkbench:   os.Getenv("WORKBENCH_IP") != "",
		ServerVM:       "qa-server",
		DPUVM:          "qa-dpu",
		HostVM:         "qa-host",
		TMFIFOPort:     "54321",
		CommandTimeout: 30 * time.Second,
		t:              t,
	}
}

// runCmd executes a command with timeout and returns output
func runCmd(ctx context.Context, t *testing.T, name string, args ...string) (string, error) {
	cmdStr := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	if t != nil {
		// Command in bold yellow to make it pop
		fmt.Printf("    %s %s\n", color.New(color.FgCyan, color.Bold).Sprint("$"), color.New(color.FgHiYellow, color.Bold).Sprint(cmdStr))
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	elapsed := time.Since(start)
	output := stdout.String() + stderr.String()

	if t != nil {
		// Output in dim gray for contrast
		if len(output) > 0 {
			// Truncate very long output
			logOutput := output
			if len(logOutput) > 500 {
				logOutput = logOutput[:500] + "... (truncated)"
			}
			fmt.Printf("      %s %s\n", dimFmt(fmt.Sprintf("[%v]", elapsed.Round(time.Millisecond))), dimFmt(strings.TrimSpace(logOutput)))
		} else {
			fmt.Printf("      %s\n", dimFmt(fmt.Sprintf("[%v] (no output)", elapsed.Round(time.Millisecond))))
		}
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return output, fmt.Errorf("%s after %v: %s", errFmt("TIMEOUT"), elapsed, cmdStr)
		}
		return output, fmt.Errorf("%w: %s", err, output)
	}
	return output, nil
}

// runSSH runs a command on workbench via SSH
func (c *TestConfig) runSSH(ctx context.Context, cmd string) (string, error) {
	if !c.UseWorkbench {
		return runCmd(ctx, c.t, "bash", "-c", cmd)
	}
	return runCmd(ctx, c.t, "ssh", fmt.Sprintf("nmelo@%s", c.WorkbenchIP), cmd)
}

// multipassExec runs a command inside a VM
func (c *TestConfig) multipassExec(ctx context.Context, vm string, args ...string) (string, error) {
	fullArgs := append([]string{"exec", vm, "--"}, args...)
	if c.UseWorkbench {
		// Quote args that contain shell metacharacters
		quotedArgs := make([]string, len(fullArgs))
		for i, arg := range fullArgs {
			if strings.ContainsAny(arg, " <>|&;$`\"'\\") {
				quotedArgs[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\\''"))
			} else {
				quotedArgs[i] = arg
			}
		}
		cmd := fmt.Sprintf("multipass %s", strings.Join(quotedArgs, " "))
		return c.runSSH(ctx, cmd)
	}
	return runCmd(ctx, c.t, "multipass", fullArgs...)
}

// getVMIP gets the IP address of a VM
func (c *TestConfig) getVMIP(ctx context.Context, vm string) (string, error) {
	var output string
	var err error
	if c.UseWorkbench {
		output, err = c.runSSH(ctx, fmt.Sprintf("multipass info %s | grep IPv4 | awk '{print $2}'", vm))
	} else {
		output, err = runCmd(ctx, c.t, "bash", "-c",
			fmt.Sprintf("multipass info %s | grep IPv4 | awk '{print $2}'", vm))
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// killProcess kills a process in a VM (logs but ignores errors)
func (c *TestConfig) killProcess(ctx context.Context, vm, process string) {
	fmt.Printf("    %s\n", dimFmt(fmt.Sprintf("...killing %s on %s", process, vm)))
	c.multipassExec(ctx, vm, "sudo", "pkill", "-9", process)
}

// logStep logs a test step in blue bold
func logStep(t *testing.T, step int, msg string) {
	fmt.Printf("\n%s %s\n", stepFmt(fmt.Sprintf("[Step %d]", step)), msg)
}

// logOK logs a success message in green
func logOK(t *testing.T, msg string) {
	fmt.Printf("    %s %s\n", okFmt("✓"), msg)
}

// logInfo logs an info message
func logInfo(t *testing.T, format string, args ...interface{}) {
	fmt.Printf("    %s\n", fmt.Sprintf(format, args...))
}

// TestVMsRunning verifies all VMs are accessible
func TestVMsRunning(t *testing.T) {
	cfg := newTestConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.CommandTimeout)
	defer cancel()

	vms := []string{cfg.ServerVM, cfg.DPUVM, cfg.HostVM}
	for _, vm := range vms {
		vm := vm // capture range variable
		t.Run(vm, func(t *testing.T) {
			output, err := cfg.multipassExec(ctx, vm, "echo", "ok")
			if err != nil {
				t.Fatalf("VM %s not accessible: %v", vm, err)
			}
			if !strings.Contains(output, "ok") {
				t.Fatalf("VM %s unexpected output: %s", vm, output)
			}
		})
	}
}

// TestTMFIFOTransportIntegration is the main integration test
func TestTMFIFOTransportIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := newTestConfig(t)
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
		cfg.killProcess(cleanupCtx, cfg.DPUVM, "socat")
		cfg.killProcess(cleanupCtx, cfg.HostVM, "sentry")
		cfg.killProcess(cleanupCtx, cfg.HostVM, "socat")
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

	// Step 2: Start socat on DPU (creates /dev/tmfifo_net0)
	logStep(t, 2, "Starting TMFIFO socat on DPU...")
	cfg.killProcess(ctx, cfg.DPUVM, "socat")
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid socat PTY,raw,echo=0,link=/dev/tmfifo_net0,mode=666 TCP-LISTEN:%s,reuseaddr,fork > /tmp/socat.log 2>&1 < /dev/null &", cfg.TMFIFOPort))
	if err != nil {
		t.Fatalf("Failed to start socat on DPU: %v", err)
	}
	time.Sleep(2 * time.Second)

	// Verify device exists
	output, err = cfg.multipassExec(ctx, cfg.DPUVM, "ls", "-la", "/dev/tmfifo_net0")
	if err != nil {
		t.Fatalf("TMFIFO device not created on DPU: %v", err)
	}
	logOK(t, fmt.Sprintf("TMFIFO device: %s", strings.TrimSpace(output)))

	// Step 3: Start aegis
	logStep(t, 3, "Starting aegis...")
	cfg.killProcess(ctx, cfg.DPUVM, "aegis")
	_, err = cfg.multipassExec(ctx, cfg.DPUVM, "bash", "-c",
		fmt.Sprintf("sudo setsid /home/ubuntu/aegis -local-api -allow-tmfifo-net -control-plane http://%s:18080 -dpu-name qa-dpu > /tmp/aegis.log 2>&1 < /dev/null &", serverIP))
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
	logOK(t, "Aegis started with TMFIFO listener")

	// Step 4: Register DPU with control plane
	logStep(t, 4, "Registering DPU...")

	// Create tenant (ignore error if already exists)
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "tenant", "add", "qa-tenant", "--insecure")

	// Remove stale DPU registration if exists
	_, _ = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl", "dpu", "remove", "qa-dpu", "--insecure")

	// Register DPU with aegis's gRPC port (default 18051)
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"dpu", "add", fmt.Sprintf("%s:18051", dpuIP), "--name", "qa-dpu", "--insecure")
	if err != nil {
		t.Fatalf("Failed to register DPU: %v", err)
	}

	// Assign DPU to tenant
	_, err = cfg.multipassExec(ctx, cfg.ServerVM, "/home/ubuntu/bluectl",
		"tenant", "assign", "qa-tenant", "qa-dpu", "--insecure")
	if err != nil {
		t.Fatalf("Failed to assign DPU to tenant: %v", err)
	}
	logOK(t, "DPU registered and assigned to tenant")

	// Step 5: Start socat on host
	logStep(t, 5, "Starting TMFIFO socat on host...")
	cfg.killProcess(ctx, cfg.HostVM, "socat")
	_, err = cfg.multipassExec(ctx, cfg.HostVM, "bash", "-c",
		fmt.Sprintf("sudo setsid socat PTY,raw,echo=0,link=/dev/tmfifo_net0,mode=666 TCP:%s:%s > /tmp/socat.log 2>&1 < /dev/null &", dpuIP, cfg.TMFIFOPort))
	if err != nil {
		t.Fatalf("Failed to start socat on host: %v", err)
	}
	time.Sleep(2 * time.Second)

	// Verify device exists
	output, err = cfg.multipassExec(ctx, cfg.HostVM, "ls", "-la", "/dev/tmfifo_net0")
	if err != nil {
		t.Fatalf("TMFIFO device not created on host: %v", err)
	}
	logOK(t, "TMFIFO tunnel established")

	// Step 6: Run sentry enrollment
	logStep(t, 6, "Running sentry enrollment...")
	sentryCtx, sentryCancel := context.WithTimeout(ctx, 30*time.Second)
	defer sentryCancel()

	output, err = cfg.multipassExec(sentryCtx, cfg.HostVM, "sudo", "/home/ubuntu/sentry", "--force-tmfifo", "--oneshot")

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
