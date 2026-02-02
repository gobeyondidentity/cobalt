//go:build dpu

// Package dpu provides hardware integration tests for DOCA ComCh transport.
//
// These tests run FROM the workbench (the machine with /dev/rshim0) and orchestrate
// the DPU via SSH over tmfifo_net (192.168.100.2). Round-trip tests start a server
// on the DPU and run the client locally on workbench.
//
// Run with: make test-dpu (from workbench)
package dpu

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/transport"
)

// DPU connection settings (tmfifo_net)
const (
	dpuTmfifoIP = "192.168.100.2"
	dpuUser     = "ubuntu"
	dpuRepoPath = "/home/ubuntu/secure-infra"
	dpuGoPath   = "/usr/local/go/bin/go"
)

// Environment variables for hardware test configuration
const (
	envDOCAPCIAddr    = "DOCA_PCI_ADDR"
	envDOCARepPCIAddr = "DOCA_REP_PCI_ADDR"
	envDOCAServerName = "DOCA_SERVER_NAME"
)

// Default test values
const (
	defaultTestServerName = "secureinfra-test"
	defaultDPUPCIAddr     = "0000:03:00.0"
	defaultDPURepPCIAddr  = "0000:01:00.0"
	defaultHostPCIAddr    = "0000:01:00.0"
)

// Hardware detection paths
var blueFieldIndicators = []string{
	"/dev/infiniband",
	"/opt/mellanox/doca",
	"/sys/class/infiniband",
}

// isRunningOnWorkbench returns true if running on a host with rshim/DPU attached.
func isRunningOnWorkbench() bool {
	_, err := os.Stat("/dev/rshim0")
	return err == nil
}

// isBlueFieldEnvironment checks if we're running on a system with BlueField hardware.
func isBlueFieldEnvironment() bool {
	for _, path := range blueFieldIndicators {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// skipUnlessWorkbench skips the test if not running from workbench.
func skipUnlessWorkbench(t *testing.T) {
	t.Helper()
	if !isRunningOnWorkbench() {
		t.Skip("DPU round-trip tests must run FROM workbench (machine with /dev/rshim0)")
	}
}

// getTestConfig returns the hardware test configuration from environment variables.
func getTestConfig(t *testing.T) (pciAddr, repPCIAddr, serverName string) {
	t.Helper()

	pciAddr = os.Getenv(envDOCAPCIAddr)
	repPCIAddr = os.Getenv(envDOCARepPCIAddr)
	serverName = os.Getenv(envDOCAServerName)

	if serverName == "" {
		serverName = defaultTestServerName
	}

	return pciAddr, repPCIAddr, serverName
}

// runCmd executes a command with context and returns output.
func runCmd(ctx context.Context, t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	cmdStr := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	t.Logf("$ %s", cmdStr)

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	output := stdout.String() + stderr.String()
	if len(output) > 0 {
		// Truncate very long output for readability
		logOutput := output
		if len(logOutput) > 500 {
			logOutput = logOutput[:500] + "... (truncated)"
		}
		t.Logf("  [%v] %s", elapsed.Round(time.Millisecond), strings.TrimSpace(logOutput))
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return output, fmt.Errorf("timeout after %v: %s", elapsed, cmdStr)
		}
		return output, fmt.Errorf("%w: %s", err, strings.TrimSpace(output))
	}
	return output, nil
}

// dpuSSH runs a command on the DPU via SSH over tmfifo_net.
func dpuSSH(ctx context.Context, t *testing.T, command string) (string, error) {
	t.Helper()
	return runCmd(ctx, t, "ssh",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		fmt.Sprintf("%s@%s", dpuUser, dpuTmfifoIP),
		command)
}

// dpuKillProcess kills a process on the DPU (logs but ignores errors).
func dpuKillProcess(ctx context.Context, t *testing.T, process string) {
	t.Helper()
	t.Logf("Killing %s on DPU...", process)
	dpuSSH(ctx, t, fmt.Sprintf("sudo pkill -9 %s 2>/dev/null || true", process))
}

// syncCodeToDPU syncs the current branch to the DPU.
func syncCodeToDPU(ctx context.Context, t *testing.T) error {
	t.Helper()
	t.Log("Syncing code to DPU...")

	// Get current branch
	branch, err := runCmd(ctx, t, "git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return fmt.Errorf("get current branch: %w", err)
	}
	branch = strings.TrimSpace(branch)

	// Sync on DPU
	cmd := fmt.Sprintf("cd %s && git fetch origin && git checkout origin/%s 2>/dev/null || git checkout %s",
		dpuRepoPath, branch, branch)
	_, err = dpuSSH(ctx, t, cmd)
	if err != nil {
		return fmt.Errorf("sync code: %w", err)
	}
	return nil
}

// buildTestBinaryOnDPU builds the test binary on the DPU (native ARM64).
func buildTestBinaryOnDPU(ctx context.Context, t *testing.T) error {
	t.Helper()
	t.Log("Building test binary on DPU (native ARM64)...")

	cmd := fmt.Sprintf("cd %s && %s test -c -tags=dpu,doca -o /tmp/dpu_server_test ./test/dpu/...",
		dpuRepoPath, dpuGoPath)
	_, err := dpuSSH(ctx, t, cmd)
	if err != nil {
		return fmt.Errorf("build test binary: %w", err)
	}
	return nil
}

// startEchoServerOnDPU starts the echo server test helper on the DPU.
// Returns a cleanup function that kills the server.
func startEchoServerOnDPU(ctx context.Context, t *testing.T, serverName string, maxMsgSize int, echoCount int) (func(), error) {
	t.Helper()
	t.Logf("Starting echo server on DPU (name=%s, maxMsg=%d, echoCount=%d)...", serverName, maxMsgSize, echoCount)

	// Kill any existing server
	dpuKillProcess(ctx, t, "dpu_server_test")
	time.Sleep(500 * time.Millisecond)

	// Start server in background with full detachment from SSH session.
	// Requirements:
	// - ssh -f: forks SSH after auth so parent returns immediately
	// - bash -c: ensures shell operators (&&, &) are interpreted correctly
	// - nohup: ignores SIGHUP when SSH session ends
	// - < /dev/null: closes stdin to prevent fd inheritance blocking SSH
	// - &: backgrounds process in bash so bash can exit
	// - sudo env VAR=val: preserves env vars (sudo alone strips them)
	// Without all of these, the process gets "Killed" when SSH detaches.
	innerCmd := fmt.Sprintf(
		"cd %s && nohup sudo env DPU_SERVER_MODE=echo DOCA_PCI_ADDR=%s DOCA_REP_PCI_ADDR=%s DOCA_SERVER_NAME=%s "+
			"ECHO_COUNT=%d MAX_MSG_SIZE=%d /tmp/dpu_server_test -test.run=TestDPU_ServerHelper -test.timeout=120s "+
			"> /tmp/dpu_server.log 2>&1 < /dev/null &",
		dpuRepoPath, defaultDPUPCIAddr, defaultDPURepPCIAddr, serverName, echoCount, maxMsgSize)

	// Wrap in bash -c to ensure shell operators are interpreted correctly
	// when exec.Command passes the command string through SSH.
	cmd := fmt.Sprintf("bash -c %q", innerCmd)

	_, err := runCmd(ctx, t, "ssh",
		"-f",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		fmt.Sprintf("%s@%s", dpuUser, dpuTmfifoIP),
		cmd)
	if err != nil {
		return nil, fmt.Errorf("start server: %w", err)
	}

	// Wait for server to be ready
	time.Sleep(2 * time.Second)

	// Verify server is running
	out, err := dpuSSH(ctx, t, "pgrep -x dpu_server_test || echo 'not running'")
	if err != nil || strings.Contains(out, "not running") {
		// Get logs for debugging
		logs, _ := dpuSSH(ctx, t, "cat /tmp/dpu_server.log 2>/dev/null || echo 'no logs'")
		return nil, fmt.Errorf("server not running. Logs:\n%s", logs)
	}

	cleanup := func() {
		dpuKillProcess(context.Background(), t, "dpu_server_test")
	}

	return cleanup, nil
}

// TestDPU_ServerHelper is invoked on the DPU via SSH to run an echo server.
// It reads config from environment variables and echoes messages back to clients.
func TestDPU_ServerHelper(t *testing.T) {
	mode := os.Getenv("DPU_SERVER_MODE")
	if mode == "" {
		t.Skip("Only runs via DPU_SERVER_MODE env var from workbench orchestration")
	}

	pciAddr := os.Getenv(envDOCAPCIAddr)
	repPCIAddr := os.Getenv(envDOCARepPCIAddr)
	serverName := os.Getenv(envDOCAServerName)
	if serverName == "" {
		serverName = defaultTestServerName
	}

	// Parse echo count (0 = unlimited until client disconnects)
	echoCount := 0
	if ec := os.Getenv("ECHO_COUNT"); ec != "" {
		fmt.Sscanf(ec, "%d", &echoCount)
	}

	maxMsgSize := 4096
	if ms := os.Getenv("MAX_MSG_SIZE"); ms != "" {
		fmt.Sscanf(ms, "%d", &maxMsgSize)
	}

	t.Logf("Starting echo server: mode=%s, pci=%s, rep=%s, name=%s, echoCount=%d, maxMsg=%d",
		mode, pciAddr, repPCIAddr, serverName, echoCount, maxMsgSize)

	cfg := transport.DOCAComchServerConfig{
		PCIAddr:    pciAddr,
		RepPCIAddr: repPCIAddr,
		ServerName: serverName,
		MaxMsgSize: uint32(maxMsgSize),
	}

	server, err := transport.NewDOCAComchServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	t.Log("Server created, waiting for connection...")

	conn, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer conn.Close()

	t.Log("Client connected, starting echo loop...")

	count := 0
	for {
		if echoCount > 0 && count >= echoCount {
			t.Logf("Reached echo count limit (%d), exiting", echoCount)
			break
		}

		msg, err := conn.Recv()
		if err != nil {
			t.Logf("Recv error (client may have disconnected): %v", err)
			break
		}

		if err := conn.Send(msg); err != nil {
			t.Logf("Send error: %v", err)
			break
		}

		count++
		if count%10 == 0 {
			t.Logf("Echoed %d messages", count)
		}
	}

	t.Logf("Echo server done, echoed %d messages total", count)
}

// TestDPU_EnvironmentDetection verifies that the hardware detection logic works.
func TestDPU_EnvironmentDetection(t *testing.T) {
	if isRunningOnWorkbench() {
		t.Log("Running on workbench (has /dev/rshim0)")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Check DPU connectivity
		out, err := dpuSSH(ctx, t, "hostname && uname -m")
		if err != nil {
			t.Fatalf("Cannot reach DPU via tmfifo_net: %v", err)
		}
		t.Logf("DPU info: %s", strings.TrimSpace(out))

		// Check for BlueField indicators on DPU
		for _, path := range blueFieldIndicators {
			out, _ := dpuSSH(ctx, t, fmt.Sprintf("test -e %s && echo 'found' || echo 'not found'", path))
			t.Logf("DPU %s: %s", path, strings.TrimSpace(out))
		}
	} else if isBlueFieldEnvironment() {
		t.Log("Running directly on BlueField")
		for _, path := range blueFieldIndicators {
			if _, err := os.Stat(path); err == nil {
				t.Logf("Found: %s", path)
			}
		}
	} else {
		t.Skip("No BlueField hardware detected and not on workbench")
	}
}

// TestDPU_DeviceDiscovery tests real device enumeration on BlueField hardware.
func TestDPU_DeviceDiscovery(t *testing.T) {
	if isRunningOnWorkbench() {
		// Run discovery on DPU via SSH
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		t.Log("Running device discovery on DPU via SSH...")

		if err := syncCodeToDPU(ctx, t); err != nil {
			t.Fatalf("Failed to sync code: %v", err)
		}

		cmd := fmt.Sprintf("cd %s && %s test -tags=dpu,doca -run=TestDPU_DeviceDiscovery -v ./test/dpu/... 2>&1 || true",
			dpuRepoPath, dpuGoPath)
		out, _ := dpuSSH(ctx, t, cmd)

		// Check for success in output
		if strings.Contains(out, "PASS") {
			t.Log("Device discovery passed on DPU")
		} else if strings.Contains(out, "SKIP") {
			t.Skip("Device discovery skipped on DPU")
		} else {
			t.Logf("Output:\n%s", out)
			if strings.Contains(out, "FAIL") {
				t.Fatal("Device discovery failed on DPU")
			}
		}
		return
	}

	// Running directly on DPU
	if !isBlueFieldEnvironment() {
		t.Skip("requires BlueField hardware: no DOCA indicators found")
	}

	devices, err := transport.DiscoverDOCADevices()
	if err != nil {
		if err == transport.ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("device discovery failed: %v", err)
	}

	if len(devices) == 0 {
		t.Fatal("no devices found despite BlueField indicators present")
	}

	t.Logf("Discovered %d device(s):", len(devices))
	for i, dev := range devices {
		t.Logf("  [%d] PCI: %s, IBDev: %s, Iface: %s, Type: %s, ComChClient: %v, ComChServer: %v",
			i, dev.PCIAddr, dev.IbdevName, dev.IfaceName, dev.FuncType,
			dev.IsComchClient, dev.IsComchServer)
	}

	hasComchDevice := false
	for _, dev := range devices {
		if dev.IsComchClient || dev.IsComchServer {
			hasComchDevice = true
			break
		}
	}

	if !hasComchDevice {
		t.Error("no ComCh-capable devices found")
	}
}

// TestDPU_ComchServerStarts tests that ComCh server initializes successfully.
func TestDPU_ComchServerStarts(t *testing.T) {
	if isRunningOnWorkbench() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		t.Log("Running server start test on DPU via SSH...")

		if err := syncCodeToDPU(ctx, t); err != nil {
			t.Fatalf("Failed to sync code: %v", err)
		}

		cmd := fmt.Sprintf("cd %s && DOCA_PCI_ADDR=%s DOCA_REP_PCI_ADDR=%s %s test -tags=dpu,doca -run=TestDPU_ComchServerStarts -v ./test/dpu/... 2>&1 || true",
			dpuRepoPath, defaultDPUPCIAddr, defaultDPURepPCIAddr, dpuGoPath)
		out, _ := dpuSSH(ctx, t, cmd)

		if strings.Contains(out, "PASS") {
			t.Log("Server start test passed on DPU")
		} else if strings.Contains(out, "SKIP") {
			t.Skip("Server start test skipped on DPU")
		} else {
			t.Logf("Output:\n%s", out)
			if strings.Contains(out, "FAIL") {
				t.Fatal("Server start test failed on DPU")
			}
		}
		return
	}

	// Running directly on DPU
	if !isBlueFieldEnvironment() {
		t.Skip("requires BlueField hardware: no DOCA indicators found")
	}

	pciAddr, repPCIAddr, serverName := getTestConfig(t)
	if pciAddr == "" || repPCIAddr == "" {
		t.Skipf("requires %s and %s environment variables", envDOCAPCIAddr, envDOCARepPCIAddr)
	}

	cfg := transport.DOCAComchServerConfig{
		PCIAddr:    pciAddr,
		RepPCIAddr: repPCIAddr,
		ServerName: serverName,
		MaxMsgSize: 4096,
	}

	server, err := transport.NewDOCAComchServer(cfg)
	if err != nil {
		if err == transport.ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	t.Logf("ComCh server started: name=%s, pci=%s, rep=%s",
		serverName, pciAddr, repPCIAddr)

	if server.Type() != transport.TransportDOCAComch {
		t.Errorf("wrong transport type: got %v, want %v", server.Type(), transport.TransportDOCAComch)
	}
}

// TestDPU_MessageRoundTrip tests sending and receiving a message.
// Orchestrates from workbench: starts server on DPU, runs client locally.
func TestDPU_MessageRoundTrip(t *testing.T) {
	skipUnlessWorkbench(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	_, _, serverName := getTestConfig(t)

	// Setup
	t.Log("Setting up round-trip test...")
	if err := syncCodeToDPU(ctx, t); err != nil {
		t.Fatalf("Failed to sync code: %v", err)
	}
	if err := buildTestBinaryOnDPU(ctx, t); err != nil {
		t.Fatalf("Failed to build test binary: %v", err)
	}

	// Start server on DPU
	cleanup, err := startEchoServerOnDPU(ctx, t, serverName, 4096, 1)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cleanup()

	// Run client locally
	t.Log("Connecting client from workbench...")

	clientCfg := transport.DOCAComchClientConfig{
		PCIAddr:    defaultHostPCIAddr,
		ServerName: serverName,
		MaxMsgSize: 4096,
	}

	client, err := transport.NewDOCAComchClient(clientCfg)
	if err != nil {
		if err == transport.ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connectCancel()

	if err := client.Connect(connectCtx); err != nil {
		t.Fatalf("Client connect failed: %v", err)
	}
	t.Log("Client connected")

	// Send test message
	testPayload := map[string]string{"test": "hardware", "time": time.Now().Format(time.RFC3339)}
	payloadJSON, _ := json.Marshal(testPayload)

	outMsg := &transport.Message{
		Version: transport.ProtocolVersion,
		Type:    transport.MessageEnrollRequest,
		ID:      "hw-test-001",
		TS:      time.Now().UnixMilli(),
		Payload: payloadJSON,
	}

	t.Log("Sending test message...")
	if err := client.Send(outMsg); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	t.Log("Waiting for echo...")
	inMsg, err := client.Recv()
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}

	// Verify round-trip
	if inMsg.ID != outMsg.ID {
		t.Errorf("ID mismatch: got %s, want %s", inMsg.ID, outMsg.ID)
	}
	if inMsg.Type != outMsg.Type {
		t.Errorf("Type mismatch: got %s, want %s", inMsg.Type, outMsg.Type)
	}
	if string(inMsg.Payload) != string(outMsg.Payload) {
		t.Errorf("Payload mismatch: got %s, want %s", inMsg.Payload, outMsg.Payload)
	}

	t.Log("Message round-trip successful")
}

// TestDPU_MultipleMessages tests exchanging multiple messages in sequence.
func TestDPU_MultipleMessages(t *testing.T) {
	skipUnlessWorkbench(t)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	const messageCount = 100
	_, _, serverName := getTestConfig(t)

	// Setup
	if err := syncCodeToDPU(ctx, t); err != nil {
		t.Fatalf("Failed to sync code: %v", err)
	}
	if err := buildTestBinaryOnDPU(ctx, t); err != nil {
		t.Fatalf("Failed to build test binary: %v", err)
	}

	// Start server on DPU
	cleanup, err := startEchoServerOnDPU(ctx, t, serverName, 4096, messageCount)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cleanup()

	// Run client locally
	t.Log("Connecting client...")

	clientCfg := transport.DOCAComchClientConfig{
		PCIAddr:        defaultHostPCIAddr,
		ServerName:     serverName,
		MaxMsgSize:     4096,
		RecvBufferSize: 64,
	}

	client, err := transport.NewDOCAComchClient(clientCfg)
	if err != nil {
		if err == transport.ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connectCancel()

	if err := client.Connect(connectCtx); err != nil {
		t.Fatalf("Client connect failed: %v", err)
	}

	// Send and receive messages
	t.Logf("Exchanging %d messages...", messageCount)
	start := time.Now()

	for i := 0; i < messageCount; i++ {
		payload := map[string]interface{}{
			"seq":   i,
			"data":  "test message payload",
			"nonce": time.Now().UnixNano(),
		}
		payloadJSON, _ := json.Marshal(payload)

		outMsg := &transport.Message{
			Version: transport.ProtocolVersion,
			Type:    transport.MessagePostureReport,
			ID:      fmt.Sprintf("multi-%d", i),
			TS:      time.Now().UnixMilli(),
			Payload: payloadJSON,
		}

		if err := client.Send(outMsg); err != nil {
			t.Fatalf("Message %d: send failed: %v", i, err)
		}

		inMsg, err := client.Recv()
		if err != nil {
			t.Fatalf("Message %d: recv failed: %v", i, err)
		}

		if inMsg.Type != outMsg.Type {
			t.Fatalf("Message %d: type mismatch", i)
		}
	}

	elapsed := time.Since(start)
	msgPerSec := float64(messageCount) / elapsed.Seconds()
	t.Logf("Exchanged %d messages in %v (%.1f msg/sec)", messageCount, elapsed, msgPerSec)
}

// TestDPU_LargeMessage tests sending messages near the size limit.
func TestDPU_LargeMessage(t *testing.T) {
	skipUnlessWorkbench(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const maxMsgSize = 8192
	_, _, serverName := getTestConfig(t)

	// Setup
	if err := syncCodeToDPU(ctx, t); err != nil {
		t.Fatalf("Failed to sync code: %v", err)
	}
	if err := buildTestBinaryOnDPU(ctx, t); err != nil {
		t.Fatalf("Failed to build test binary: %v", err)
	}

	// Start server on DPU
	cleanup, err := startEchoServerOnDPU(ctx, t, serverName, maxMsgSize, 1)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cleanup()

	// Run client locally
	t.Log("Connecting client...")

	clientCfg := transport.DOCAComchClientConfig{
		PCIAddr:    defaultHostPCIAddr,
		ServerName: serverName,
		MaxMsgSize: maxMsgSize,
	}

	client, err := transport.NewDOCAComchClient(clientCfg)
	if err != nil {
		if err == transport.ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connectCancel()

	if err := client.Connect(connectCtx); err != nil {
		t.Fatalf("Client connect failed: %v", err)
	}

	// Create a large payload (6KB of data to leave room for envelope)
	largeData := make([]byte, 6000)
	for i := range largeData {
		largeData[i] = byte('A' + (i % 26))
	}
	payloadJSON, _ := json.Marshal(map[string]string{"data": string(largeData)})

	outMsg := &transport.Message{
		Version: transport.ProtocolVersion,
		Type:    transport.MessageCredentialPush,
		ID:      "large-msg-test",
		TS:      time.Now().UnixMilli(),
		Payload: payloadJSON,
	}

	t.Logf("Sending large message (%d bytes)...", len(payloadJSON))
	if err := client.Send(outMsg); err != nil {
		t.Fatalf("Send large message failed: %v", err)
	}

	inMsg, err := client.Recv()
	if err != nil {
		t.Fatalf("Recv large message failed: %v", err)
	}

	if len(inMsg.Payload) != len(outMsg.Payload) {
		t.Errorf("Payload size mismatch: got %d, want %d", len(inMsg.Payload), len(outMsg.Payload))
	}

	t.Logf("Large message test passed: %d bytes", len(payloadJSON))
}

// TestDPU_ReconnectAfterDisconnect tests reconnection behavior.
func TestDPU_ReconnectAfterDisconnect(t *testing.T) {
	skipUnlessWorkbench(t)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	_, _, serverName := getTestConfig(t)

	// Setup
	if err := syncCodeToDPU(ctx, t); err != nil {
		t.Fatalf("Failed to sync code: %v", err)
	}
	if err := buildTestBinaryOnDPU(ctx, t); err != nil {
		t.Fatalf("Failed to build test binary: %v", err)
	}

	// Test multiple connections
	for i := 0; i < 3; i++ {
		t.Logf("Connection attempt %d/3...", i+1)

		// Start fresh server for each connection
		cleanup, err := startEchoServerOnDPU(ctx, t, serverName, 4096, 1)
		if err != nil {
			t.Fatalf("Connection %d: failed to start server: %v", i, err)
		}

		// Create client
		clientCfg := transport.DOCAComchClientConfig{
			PCIAddr:    defaultHostPCIAddr,
			ServerName: serverName,
			MaxMsgSize: 4096,
		}

		client, err := transport.NewDOCAComchClient(clientCfg)
		if err != nil {
			cleanup()
			if err == transport.ErrDOCANotAvailable {
				t.Skip("DOCA SDK not available in this build")
			}
			t.Fatalf("Connection %d: failed to create client: %v", i, err)
		}

		connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
		if err := client.Connect(connectCtx); err != nil {
			connectCancel()
			client.Close()
			cleanup()
			t.Fatalf("Connection %d: connect failed: %v", i, err)
		}
		connectCancel()

		// Send and receive
		msg := &transport.Message{
			Version: transport.ProtocolVersion,
			Type:    transport.MessagePostureReport,
			ID:      fmt.Sprintf("reconnect-test-%d", i),
			TS:      time.Now().UnixMilli(),
			Payload: json.RawMessage(fmt.Sprintf(`{"iter":%d}`, i)),
		}

		if err := client.Send(msg); err != nil {
			client.Close()
			cleanup()
			t.Fatalf("Connection %d: send failed: %v", i, err)
		}

		_, err = client.Recv()
		client.Close()
		cleanup()

		if err != nil {
			t.Fatalf("Connection %d: recv failed: %v", i, err)
		}

		t.Logf("Connection %d: success", i+1)
		time.Sleep(500 * time.Millisecond) // Brief pause between reconnects
	}

	t.Log("Reconnect test passed (3 consecutive connections)")
}

// TestDPU_ClientTimeout tests that client connection properly times out.
func TestDPU_ClientTimeout(t *testing.T) {
	skipUnlessWorkbench(t)

	// This test doesn't need a server - it tests timeout when no server exists

	clientCfg := transport.DOCAComchClientConfig{
		PCIAddr:    defaultHostPCIAddr,
		ServerName: "nonexistent-server-" + time.Now().Format("20060102150405"),
		MaxMsgSize: 4096,
	}

	client, err := transport.NewDOCAComchClient(clientCfg)
	if err != nil {
		if err == transport.ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err = client.Connect(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected connection to fail/timeout")
	}

	t.Logf("Connection failed as expected after %v: %v", elapsed, err)

	// Should complete within context timeout (plus some margin)
	if elapsed > 5*time.Second {
		t.Errorf("Timeout took too long: %v", elapsed)
	}
}

// TestDPU_DeviceSelection tests automatic device selection.
func TestDPU_DeviceSelection(t *testing.T) {
	if isRunningOnWorkbench() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		t.Log("Running device selection test on DPU via SSH...")

		if err := syncCodeToDPU(ctx, t); err != nil {
			t.Fatalf("Failed to sync code: %v", err)
		}

		cmd := fmt.Sprintf("cd %s && %s test -tags=dpu,doca -run=TestDPU_DeviceSelection -v ./test/dpu/... 2>&1 || true",
			dpuRepoPath, dpuGoPath)
		out, _ := dpuSSH(ctx, t, cmd)

		if strings.Contains(out, "PASS") {
			t.Log("Device selection test passed on DPU")
		} else if strings.Contains(out, "SKIP") {
			t.Skip("Device selection test skipped on DPU")
		} else {
			t.Logf("Output:\n%s", out)
			if strings.Contains(out, "FAIL") {
				t.Fatal("Device selection test failed on DPU")
			}
		}
		return
	}

	// Running directly on DPU
	if !isBlueFieldEnvironment() {
		t.Skip("requires BlueField hardware: no DOCA indicators found")
	}

	cfg := transport.DefaultDeviceSelectionConfig()
	cfg.RequireClient = true

	device, err := transport.SelectDevice(cfg)
	if err != nil {
		if err == transport.ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("Device selection failed: %v", err)
	}

	t.Logf("Selected device: PCI=%s, IBDev=%s", device.PCIAddr, device.IbdevName)

	if !device.IsComchClient {
		t.Error("Selected device does not support ComCh client")
	}
}
