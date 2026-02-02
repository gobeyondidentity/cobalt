//go:build hardware

// Hardware integration tests for DOCA ComCh.
// Requires real BlueField hardware. Intended for CI nightly builds.
// Run with: go test -tags=hardware ./pkg/transport/... -v
package transport

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

// Environment variables for hardware test configuration
const (
	envDOCAPCIAddr    = "DOCA_PCI_ADDR"     // PCI address of device (e.g., "03:00.0")
	envDOCARepPCIAddr = "DOCA_REP_PCI_ADDR" // Representor PCI address (e.g., "01:00.0")
	envDOCAServerName = "DOCA_SERVER_NAME"  // Server name (default: "secureinfra-test")
)

// Default server name for tests
const defaultTestServerName = "secureinfra-test"

// Hardware detection paths
var blueFieldIndicators = []string{
	"/dev/infiniband",
	"/opt/mellanox/doca",
	"/sys/class/infiniband",
}

// isBlueFieldEnvironment checks if we're running on a system with BlueField hardware.
// Returns true if DOCA indicators are present (device files, SDK installation).
func isBlueFieldEnvironment() bool {
	for _, path := range blueFieldIndicators {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// skipIfNoHardware skips the test if BlueField hardware is not available.
func skipIfNoHardware(t *testing.T) {
	t.Helper()
	if !isBlueFieldEnvironment() {
		t.Skip("requires BlueField hardware: no DOCA indicators found")
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

// TestHardware_EnvironmentDetection verifies that the hardware detection logic works.
func TestHardware_EnvironmentDetection(t *testing.T) {
	if isBlueFieldEnvironment() {
		t.Log("BlueField environment detected")
		for _, path := range blueFieldIndicators {
			if _, err := os.Stat(path); err == nil {
				t.Logf("  Found: %s", path)
			}
		}
	} else {
		t.Skip("No BlueField hardware detected")
	}
}

// TestHardware_DeviceDiscovery tests real device enumeration on BlueField hardware.
func TestHardware_DeviceDiscovery(t *testing.T) {
	skipIfNoHardware(t)

	devices, err := DiscoverDOCADevices()
	if err != nil {
		// Expected error on non-DOCA builds
		if err == ErrDOCANotAvailable {
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

	// Verify at least one device supports ComCh
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

// TestHardware_DeviceSelection tests automatic device selection.
func TestHardware_DeviceSelection(t *testing.T) {
	skipIfNoHardware(t)

	cfg := DefaultDeviceSelectionConfig()
	cfg.RequireClient = true

	device, err := SelectDevice(cfg)
	if err != nil {
		if err == ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("device selection failed: %v", err)
	}

	t.Logf("Selected device: PCI=%s, IBDev=%s", device.PCIAddr, device.IbdevName)

	if !device.IsComchClient {
		t.Error("selected device does not support ComCh client")
	}
}

// TestHardware_ComchServerStarts tests that ComCh server initializes successfully.
func TestHardware_ComchServerStarts(t *testing.T) {
	skipIfNoHardware(t)

	pciAddr, repPCIAddr, serverName := getTestConfig(t)
	if pciAddr == "" || repPCIAddr == "" {
		t.Skipf("requires %s and %s environment variables", envDOCAPCIAddr, envDOCARepPCIAddr)
	}

	cfg := DOCAComchServerConfig{
		PCIAddr:    pciAddr,
		RepPCIAddr: repPCIAddr,
		ServerName: serverName,
		MaxMsgSize: 4096,
	}

	server, err := NewDOCAComchServer(cfg)
	if err != nil {
		if err == ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	t.Logf("ComCh server started: name=%s, pci=%s, rep=%s",
		serverName, pciAddr, repPCIAddr)

	if server.Type() != TransportDOCAComch {
		t.Errorf("wrong transport type: got %v, want %v", server.Type(), TransportDOCAComch)
	}
}

// TestHardware_ComchClientConnects tests that ComCh client can connect.
// This test requires a server to be running on the DPU side.
func TestHardware_ComchClientConnects(t *testing.T) {
	skipIfNoHardware(t)

	pciAddr, _, serverName := getTestConfig(t)
	if pciAddr == "" {
		// Try auto-discovery
		cfg := DefaultDeviceSelectionConfig()
		cfg.RequireClient = true
		device, err := SelectDevice(cfg)
		if err != nil {
			t.Skipf("requires %s or discoverable ComCh client device", envDOCAPCIAddr)
		}
		pciAddr = device.PCIAddr
	}

	cfg := DOCAComchClientConfig{
		PCIAddr:    pciAddr,
		ServerName: serverName,
		MaxMsgSize: 4096,
	}

	client, err := NewDOCAComchClient(cfg)
	if err != nil {
		if err == ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		// Connection failure is expected if no server is running
		t.Logf("Connect failed (expected if no server running): %v", err)
		t.Skip("no ComCh server available to connect to")
	}

	t.Logf("ComCh client connected: pci=%s, server=%s", pciAddr, serverName)

	if client.State() != "connected" {
		t.Errorf("unexpected state: got %s, want connected", client.State())
	}
}

// TestHardware_MessageRoundTrip tests sending and receiving a message.
// This test requires both server and client to be available.
func TestHardware_MessageRoundTrip(t *testing.T) {
	skipIfNoHardware(t)

	pciAddr, repPCIAddr, serverName := getTestConfig(t)
	if pciAddr == "" || repPCIAddr == "" {
		t.Skipf("requires %s and %s environment variables", envDOCAPCIAddr, envDOCARepPCIAddr)
	}

	// Start server
	serverCfg := DOCAComchServerConfig{
		PCIAddr:    pciAddr,
		RepPCIAddr: repPCIAddr,
		ServerName: serverName,
		MaxMsgSize: 4096,
	}

	server, err := NewDOCAComchServer(serverCfg)
	if err != nil {
		if err == ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	// Track received messages
	var wg sync.WaitGroup
	var receivedMsg *Message
	var recvErr error

	// Server goroutine: accept connection and echo
	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := server.Accept()
		if err != nil {
			recvErr = err
			return
		}
		defer conn.Close()

		// Receive message
		receivedMsg, recvErr = conn.Recv()
		if recvErr != nil {
			return
		}

		// Echo it back
		recvErr = conn.Send(receivedMsg)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create and connect client
	clientCfg := DOCAComchClientConfig{
		PCIAddr:    pciAddr,
		ServerName: serverName,
		MaxMsgSize: 4096,
	}

	client, err := NewDOCAComchClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("client connect failed: %v", err)
	}

	// Send test message
	testPayload := map[string]string{"test": "hardware", "time": time.Now().Format(time.RFC3339)}
	payloadJSON, _ := json.Marshal(testPayload)

	outMsg := &Message{
		Version: ProtocolVersion,
		Type:    MessageEnrollRequest,
		ID:      "hw-test-001",
		TS:      time.Now().UnixMilli(),
		Payload: payloadJSON,
	}

	if err := client.Send(outMsg); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// Receive echo
	inMsg, err := client.Recv()
	if err != nil {
		t.Fatalf("recv failed: %v", err)
	}

	// Wait for server goroutine
	wg.Wait()

	if recvErr != nil {
		t.Fatalf("server error: %v", recvErr)
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

// TestHardware_ReconnectAfterDisconnect tests reconnection behavior.
func TestHardware_ReconnectAfterDisconnect(t *testing.T) {
	skipIfNoHardware(t)

	pciAddr, repPCIAddr, serverName := getTestConfig(t)
	if pciAddr == "" || repPCIAddr == "" {
		t.Skipf("requires %s and %s environment variables", envDOCAPCIAddr, envDOCARepPCIAddr)
	}

	// Start server
	serverCfg := DOCAComchServerConfig{
		PCIAddr:    pciAddr,
		RepPCIAddr: repPCIAddr,
		ServerName: serverName,
		MaxMsgSize: 4096,
	}

	server, err := NewDOCAComchServer(serverCfg)
	if err != nil {
		if err == ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	// Server goroutine: accept connections in loop
	serverDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-serverDone:
				return
			default:
			}

			conn, err := server.Accept()
			if err != nil {
				return
			}

			// Echo one message then close
			msg, err := conn.Recv()
			if err == nil {
				conn.Send(msg)
			}
			conn.Close()
		}
	}()
	defer close(serverDone)

	time.Sleep(100 * time.Millisecond)

	// Test multiple connections
	for i := 0; i < 3; i++ {
		clientCfg := DOCAComchClientConfig{
			PCIAddr:    pciAddr,
			ServerName: serverName,
			MaxMsgSize: 4096,
		}

		client, err := NewDOCAComchClient(clientCfg)
		if err != nil {
			t.Fatalf("connection %d: failed to create client: %v", i, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := client.Connect(ctx); err != nil {
			cancel()
			client.Close()
			t.Fatalf("connection %d: connect failed: %v", i, err)
		}

		// Send and receive
		msg := &Message{
			Version: ProtocolVersion,
			Type:    MessagePostureReport,
			ID:      "reconnect-test",
			TS:      time.Now().UnixMilli(),
			Payload: json.RawMessage(`{"iter":` + string(rune('0'+i)) + `}`),
		}

		if err := client.Send(msg); err != nil {
			cancel()
			client.Close()
			t.Fatalf("connection %d: send failed: %v", i, err)
		}

		_, err = client.Recv()
		cancel()
		client.Close()

		if err != nil {
			t.Fatalf("connection %d: recv failed: %v", i, err)
		}

		t.Logf("Connection %d: success", i+1)
		time.Sleep(100 * time.Millisecond) // Brief pause between reconnects
	}

	t.Log("Reconnect test passed (3 consecutive connections)")
}

// TestHardware_MultipleMessages tests exchanging multiple messages in sequence.
func TestHardware_MultipleMessages(t *testing.T) {
	skipIfNoHardware(t)

	pciAddr, repPCIAddr, serverName := getTestConfig(t)
	if pciAddr == "" || repPCIAddr == "" {
		t.Skipf("requires %s and %s environment variables", envDOCAPCIAddr, envDOCARepPCIAddr)
	}

	const messageCount = 100

	// Start server
	serverCfg := DOCAComchServerConfig{
		PCIAddr:        pciAddr,
		RepPCIAddr:     repPCIAddr,
		ServerName:     serverName,
		MaxMsgSize:     4096,
		RecvBufferSize: 64,
	}

	server, err := NewDOCAComchServer(serverCfg)
	if err != nil {
		if err == ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	var serverErr error
	serverDone := make(chan struct{})

	// Server goroutine: echo all messages
	go func() {
		defer close(serverDone)

		conn, err := server.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer conn.Close()

		for i := 0; i < messageCount; i++ {
			msg, err := conn.Recv()
			if err != nil {
				serverErr = err
				return
			}

			if err := conn.Send(msg); err != nil {
				serverErr = err
				return
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Create client
	clientCfg := DOCAComchClientConfig{
		PCIAddr:        pciAddr,
		ServerName:     serverName,
		MaxMsgSize:     4096,
		RecvBufferSize: 64,
	}

	client, err := NewDOCAComchClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	// Send and receive messages
	start := time.Now()
	for i := 0; i < messageCount; i++ {
		payload := map[string]interface{}{
			"seq":   i,
			"data":  "test message payload",
			"nonce": time.Now().UnixNano(),
		}
		payloadJSON, _ := json.Marshal(payload)

		outMsg := &Message{
			Version: ProtocolVersion,
			Type:    MessagePostureReport,
			ID:      "multi-" + string(rune('0'+i%10)),
			TS:      time.Now().UnixMilli(),
			Payload: payloadJSON,
		}

		if err := client.Send(outMsg); err != nil {
			t.Fatalf("message %d: send failed: %v", i, err)
		}

		inMsg, err := client.Recv()
		if err != nil {
			t.Fatalf("message %d: recv failed: %v", i, err)
		}

		if inMsg.Type != outMsg.Type {
			t.Fatalf("message %d: type mismatch", i)
		}
	}

	elapsed := time.Since(start)
	<-serverDone

	if serverErr != nil {
		t.Fatalf("server error: %v", serverErr)
	}

	msgPerSec := float64(messageCount) / elapsed.Seconds()
	t.Logf("Exchanged %d messages in %v (%.1f msg/sec)", messageCount, elapsed, msgPerSec)
}

// TestHardware_LargeMessage tests sending messages near the size limit.
func TestHardware_LargeMessage(t *testing.T) {
	skipIfNoHardware(t)

	pciAddr, repPCIAddr, serverName := getTestConfig(t)
	if pciAddr == "" || repPCIAddr == "" {
		t.Skipf("requires %s and %s environment variables", envDOCAPCIAddr, envDOCARepPCIAddr)
	}

	// Start server
	serverCfg := DOCAComchServerConfig{
		PCIAddr:    pciAddr,
		RepPCIAddr: repPCIAddr,
		ServerName: serverName,
		MaxMsgSize: 8192, // 8KB
	}

	server, err := NewDOCAComchServer(serverCfg)
	if err != nil {
		if err == ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	var serverErr error
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		conn, err := server.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer conn.Close()

		msg, err := conn.Recv()
		if err != nil {
			serverErr = err
			return
		}
		serverErr = conn.Send(msg)
	}()

	time.Sleep(100 * time.Millisecond)

	// Create client
	clientCfg := DOCAComchClientConfig{
		PCIAddr:    pciAddr,
		ServerName: serverName,
		MaxMsgSize: 8192,
	}

	client, err := NewDOCAComchClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	// Create a large payload (6KB of data to leave room for envelope)
	largeData := make([]byte, 6000)
	for i := range largeData {
		largeData[i] = byte('A' + (i % 26))
	}
	payloadJSON, _ := json.Marshal(map[string]string{"data": string(largeData)})

	outMsg := &Message{
		Version: ProtocolVersion,
		Type:    MessageCredentialPush,
		ID:      "large-msg-test",
		TS:      time.Now().UnixMilli(),
		Payload: payloadJSON,
	}

	if err := client.Send(outMsg); err != nil {
		t.Fatalf("send large message failed: %v", err)
	}

	inMsg, err := client.Recv()
	if err != nil {
		t.Fatalf("recv large message failed: %v", err)
	}

	<-serverDone
	if serverErr != nil {
		t.Fatalf("server error: %v", serverErr)
	}

	if len(inMsg.Payload) != len(outMsg.Payload) {
		t.Errorf("payload size mismatch: got %d, want %d", len(inMsg.Payload), len(outMsg.Payload))
	}

	t.Logf("Large message test passed: %d bytes", len(payloadJSON))
}

// TestHardware_ClientTimeout tests that client connection properly times out.
func TestHardware_ClientTimeout(t *testing.T) {
	skipIfNoHardware(t)

	pciAddr, _, _ := getTestConfig(t)
	if pciAddr == "" {
		cfg := DefaultDeviceSelectionConfig()
		cfg.RequireClient = true
		device, err := SelectDevice(cfg)
		if err != nil {
			t.Skipf("requires %s or discoverable ComCh client device", envDOCAPCIAddr)
		}
		pciAddr = device.PCIAddr
	}

	// Connect to a non-existent server name (should timeout)
	clientCfg := DOCAComchClientConfig{
		PCIAddr:    pciAddr,
		ServerName: "nonexistent-server-" + time.Now().Format("20060102150405"),
		MaxMsgSize: 4096,
	}

	client, err := NewDOCAComchClient(clientCfg)
	if err != nil {
		if err == ErrDOCANotAvailable {
			t.Skip("DOCA SDK not available in this build")
		}
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err = client.Connect(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected connection to fail/timeout")
	}

	t.Logf("Connection failed as expected after %v: %v", elapsed, err)

	// Should complete within context timeout (plus some margin)
	if elapsed > 5*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

// BenchmarkHardware_MessageRoundTrip benchmarks message exchange on real hardware.
func BenchmarkHardware_MessageRoundTrip(b *testing.B) {
	if !isBlueFieldEnvironment() {
		b.Skip("requires BlueField hardware")
	}

	pciAddr := os.Getenv(envDOCAPCIAddr)
	repPCIAddr := os.Getenv(envDOCARepPCIAddr)
	serverName := os.Getenv(envDOCAServerName)
	if serverName == "" {
		serverName = defaultTestServerName
	}

	if pciAddr == "" || repPCIAddr == "" {
		b.Skipf("requires %s and %s environment variables", envDOCAPCIAddr, envDOCARepPCIAddr)
	}

	// Start server
	serverCfg := DOCAComchServerConfig{
		PCIAddr:    pciAddr,
		RepPCIAddr: repPCIAddr,
		ServerName: serverName,
		MaxMsgSize: 4096,
	}

	server, err := NewDOCAComchServer(serverCfg)
	if err != nil {
		b.Skipf("failed to create server: %v", err)
	}
	defer server.Close()

	// Server echo loop
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := server.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			msg, err := conn.Recv()
			if err != nil {
				return
			}
			if err := conn.Send(msg); err != nil {
				return
			}
		}
	}()

	// Create client
	clientCfg := DOCAComchClientConfig{
		PCIAddr:    pciAddr,
		ServerName: serverName,
		MaxMsgSize: 4096,
	}

	client, err := NewDOCAComchClient(clientCfg)
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		b.Fatalf("connect failed: %v", err)
	}

	// Prepare test message
	msg := &Message{
		Version: ProtocolVersion,
		Type:    MessagePostureReport,
		ID:      "bench-test",
		TS:      time.Now().UnixMilli(),
		Payload: json.RawMessage(`{"benchmark":true,"data":"test payload for benchmarking"}`),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := client.Send(msg); err != nil {
			b.Fatalf("send failed: %v", err)
		}
		if _, err := client.Recv(); err != nil {
			b.Fatalf("recv failed: %v", err)
		}
	}

	b.StopTimer()
	client.Close()
	<-serverDone
}
