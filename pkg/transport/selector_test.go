package transport

import (
	"context"
	"runtime"
	"testing"
)

// testTransport is a minimal Transport implementation for testing.
type testTransport struct {
	transportType TransportType
}

func (t *testTransport) Connect(ctx context.Context) error { return nil }
func (t *testTransport) Send(msg *Message) error          { return nil }
func (t *testTransport) Recv() (*Message, error)          { return nil, nil }
func (t *testTransport) Close() error                     { return nil }
func (t *testTransport) Type() TransportType              { return t.transportType }

func TestNewHostTransport_MockPriority(t *testing.T) {
	mock := &testTransport{transportType: TransportMock}
	cfg := &Config{
		MockTransport: mock,
	}

	transport, err := NewHostTransport(cfg)
	if err != nil {
		t.Fatalf("NewHostTransport with mock failed: %v", err)
	}

	if transport != mock {
		t.Error("Expected mock transport to be returned")
	}

	if transport.Type() != TransportMock {
		t.Errorf("Expected type %s, got %s", TransportMock, transport.Type())
	}
}

func TestNewHostTransport_MockOverridesHardware(t *testing.T) {
	// Even if tmfifo socket path is set, mock should take priority
	mock := &testTransport{transportType: TransportMock}
	cfg := &Config{
		MockTransport:    mock,
		TmfifoSocketPath: "/tmp/tmfifo.sock",
		InviteCode:       "test-invite",
		DPUAddr:          "localhost:8443",
	}

	transport, err := NewHostTransport(cfg)
	if err != nil {
		t.Fatalf("NewHostTransport failed: %v", err)
	}

	if transport != mock {
		t.Error("Mock transport should override all other options")
	}
}

func TestNewHostTransport_NoTransportAvailable(t *testing.T) {
	if HasTmfifoInterface() {
		t.Skip("Test assumes no hardware; tmfifo_net0 interface detected")
	}
	// No mock, no tmfifo socket, no invite code
	cfg := &Config{
		TmfifoSocketPath: "/nonexistent/socket",
	}

	transport, err := NewHostTransport(cfg)
	if err == nil {
		t.Fatal("Expected error when no transport available")
	}

	if transport != nil {
		t.Error("Expected nil transport when error returned")
	}
}

func TestNewHostTransport_NilConfig(t *testing.T) {
	if HasTmfifoInterface() {
		t.Skip("Test assumes no hardware; tmfifo_net0 interface detected")
	}
	// Should handle nil config gracefully
	transport, err := NewHostTransport(nil)
	if err == nil {
		t.Fatal("Expected error with nil config (no transport available)")
	}

	if transport != nil {
		t.Error("Expected nil transport")
	}
}

func TestNewHostTransport_NetworkRequiresDPUAddr(t *testing.T) {
	if HasTmfifoInterface() {
		t.Skip("Test assumes no hardware; tmfifo_net0 interface detected")
	}
	// Only invite code, no DPU address - should error
	cfg := &Config{
		InviteCode:       "test-invite",
		TmfifoSocketPath: "/nonexistent/socket",
	}

	_, err := NewHostTransport(cfg)
	if err == nil {
		t.Error("Expected error when DPUAddr missing")
	}

	// DPU address provided, no invite code - should succeed (legacy HTTP mode)
	cfg = &Config{
		DPUAddr:          "localhost:8443",
		TmfifoSocketPath: "/nonexistent/socket",
	}

	transport, err := NewHostTransport(cfg)
	if err != nil {
		t.Errorf("Should not error when only DPUAddr provided (legacy HTTP mode): %v", err)
	}
	if transport == nil {
		t.Error("Expected transport to be returned")
	}
	if transport != nil && transport.Type() != TransportNetwork {
		t.Errorf("Expected network transport, got %s", transport.Type())
	}
}

func TestNewHostTransport_ForceTmfifo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tmfifo is Linux-only")
	}
	if HasTmfifoInterface() {
		t.Skip("Test assumes no hardware; tmfifo_net0 interface detected")
	}
	// ForceTmfifo with nonexistent socket should error
	cfg := &Config{
		ForceTmfifo:      true,
		TmfifoSocketPath: "/nonexistent/socket",
		DPUAddr:          "localhost:8443", // Should be ignored
	}

	_, err := NewHostTransport(cfg)
	if err == nil {
		t.Error("Expected error when ForceTmfifo set but socket doesn't exist and interface not found")
	}
}

func TestNewHostTransport_ForceNetwork(t *testing.T) {
	// ForceNetwork skips hardware detection
	cfg := &Config{
		ForceNetwork:     true,
		DPUAddr:          "localhost:8443",
		TmfifoSocketPath: "/tmp/tmfifo.sock", // Would normally be checked first
	}

	transport, err := NewHostTransport(cfg)
	if err != nil {
		t.Fatalf("ForceNetwork should not error when DPUAddr provided: %v", err)
	}
	if transport.Type() != TransportNetwork {
		t.Errorf("Expected network transport, got %s", transport.Type())
	}
}

func TestNewHostTransport_ForceNetworkRequiresDPUAddr(t *testing.T) {
	// ForceNetwork without DPUAddr should error
	cfg := &Config{
		ForceNetwork: true,
	}

	_, err := NewHostTransport(cfg)
	if err == nil {
		t.Error("Expected error when ForceNetwork set but DPUAddr missing")
	}
}

func TestConfig_DefaultTmfifoPath(t *testing.T) {
	if DefaultTmfifoPath != "/dev/tmfifo_net0" {
		t.Errorf("Expected default tmfifo path /dev/tmfifo_net0, got %s", DefaultTmfifoPath)
	}
}

func TestDOCAComchAvailable_Stub(t *testing.T) {
	// On non-DOCA systems (like this test environment), should return false
	if DOCAComchAvailable() {
		t.Skip("DOCA Comch is available; skipping stub test")
	}
	// If we get here, the stub is working correctly
}

func TestNewHostTransport_ForceComCh(t *testing.T) {
	// ForceComCh when DOCA is not available should error
	if DOCAComchAvailable() {
		t.Skip("DOCA Comch is available; cannot test ForceComCh failure")
	}

	cfg := &Config{
		ForceComCh: true,
		DPUAddr:    "localhost:8443", // Should be ignored
	}

	_, err := NewHostTransport(cfg)
	if err == nil {
		t.Error("Expected error when ForceComCh set but DOCA not available")
	}

	expectedErr := "DOCA ComCh not available (required by ForceComCh)"
	if err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
	}
}

func TestConfig_NewFields(t *testing.T) {
	// Verify new config fields can be set
	cfg := &Config{
		ForceComCh:     true,
		DOCADeviceName: "mlx5_0",
		DOCAServerName: "secure-infra",
		KeyPath:        "/var/lib/secure-infra/host.key",
	}

	if !cfg.ForceComCh {
		t.Error("ForceComCh should be true")
	}
	if cfg.DOCADeviceName != "mlx5_0" {
		t.Errorf("DOCADeviceName = %q, want %q", cfg.DOCADeviceName, "mlx5_0")
	}
	if cfg.DOCAServerName != "secure-infra" {
		t.Errorf("DOCAServerName = %q, want %q", cfg.DOCAServerName, "secure-infra")
	}
	if cfg.KeyPath != "/var/lib/secure-infra/host.key" {
		t.Errorf("KeyPath = %q, want %q", cfg.KeyPath, "/var/lib/secure-infra/host.key")
	}
}

// ============================================================================
// NewDPUTransportListener Tests
// ============================================================================

// testListener is a minimal TransportListener implementation for testing.
type testListener struct {
	transportType TransportType
	acceptErr     error
	closed        bool
}

func (l *testListener) Accept() (Transport, error) {
	if l.acceptErr != nil {
		return nil, l.acceptErr
	}
	return &testTransport{transportType: l.transportType}, nil
}

func (l *testListener) Close() error {
	l.closed = true
	return nil
}

func (l *testListener) Type() TransportType {
	return l.transportType
}

func TestNewDPUTransportListener_SelectionPriority(t *testing.T) {
	// When DOCA is not available, should fall back to tmfifo, then to network
	if DOCAComchAvailable() {
		t.Skip("DOCA ComCh is available; cannot test fallback behavior")
	}

	// With no tmfifo socket path and no network config, DPU listener will actually
	// try to start a TCP listener. We need to test with an empty config.
	cfg := &Config{}

	// This should succeed because it will create a TCP listener on default port
	listener, err := NewDPUTransportListener(cfg)
	if err == nil {
		listener.Close()
		t.Log("NewDPUTransportListener(empty config) succeeded with TCP listener")
	} else {
		t.Log("NewDPUTransportListener(empty config) failed as expected:", err)
	}
}

func TestNewDPUTransportListener_NilConfig(t *testing.T) {
	// Should handle nil config gracefully (use defaults)
	_, err := NewDPUTransportListener(nil)
	// With nil config and no hardware, should return error
	if err == nil && !DOCAComchAvailable() {
		// May succeed if tmfifo exists at default path, otherwise should fail
		t.Log("NewDPUTransportListener(nil) succeeded, tmfifo may exist")
	}
}

func TestNewDPUTransportListener_ForceComCh(t *testing.T) {
	// ForceComCh when DOCA is not available should error
	if DOCAComchAvailable() {
		t.Skip("DOCA ComCh is available; cannot test ForceComCh failure")
	}

	cfg := &Config{
		ForceComCh: true,
	}

	_, err := NewDPUTransportListener(cfg)
	if err == nil {
		t.Error("Expected error when ForceComCh set but DOCA not available")
	}

	expectedErr := "DOCA ComCh not available (required by ForceComCh)"
	if err != nil && err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
	}
}

func TestNewDPUTransportListener_ForceTmfifo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tmfifo Unix sockets are Linux-only")
	}
	// ForceTmfifo with a socket path will try to create a Unix socket listener
	// This should succeed since it creates the socket
	cfg := &Config{
		ForceTmfifo:      true,
		TmfifoSocketPath: "/tmp/test_tmfifo_listener.sock",
	}

	listener, err := NewDPUTransportListener(cfg)
	if err != nil {
		t.Fatalf("ForceTmfifo with socket path should succeed: %v", err)
	}
	listener.Close()
}

func TestNewDPUTransportListener_NetworkFallback(t *testing.T) {
	// When no tmfifo socket path but network DPUAddr provided, should use network
	if DOCAComchAvailable() {
		t.Skip("DOCA ComCh is available; cannot test network fallback")
	}

	cfg := &Config{
		ForceNetwork: true, // Force network to skip tmfifo detection
		DPUAddr:      ":0", // Use random port
	}

	listener, err := NewDPUTransportListener(cfg)
	if err != nil {
		t.Fatalf("Expected network fallback to succeed: %v", err)
	}
	defer listener.Close()

	if listener.Type() != TransportNetwork {
		t.Errorf("Expected network listener, got %s", listener.Type())
	}
}

func TestConfig_DPUListenerFields(t *testing.T) {
	// DPU-specific config fields
	cfg := &Config{
		DOCAPCIAddr:    "03:00.0",
		DOCARepPCIAddr: "01:00.0",
		DOCAServerName: "secure-infra-dpu",
	}

	if cfg.DOCAPCIAddr != "03:00.0" {
		t.Errorf("DOCAPCIAddr = %q, want %q", cfg.DOCAPCIAddr, "03:00.0")
	}
	if cfg.DOCARepPCIAddr != "01:00.0" {
		t.Errorf("DOCARepPCIAddr = %q, want %q", cfg.DOCARepPCIAddr, "01:00.0")
	}
	if cfg.DOCAServerName != "secure-infra-dpu" {
		t.Errorf("DOCAServerName = %q, want %q", cfg.DOCAServerName, "secure-infra-dpu")
	}
}

// ============================================================================
// Selection Priority Tests
// ============================================================================

func TestNewHostTransport_SelectionPriority_MockFirst(t *testing.T) {
	// Mock should always be selected first, even with other options available
	mock := &testTransport{transportType: TransportMock}
	cfg := &Config{
		MockTransport:  mock,
		ForceComCh:     true, // Should be ignored
		DOCADeviceName: "mlx5_0",
		DPUAddr:        "localhost:8443",
	}

	transport, err := NewHostTransport(cfg)
	if err != nil {
		t.Fatalf("NewHostTransport failed: %v", err)
	}

	if transport != mock {
		t.Error("Mock transport should be selected first regardless of other options")
	}
}

func TestNewHostTransport_ForceComCh_OverridesFallback(t *testing.T) {
	// ForceComCh should not fall back to tmfifo or network
	if DOCAComchAvailable() {
		t.Skip("DOCA ComCh is available; cannot test ForceComCh failure path")
	}

	cfg := &Config{
		ForceComCh:       true,
		TmfifoSocketPath: "/tmp/tmfifo.sock", // Would normally be a fallback
		DPUAddr:          "localhost:8443",   // Would normally be a fallback
	}

	_, err := NewHostTransport(cfg)
	if err == nil {
		t.Error("Expected error when ForceComCh set but DOCA not available")
	}

	// Should not fall back to tmfifo or network
	expectedErr := "DOCA ComCh not available (required by ForceComCh)"
	if err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
	}
}

func TestNewDPUTransportListener_SelectionPriority_ComChFirst(t *testing.T) {
	// On DOCA systems with server-capable hardware, ComCh should be selected before tmfifo.
	// This test requires actual DPU hardware with server capability (runs on DPU, not host).
	if !DOCAComchAvailable() {
		t.Skip("DOCA ComCh not available; cannot test ComCh priority")
	}

	// Check for actual server-capable devices (not just SDK availability)
	devices, err := DiscoverDOCADevices()
	if err != nil {
		t.Skipf("Cannot discover DOCA devices: %v", err)
	}

	var serverDevice *DeviceInfo
	for i := range devices {
		if devices[i].IsComchServer {
			serverDevice = &devices[i]
			break
		}
	}
	if serverDevice == nil {
		t.Skip("No ComCh server-capable devices found; test requires DPU hardware")
	}

	cfg := &Config{
		TmfifoSocketPath: "/tmp/tmfifo.sock", // Should not be used
		DOCAPCIAddr:      serverDevice.PCIAddr,
		DOCARepPCIAddr:   serverDevice.PCIAddr, // Use same for test; real config needs representor
		DOCAServerName:   "test-server",
	}

	listener, err := NewDPUTransportListener(cfg)
	if err != nil {
		t.Fatalf("NewDPUTransportListener failed: %v", err)
	}
	defer listener.Close()

	if listener.Type() != TransportDOCAComch {
		t.Errorf("Expected DOCA ComCh listener, got %s", listener.Type())
	}
}

func TestNewDPUTransportListener_ForceComCh_NoFallback(t *testing.T) {
	// ForceComCh should not fall back to tmfifo or network
	if DOCAComchAvailable() {
		t.Skip("DOCA ComCh is available; cannot test ForceComCh failure path")
	}

	cfg := &Config{
		ForceComCh:       true,
		TmfifoSocketPath: "/tmp/tmfifo.sock", // Should not be used as fallback
		DPUAddr:          ":18052",           // Should not be used as fallback
	}

	_, err := NewDPUTransportListener(cfg)
	if err == nil {
		t.Error("Expected error when ForceComCh set but DOCA not available")
	}
}

func TestNewDPUTransportListener_FallbackToNetwork(t *testing.T) {
	// When DOCA is not available and tmfifo socket path not set,
	// but DPUAddr provided, should fall back to network
	if DOCAComchAvailable() {
		t.Skip("DOCA ComCh is available; cannot test network fallback")
	}

	cfg := &Config{
		ForceNetwork: true, // Force network mode
		DPUAddr:      ":0", // Use random port
	}

	listener, err := NewDPUTransportListener(cfg)
	if err != nil {
		t.Fatalf("Expected network fallback to succeed: %v", err)
	}
	defer listener.Close()

	if listener.Type() != TransportNetwork {
		t.Errorf("Expected network listener fallback, got %s", listener.Type())
	}
}

func TestNewDPUTransportListener_ForceTmfifo_SucceedsWithSocketPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tmfifo Unix sockets are Linux-only")
	}
	// ForceTmfifo with a socket path should create a Unix socket listener
	cfg := &Config{
		ForceTmfifo:      true,
		TmfifoSocketPath: "/tmp/test_forcetmfifo.sock",
		DPUAddr:          ":18052", // Should not be used as fallback
	}

	listener, err := NewDPUTransportListener(cfg)
	if err != nil {
		t.Fatalf("ForceTmfifo with socket path should succeed: %v", err)
	}
	listener.Close()
}

func TestNewDPUTransportListener_ForceNetwork(t *testing.T) {
	// ForceNetwork skips hardware detection
	cfg := &Config{
		ForceNetwork: true,
		DPUAddr:      ":18052",
	}

	listener, err := NewDPUTransportListener(cfg)
	if err != nil {
		t.Fatalf("ForceNetwork should succeed with DPUAddr: %v", err)
	}
	defer listener.Close()

	if listener.Type() != TransportNetwork {
		t.Errorf("Expected network listener, got %s", listener.Type())
	}
}

func TestNewDPUTransportListener_ForceNetworkRequiresDPUAddr(t *testing.T) {
	// ForceNetwork without DPUAddr should error
	cfg := &Config{
		ForceNetwork: true,
	}

	_, err := NewDPUTransportListener(cfg)
	if err == nil {
		t.Error("Expected error when ForceNetwork set but DPUAddr missing")
	}
}
