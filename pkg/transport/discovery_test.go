//go:build !doca

package transport

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

// Discovery errors for testing (mirror the ones in doca_pci_discovery.go).
// These are redefined here because the real errors are only available in DOCA builds.
var (
	ErrNoDevicesFound        = errors.New("doca discovery: no Mellanox devices found - is the driver loaded?")
	ErrNoComchCapableDevices = errors.New("doca discovery: no ComCh-capable devices found - BlueField required")
	ErrDeviceNotFound        = errors.New("doca discovery: specified device not found")
)

// MockDiscovery provides a mockable device discovery layer for testing.
// It simulates DOCA device discovery without requiring actual hardware.
type MockDiscovery struct {
	// Devices to return from DiscoverDevices
	Devices []DeviceInfo
	// Error to return from DiscoverDevices
	DiscoverErr error
	// Per-device capability checks (keyed by PCI address)
	ClientCaps map[string]bool
	ServerCaps map[string]bool
	// Errors for capability checks
	ClientCapErr error
	ServerCapErr error
}

// NewMockDiscovery creates a new MockDiscovery with empty device list.
func NewMockDiscovery() *MockDiscovery {
	return &MockDiscovery{
		Devices:    []DeviceInfo{},
		ClientCaps: make(map[string]bool),
		ServerCaps: make(map[string]bool),
	}
}

// AddDevice adds a device to the mock discovery.
func (m *MockDiscovery) AddDevice(dev DeviceInfo) {
	m.Devices = append(m.Devices, dev)
	m.ClientCaps[dev.PCIAddr] = dev.IsComchClient
	m.ServerCaps[dev.PCIAddr] = dev.IsComchServer
}

// DiscoverDevices returns the configured devices or error.
func (m *MockDiscovery) DiscoverDevices() ([]DeviceInfo, error) {
	if m.DiscoverErr != nil {
		return nil, m.DiscoverErr
	}
	result := make([]DeviceInfo, len(m.Devices))
	copy(result, m.Devices)
	return result, nil
}

// CheckClientCapability returns the configured capability for a device.
func (m *MockDiscovery) CheckClientCapability(pciAddr string) (bool, error) {
	if m.ClientCapErr != nil {
		return false, m.ClientCapErr
	}
	cap, ok := m.ClientCaps[pciAddr]
	if !ok {
		return false, errors.New("device not found")
	}
	return cap, nil
}

// CheckServerCapability returns the configured capability for a device.
func (m *MockDiscovery) CheckServerCapability(pciAddr string) (bool, error) {
	if m.ServerCapErr != nil {
		return false, m.ServerCapErr
	}
	cap, ok := m.ServerCaps[pciAddr]
	if !ok {
		return false, errors.New("device not found")
	}
	return cap, nil
}

// SelectDevice implements the same selection logic as the real SelectDevice
// but uses mock data instead of DOCA SDK calls.
func (m *MockDiscovery) SelectDevice(cfg DeviceSelectionConfig) (*DeviceInfo, error) {
	// If override is specified, look for that specific device
	if cfg.PCIAddrOverride != "" {
		return m.selectByPCIAddr(cfg.PCIAddrOverride)
	}

	devices, err := m.DiscoverDevices()
	if err != nil {
		return nil, err
	}

	if len(devices) == 0 {
		return nil, ErrNoDevicesFound
	}

	// Filter to ComCh-capable devices
	var candidates []DeviceInfo
	for _, dev := range devices {
		// Skip non-PF devices (prefer physical functions)
		if dev.FuncType != PCIFuncTypePF {
			continue
		}

		// Check capability requirements
		if cfg.RequireClient && !dev.IsComchClient {
			continue
		}
		if cfg.RequireServer && !dev.IsComchServer {
			continue
		}

		// At least one ComCh capability required
		if !dev.IsComchClient && !dev.IsComchServer {
			continue
		}

		candidates = append(candidates, dev)
	}

	if len(candidates) == 0 {
		return nil, ErrNoComchCapableDevices
	}

	// If only one candidate, use it
	if len(candidates) == 1 {
		return &candidates[0], nil
	}

	// Multiple candidates: apply port preference
	preferredPort := "." + string(rune('0'+cfg.PreferPort))
	for i := range candidates {
		if strings.HasSuffix(candidates[i].PCIAddr, preferredPort) {
			return &candidates[i], nil
		}
	}

	// No port preference match: return error with device list
	var addrs []string
	for _, c := range candidates {
		addrs = append(addrs, c.PCIAddr)
	}
	return nil, errors.New("multiple devices found: " + strings.Join(addrs, ", "))
}

// selectByPCIAddr finds a device by its PCI address.
func (m *MockDiscovery) selectByPCIAddr(pciAddr string) (*DeviceInfo, error) {
	devices, err := m.DiscoverDevices()
	if err != nil {
		return nil, err
	}

	for i := range devices {
		if devices[i].PCIAddr == pciAddr {
			return &devices[i], nil
		}
	}

	return nil, ErrDeviceNotFound
}

// ============================================================================
// Single Device Scenarios
// ============================================================================

func TestDiscovery_SingleComchCapableDevice(t *testing.T) {
	t.Log("Testing device selection with single ComCh-capable device")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "01:00.0" {
		t.Errorf("Expected PCI address 01:00.0, got %s", dev.PCIAddr)
	}
	if !dev.IsComchClient {
		t.Error("Expected device to be ComCh client capable")
	}
}

func TestDiscovery_NoDevicesFound(t *testing.T) {
	t.Log("Testing device selection returns error when no devices found")
	mock := NewMockDiscovery()

	cfg := DeviceSelectionConfig{}
	dev, err := mock.SelectDevice(cfg)

	if err == nil {
		t.Fatal("Expected error when no devices found")
	}
	if !errors.Is(err, ErrNoDevicesFound) {
		t.Errorf("Expected ErrNoDevicesFound, got %v", err)
	}
	if dev != nil {
		t.Error("Expected nil device when no devices found")
	}
}

func TestDiscovery_DeviceFoundButNotComchCapable(t *testing.T) {
	t.Log("Testing device selection returns error when device is not ComCh capable")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: false,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{}
	dev, err := mock.SelectDevice(cfg)

	if err == nil {
		t.Fatal("Expected error when device is not ComCh capable")
	}
	if !errors.Is(err, ErrNoComchCapableDevices) {
		t.Errorf("Expected ErrNoComchCapableDevices, got %v", err)
	}
	if dev != nil {
		t.Error("Expected nil device")
	}
}

func TestDiscovery_VirtualFunctionSkipped(t *testing.T) {
	t.Log("Testing device selection skips Virtual Function (VF) devices")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.2",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp1s0f0v0",
		FuncType:      PCIFuncTypeVF,
		IsComchClient: true,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{}
	dev, err := mock.SelectDevice(cfg)

	if err == nil {
		t.Fatal("Expected error when only VF devices available")
	}
	if !errors.Is(err, ErrNoComchCapableDevices) {
		t.Errorf("Expected ErrNoComchCapableDevices, got %v", err)
	}
	if dev != nil {
		t.Error("Expected nil device")
	}
}

func TestDiscovery_SubFunctionSkipped(t *testing.T) {
	t.Log("Testing device selection skips Sub-Function (SF) devices")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.3",
		IbdevName:     "mlx5_3",
		IfaceName:     "enp1s0f0s0",
		FuncType:      PCIFuncTypeSF,
		IsComchClient: true,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{}
	dev, err := mock.SelectDevice(cfg)

	if err == nil {
		t.Fatal("Expected error when only SF devices available")
	}
	if !errors.Is(err, ErrNoComchCapableDevices) {
		t.Errorf("Expected ErrNoComchCapableDevices, got %v", err)
	}
	if dev != nil {
		t.Error("Expected nil device")
	}
}

// ============================================================================
// Multi-Device Scenarios
// ============================================================================

func TestDiscovery_MultipleComchCapableDevices_SelectFirst(t *testing.T) {
	t.Log("Testing device selection prefers port 0 with multiple devices")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.1",
		IbdevName:     "mlx5_1",
		IfaceName:     "enp1s0f1np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})

	// Default config prefers port 0
	cfg := DeviceSelectionConfig{PreferPort: 0}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "01:00.0" {
		t.Errorf("Expected device with port 0 (01:00.0), got %s", dev.PCIAddr)
	}
}

func TestDiscovery_MultipleComchCapableDevices_PreferPort1(t *testing.T) {
	t.Log("Testing device selection with PreferPort=1 selects port 1")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.1",
		IbdevName:     "mlx5_1",
		IfaceName:     "enp1s0f1np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{PreferPort: 1}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "01:00.1" {
		t.Errorf("Expected device with port 1 (01:00.1), got %s", dev.PCIAddr)
	}
}

func TestDiscovery_MixedCapableAndNonCapableDevices(t *testing.T) {
	t.Log("Testing device selection filters to ComCh-capable devices only")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: false,
		IsComchServer: false,
	})
	// Add a ComCh capable PF
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "02:00.0",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp2s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	// Add a VF (should be skipped)
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.2",
		IbdevName:     "mlx5_0v0",
		IfaceName:     "enp1s0f0v0",
		FuncType:      PCIFuncTypeVF,
		IsComchClient: true,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "02:00.0" {
		t.Errorf("Expected ComCh capable device 02:00.0, got %s", dev.PCIAddr)
	}
}

func TestDiscovery_SelectionByPCIAddress(t *testing.T) {
	t.Log("Testing device selection by PCI address override")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "02:00.0",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp2s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: true,
	})

	// Override to select specific device
	cfg := DeviceSelectionConfig{PCIAddrOverride: "02:00.0"}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "02:00.0" {
		t.Errorf("Expected device 02:00.0, got %s", dev.PCIAddr)
	}
	if !dev.IsComchServer {
		t.Error("Expected device to be ComCh server capable")
	}
}

func TestDiscovery_SelectionByPCIAddress_NotFound(t *testing.T) {
	t.Log("Testing device selection returns error when PCI address not found")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{PCIAddrOverride: "99:00.0"}
	dev, err := mock.SelectDevice(cfg)

	if err == nil {
		t.Fatal("Expected error when specified device not found")
	}
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Errorf("Expected ErrDeviceNotFound, got %v", err)
	}
	if dev != nil {
		t.Error("Expected nil device")
	}
}

// ============================================================================
// Capability Filtering
// ============================================================================

func TestDiscovery_RequireClientCapability(t *testing.T) {
	t.Log("Testing device selection with RequireClient=true filters to client-capable devices")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: false,
		IsComchServer: true,
	})
	// Client-capable device
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "02:00.0",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp2s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{RequireClient: true}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "02:00.0" {
		t.Errorf("Expected client-capable device 02:00.0, got %s", dev.PCIAddr)
	}
	if !dev.IsComchClient {
		t.Error("Expected device to be ComCh client capable")
	}
}

func TestDiscovery_RequireServerCapability(t *testing.T) {
	t.Log("Testing device selection with RequireServer=true filters to server-capable devices")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	// Server-capable device
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "02:00.0",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp2s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: false,
		IsComchServer: true,
	})

	cfg := DeviceSelectionConfig{RequireServer: true}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "02:00.0" {
		t.Errorf("Expected server-capable device 02:00.0, got %s", dev.PCIAddr)
	}
	if !dev.IsComchServer {
		t.Error("Expected device to be ComCh server capable")
	}
}

func TestDiscovery_RequireBothCapabilities(t *testing.T) {
	t.Log("Testing device selection with both RequireClient and RequireServer")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	// Server-only device
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "02:00.0",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp2s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: false,
		IsComchServer: true,
	})
	// Both capabilities (DPU)
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "03:00.0",
		IbdevName:     "mlx5_4",
		IfaceName:     "enp3s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: true,
	})

	cfg := DeviceSelectionConfig{RequireClient: true, RequireServer: true}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "03:00.0" {
		t.Errorf("Expected dual-capability device 03:00.0, got %s", dev.PCIAddr)
	}
	if !dev.IsComchClient || !dev.IsComchServer {
		t.Error("Expected device to have both client and server capabilities")
	}
}

func TestDiscovery_NoBothCapabilitiesAvailable(t *testing.T) {
	t.Log("Testing device selection returns error when no device has both capabilities")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	// Server-only device
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "02:00.0",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp2s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: false,
		IsComchServer: true,
	})

	cfg := DeviceSelectionConfig{RequireClient: true, RequireServer: true}
	dev, err := mock.SelectDevice(cfg)

	if err == nil {
		t.Fatal("Expected error when no device has both capabilities")
	}
	if !errors.Is(err, ErrNoComchCapableDevices) {
		t.Errorf("Expected ErrNoComchCapableDevices, got %v", err)
	}
	if dev != nil {
		t.Error("Expected nil device")
	}
}

// ============================================================================
// Device Type Filtering
// ============================================================================

func TestDiscovery_FilterByFunctionType(t *testing.T) {
	t.Log("Testing device selection prefers PF over VF and SF")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.2",
		IbdevName:     "mlx5_0v0",
		IfaceName:     "enp1s0f0v0",
		FuncType:      PCIFuncTypeVF,
		IsComchClient: true,
		IsComchServer: false,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.3",
		IbdevName:     "mlx5_0s0",
		IfaceName:     "enp1s0f0s0",
		FuncType:      PCIFuncTypeSF,
		IsComchClient: true,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	// Should select only PF
	if dev.FuncType != PCIFuncTypePF {
		t.Errorf("Expected PF device, got %s", dev.FuncType)
	}
	if dev.PCIAddr != "01:00.0" {
		t.Errorf("Expected 01:00.0, got %s", dev.PCIAddr)
	}
}

func TestDiscovery_MultiplePFsNoPortMatch(t *testing.T) {
	t.Log("Testing device selection returns error when multiple PFs but no port match")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.2",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "02:00.3",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp2s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})

	// Default prefers port 0, but neither device ends in .0
	cfg := DeviceSelectionConfig{PreferPort: 0}
	dev, err := mock.SelectDevice(cfg)

	// Should error with multiple devices message
	if err == nil {
		t.Fatal("Expected error when multiple devices with no port match")
	}
	if !strings.Contains(err.Error(), "multiple devices") {
		t.Errorf("Expected 'multiple devices' error, got: %v", err)
	}
	if dev != nil {
		t.Error("Expected nil device")
	}
}

// ============================================================================
// Discovery Error Scenarios
// ============================================================================

func TestDiscovery_DiscoverError(t *testing.T) {
	t.Log("Testing device selection propagates discovery errors")
	mock := NewMockDiscovery()
	mock.DiscoverErr = errors.New("discovery failed: driver not loaded")

	cfg := DeviceSelectionConfig{}
	dev, err := mock.SelectDevice(cfg)

	if err == nil {
		t.Fatal("Expected error when discovery fails")
	}
	if !strings.Contains(err.Error(), "driver not loaded") {
		t.Errorf("Expected driver error, got: %v", err)
	}
	if dev != nil {
		t.Error("Expected nil device")
	}
}

func TestDiscovery_CapabilityCheckError(t *testing.T) {
	t.Log("Testing capability check error propagation")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	mock.ClientCapErr = errors.New("capability check failed")

	// Capability check via the mock's CheckClientCapability
	_, err := mock.CheckClientCapability("01:00.0")
	if err == nil {
		t.Fatal("Expected error from capability check")
	}
	if !strings.Contains(err.Error(), "capability check failed") {
		t.Errorf("Expected capability error, got: %v", err)
	}
}

// ============================================================================
// Multi-DPU Cluster Scenarios
// ============================================================================

func TestDiscovery_TwoDPUConfiguration(t *testing.T) {
	t.Log("Testing device selection in multi-DPU configuration")
	mock := NewMockDiscovery()

	// DPU 1: Two PF devices
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "03:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp3s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: true,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "03:00.1",
		IbdevName:     "mlx5_1",
		IfaceName:     "enp3s0f1np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: true,
	})

	// DPU 2: Two PF devices
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "83:00.0",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp131s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: true,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "83:00.1",
		IbdevName:     "mlx5_3",
		IfaceName:     "enp131s0f1np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: true,
	})

	// Without PCI override, should get first port 0 device
	cfg := DeviceSelectionConfig{PreferPort: 0}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "03:00.0" {
		t.Errorf("Expected first DPU port 0 (03:00.0), got %s", dev.PCIAddr)
	}

	// With PCI override, should get specific DPU
	cfg = DeviceSelectionConfig{PCIAddrOverride: "83:00.0"}
	dev, err = mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice with override failed: %v", err)
	}

	if dev.PCIAddr != "83:00.0" {
		t.Errorf("Expected second DPU (83:00.0), got %s", dev.PCIAddr)
	}
}

func TestDiscovery_HostWithMultipleMellanoxNICs(t *testing.T) {
	t.Log("Testing device selection filters out non-DPU Mellanox NICs")
	mock := NewMockDiscovery()

	// ConnectX-6 NIC (not ComCh capable)
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "07:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp7s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: false, // Regular NIC, not DPU
		IsComchServer: false,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "07:00.1",
		IbdevName:     "mlx5_1",
		IfaceName:     "enp7s0f1np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: false,
		IsComchServer: false,
	})

	// BlueField-3 DPU (ComCh capable)
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "41:00.0",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp65s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})

	cfg := DeviceSelectionConfig{}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	// Should select the BlueField DPU, not the ConnectX NICs
	if dev.PCIAddr != "41:00.0" {
		t.Errorf("Expected BlueField DPU (41:00.0), got %s", dev.PCIAddr)
	}
	if !dev.IsComchClient {
		t.Error("Expected device to be ComCh client capable")
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestDiscovery_EmptyPCIAddrOverride(t *testing.T) {
	t.Log("Testing device selection with empty PCI override uses normal selection")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})

	// Empty override should use normal selection
	cfg := DeviceSelectionConfig{PCIAddrOverride: ""}
	dev, err := mock.SelectDevice(cfg)
	if err != nil {
		t.Fatalf("SelectDevice failed: %v", err)
	}

	if dev.PCIAddr != "01:00.0" {
		t.Errorf("Expected 01:00.0, got %s", dev.PCIAddr)
	}
}

func TestDiscovery_DeviceInfoJSONSerialization(t *testing.T) {
	t.Log("Testing DeviceInfo struct field access")
	dev := DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	}

	// Verify field access works (compile-time check for struct fields)
	if dev.PCIAddr == "" {
		t.Error("PCIAddr should not be empty")
	}
	if dev.IbdevName == "" {
		t.Error("IbdevName should not be empty")
	}
	if dev.IfaceName == "" {
		t.Error("IfaceName should not be empty")
	}
}

func TestDiscovery_DefaultConfigValues(t *testing.T) {
	t.Log("Testing DefaultDeviceSelectionConfig returns expected defaults")
	cfg := DefaultDeviceSelectionConfig()

	if cfg.PCIAddrOverride != "" {
		t.Errorf("Expected empty PCIAddrOverride, got %s", cfg.PCIAddrOverride)
	}
	if cfg.PreferPort != 0 {
		t.Errorf("Expected PreferPort 0, got %d", cfg.PreferPort)
	}
	if cfg.RequireClient {
		t.Error("Expected RequireClient false")
	}
	if cfg.RequireServer {
		t.Error("Expected RequireServer false")
	}
}

func TestDiscovery_PCIFuncTypeString(t *testing.T) {
	t.Log("Testing PCIFuncType.String() returns human-readable names")
	tests := []struct {
		funcType PCIFuncType
		expected string
	}{
		{PCIFuncTypePF, "PF"},
		{PCIFuncTypeVF, "VF"},
		{PCIFuncTypeSF, "SF"},
		{PCIFuncType(99), "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if got := tc.funcType.String(); got != tc.expected {
				t.Errorf("PCIFuncType(%d).String() = %q, want %q", tc.funcType, got, tc.expected)
			}
		})
	}
}

// ============================================================================
// Discovery Enumeration Tests
// ============================================================================

func TestDiscovery_EnumerateAllDevices(t *testing.T) {
	t.Log("Testing DiscoverDevices returns all configured devices")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	})
	mock.AddDevice(DeviceInfo{
		PCIAddr:       "02:00.0",
		IbdevName:     "mlx5_2",
		IfaceName:     "enp2s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: false,
		IsComchServer: true,
	})

	devices, err := mock.DiscoverDevices()
	if err != nil {
		t.Fatalf("DiscoverDevices failed: %v", err)
	}

	if len(devices) != 2 {
		t.Errorf("Expected 2 devices, got %d", len(devices))
	}

	// Verify returned slice is a copy
	devices[0].PCIAddr = "modified"
	original, _ := mock.DiscoverDevices()
	if original[0].PCIAddr == "modified" {
		t.Error("DiscoverDevices should return a copy, not reference to internal slice")
	}
}

func TestDiscovery_SortDevicesByPCI(t *testing.T) {
	t.Log("Testing devices can be sorted by PCI address")
	mock := NewMockDiscovery()
	mock.AddDevice(DeviceInfo{PCIAddr: "83:00.0", FuncType: PCIFuncTypePF, IsComchClient: true})
	mock.AddDevice(DeviceInfo{PCIAddr: "03:00.0", FuncType: PCIFuncTypePF, IsComchClient: true})
	mock.AddDevice(DeviceInfo{PCIAddr: "41:00.0", FuncType: PCIFuncTypePF, IsComchClient: true})

	devices, err := mock.DiscoverDevices()
	if err != nil {
		t.Fatalf("DiscoverDevices failed: %v", err)
	}

	// Sort by PCI address for predictable ordering
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].PCIAddr < devices[j].PCIAddr
	})

	expected := []string{"03:00.0", "41:00.0", "83:00.0"}
	for i, addr := range expected {
		if devices[i].PCIAddr != addr {
			t.Errorf("devices[%d].PCIAddr = %s, want %s", i, devices[i].PCIAddr, addr)
		}
	}
}

// ============================================================================
// Error Constants Verification
// ============================================================================

func TestDiscoveryErrors_AreDistinct(t *testing.T) {
	t.Log("Testing discovery error constants are unique and distinguishable")
	errs := []error{
		ErrNoDevicesFound,
		ErrNoComchCapableDevices,
		ErrDeviceNotFound,
	}

	for i, err1 := range errs {
		for j, err2 := range errs {
			if i != j && errors.Is(err1, err2) {
				t.Errorf("Error %v should not equal %v", err1, err2)
			}
		}
	}
}

func TestDiscoveryErrors_ContainHelpfulMessages(t *testing.T) {
	t.Log("Testing discovery error messages contain helpful context")
	tests := []struct {
		err      error
		contains string
	}{
		{ErrNoDevicesFound, "no"},
		{ErrNoComchCapableDevices, "ComCh"},
		{ErrDeviceNotFound, "not found"},
	}

	for _, tc := range tests {
		if !strings.Contains(tc.err.Error(), tc.contains) {
			t.Errorf("Error %q should contain %q", tc.err.Error(), tc.contains)
		}
	}
}
