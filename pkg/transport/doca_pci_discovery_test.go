//go:build !doca

package transport

import (
	"errors"
	"testing"
)

func TestDiscoverDOCADevicesStub(t *testing.T) {
	devices, err := DiscoverDOCADevices()

	if !errors.Is(err, ErrDOCANotAvailable) {
		t.Errorf("DiscoverDOCADevices error = %v, want ErrDOCANotAvailable", err)
	}
	if devices != nil {
		t.Errorf("DiscoverDOCADevices devices = %v, want nil", devices)
	}
}

func TestSelectDeviceStub(t *testing.T) {
	cfg := DeviceSelectionConfig{
		PCIAddrOverride: "",
		PreferPort:      0,
		RequireClient:   false,
		RequireServer:   false,
	}

	device, err := SelectDevice(cfg)

	if !errors.Is(err, ErrDOCANotAvailable) {
		t.Errorf("SelectDevice error = %v, want ErrDOCANotAvailable", err)
	}
	if device != nil {
		t.Errorf("SelectDevice device = %v, want nil", device)
	}
}

func TestDeviceInfoFields(t *testing.T) {
	// Verify the DeviceInfo struct has the expected fields
	info := DeviceInfo{
		PCIAddr:       "01:00.0",
		IbdevName:     "mlx5_0",
		IfaceName:     "enp1s0f0np0",
		FuncType:      PCIFuncTypePF,
		IsComchClient: true,
		IsComchServer: false,
	}

	if info.PCIAddr != "01:00.0" {
		t.Errorf("PCIAddr = %v, want 01:00.0", info.PCIAddr)
	}
	if info.IbdevName != "mlx5_0" {
		t.Errorf("IbdevName = %v, want mlx5_0", info.IbdevName)
	}
	if info.IfaceName != "enp1s0f0np0" {
		t.Errorf("IfaceName = %v, want enp1s0f0np0", info.IfaceName)
	}
	if info.FuncType != PCIFuncTypePF {
		t.Errorf("FuncType = %v, want %v", info.FuncType, PCIFuncTypePF)
	}
	if !info.IsComchClient {
		t.Error("IsComchClient should be true")
	}
	if info.IsComchServer {
		t.Error("IsComchServer should be false")
	}
}

func TestPCIFuncTypeConstants(t *testing.T) {
	// Verify constants match DOCA API values
	if PCIFuncTypePF != 0 {
		t.Errorf("PCIFuncTypePF = %d, want 0", PCIFuncTypePF)
	}
	if PCIFuncTypeVF != 1 {
		t.Errorf("PCIFuncTypeVF = %d, want 1", PCIFuncTypeVF)
	}
	if PCIFuncTypeSF != 2 {
		t.Errorf("PCIFuncTypeSF = %d, want 2", PCIFuncTypeSF)
	}
}

func TestDeviceSelectionConfigDefaults(t *testing.T) {
	cfg := DefaultDeviceSelectionConfig()

	if cfg.PCIAddrOverride != "" {
		t.Errorf("PCIAddrOverride = %v, want empty string", cfg.PCIAddrOverride)
	}
	if cfg.PreferPort != 0 {
		t.Errorf("PreferPort = %d, want 0", cfg.PreferPort)
	}
	if cfg.RequireClient {
		t.Error("RequireClient should default to false")
	}
	if cfg.RequireServer {
		t.Error("RequireServer should default to false")
	}
}
