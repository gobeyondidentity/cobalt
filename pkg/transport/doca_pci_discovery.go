//go:build doca

// Package transport provides DOCA PCI device discovery for BlueField DPU communication.
// This file requires the DOCA SDK and BlueField hardware to build.
package transport

/*
#cgo CFLAGS: -I/opt/mellanox/doca/include -I${SRCDIR}/csrc
#cgo linux,arm64 LDFLAGS: -L/opt/mellanox/doca/lib/aarch64-linux-gnu -ldoca_comch -ldoca_common -ldoca_argp
#cgo linux,amd64 LDFLAGS: -L/opt/mellanox/doca/lib/x86_64-linux-gnu -ldoca_comch -ldoca_common -ldoca_argp

#include <stdlib.h>
#include "discovery_shim.h"
#include "discovery_shim.c"
*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

// PCIFuncType represents the PCI function type from DOCA API.
type PCIFuncType int

const (
	// PCIFuncTypePF is a Physical Function (preferred for ComCh)
	PCIFuncTypePF PCIFuncType = 0
	// PCIFuncTypeVF is a Virtual Function
	PCIFuncTypeVF PCIFuncType = 1
	// PCIFuncTypeSF is a Sub Function
	PCIFuncTypeSF PCIFuncType = 2
)

// String returns a human-readable function type name.
func (t PCIFuncType) String() string {
	switch t {
	case PCIFuncTypePF:
		return "PF"
	case PCIFuncTypeVF:
		return "VF"
	case PCIFuncTypeSF:
		return "SF"
	default:
		return "unknown"
	}
}

// DeviceInfo contains information about a discovered DOCA device.
type DeviceInfo struct {
	// PCIAddr is the PCI address (e.g., "01:00.0")
	PCIAddr string `json:"pci_addr"`

	// IbdevName is the InfiniBand device name (e.g., "mlx5_0")
	IbdevName string `json:"ibdev_name"`

	// IfaceName is the network interface name (e.g., "enp1s0f0np0")
	IfaceName string `json:"iface_name"`

	// FuncType is the PCI function type (PF, VF, or SF)
	FuncType PCIFuncType `json:"func_type"`

	// IsComchClient indicates if this device supports ComCh client operations (host side)
	IsComchClient bool `json:"is_comch_client"`

	// IsComchServer indicates if this device supports ComCh server operations (DPU side)
	IsComchServer bool `json:"is_comch_server"`
}

// DeviceSelectionConfig configures automatic device selection.
type DeviceSelectionConfig struct {
	// PCIAddrOverride forces selection of a specific PCI address.
	// If set, auto-selection is bypassed.
	PCIAddrOverride string

	// PreferPort prefers devices with this port number (0 or 1).
	// Default: 0 (prefer *.0 over *.1)
	PreferPort int

	// RequireClient requires the device to support ComCh client operations.
	RequireClient bool

	// RequireServer requires the device to support ComCh server operations.
	RequireServer bool
}

// DefaultDeviceSelectionConfig returns a DeviceSelectionConfig with sensible defaults.
func DefaultDeviceSelectionConfig() DeviceSelectionConfig {
	return DeviceSelectionConfig{
		PCIAddrOverride: "",
		PreferPort:      0,
		RequireClient:   false,
		RequireServer:   false,
	}
}

// Discovery errors
var (
	ErrNoDevicesFound         = errors.New("doca discovery: no Mellanox devices found - is the driver loaded?")
	ErrNoComchCapableDevices  = errors.New("doca discovery: no ComCh-capable devices found - BlueField required")
	ErrMultipleDevicesFound   = errors.New("doca discovery: multiple devices found - specify pci_address in config")
	ErrDeviceNotFound         = errors.New("doca discovery: specified device not found")
	ErrDiscoveryFailed        = errors.New("doca discovery: device enumeration failed")
)

// DiscoverDOCADevices enumerates all available DOCA devices.
// Returns a list of devices with their capabilities.
func DiscoverDOCADevices() ([]DeviceInfo, error) {
	// Allocate buffer for JSON result
	const bufSize = 8192
	buf := C.malloc(C.size_t(bufSize))
	if buf == nil {
		return nil, errors.New("doca discovery: failed to allocate buffer")
	}
	defer C.free(buf)

	// Call C discovery function
	ret := C.shim_discover_devices((*C.char)(buf), C.size_t(bufSize))
	if ret < 0 {
		switch ret {
		case C.SHIM_DISCOVERY_ERR_NO_DEVICES:
			return nil, ErrNoDevicesFound
		case C.SHIM_DISCOVERY_ERR_ENUM_FAILED:
			return nil, ErrDiscoveryFailed
		default:
			return nil, fmt.Errorf("doca discovery: failed with code %d", ret)
		}
	}

	if ret == 0 {
		return []DeviceInfo{}, nil
	}

	// Parse JSON result
	jsonStr := C.GoString((*C.char)(buf))
	var devices []DeviceInfo
	if err := json.Unmarshal([]byte(jsonStr), &devices); err != nil {
		return nil, fmt.Errorf("doca discovery: failed to parse device list: %w", err)
	}

	return devices, nil
}

// SelectDevice auto-selects the best DOCA device based on configuration.
// Returns the selected device or an error with helpful troubleshooting info.
func SelectDevice(cfg DeviceSelectionConfig) (*DeviceInfo, error) {
	// If override is specified, look for that specific device
	if cfg.PCIAddrOverride != "" {
		return selectByPCIAddr(cfg.PCIAddrOverride)
	}

	devices, err := DiscoverDOCADevices()
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

	// Multiple candidates - apply port preference
	preferredPort := fmt.Sprintf(".%d", cfg.PreferPort)
	for i := range candidates {
		if strings.HasSuffix(candidates[i].PCIAddr, preferredPort) {
			return &candidates[i], nil
		}
	}

	// No port preference match - return error with device list
	var addrs []string
	for _, c := range candidates {
		addrs = append(addrs, c.PCIAddr)
	}
	return nil, fmt.Errorf("%w: [%s]", ErrMultipleDevicesFound, strings.Join(addrs, ", "))
}

// selectByPCIAddr finds a device by its PCI address.
func selectByPCIAddr(pciAddr string) (*DeviceInfo, error) {
	devices, err := DiscoverDOCADevices()
	if err != nil {
		return nil, err
	}

	for i := range devices {
		if devices[i].PCIAddr == pciAddr {
			return &devices[i], nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrDeviceNotFound, pciAddr)
}

// CheckComchClientCapability checks if a device supports ComCh client operations.
func CheckComchClientCapability(pciAddr string) (bool, error) {
	cPCI := C.CString(pciAddr)
	defer C.free(unsafe.Pointer(cPCI))

	ret := C.shim_check_comch_client_cap(cPCI)
	if ret < 0 {
		return false, fmt.Errorf("doca capability check failed: %d", ret)
	}
	return ret == 1, nil
}

// CheckComchServerCapability checks if a device supports ComCh server operations.
func CheckComchServerCapability(pciAddr string) (bool, error) {
	cPCI := C.CString(pciAddr)
	defer C.free(unsafe.Pointer(cPCI))

	ret := C.shim_check_comch_server_cap(cPCI)
	if ret < 0 {
		return false, fmt.Errorf("doca capability check failed: %d", ret)
	}
	return ret == 1, nil
}
