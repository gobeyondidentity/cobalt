// Package doca provides collectors for DOCA/BlueField system information.
package doca

import (
	"bufio"
	"context"
	"strconv"
	"strings"
)

// Inventory contains detailed firmware and software inventory of the DPU.
type Inventory struct {
	Firmwares     []FirmwareComponent
	Packages      []InstalledPackage
	Modules       []KernelModule
	Boot          BootInfo
	OperationMode string
}

// FirmwareComponent represents a firmware version.
type FirmwareComponent struct {
	Name      string
	Version   string
	BuildDate string
}

// InstalledPackage represents an installed Debian package.
type InstalledPackage struct {
	Name    string
	Version string
}

// KernelModule represents a loaded kernel module.
type KernelModule struct {
	Name   string
	Size   string
	UsedBy int
}

// BootInfo contains boot configuration details.
type BootInfo struct {
	UEFIMode   bool
	SecureBoot bool
	BootDevice string
}

// InvCollector defines the interface for inventory collection.
// This allows injecting mock implementations for testing.
type InvCollector interface {
	Collect(ctx context.Context) (*Inventory, error)
}

// InventoryCollector gathers DPU inventory information.
type InventoryCollector struct{}

// NoOpInventoryCollector is a no-op inventory collector for testing.
type NoOpInventoryCollector struct{}

// NewNoOpInventoryCollector creates a no-op inventory collector for testing.
func NewNoOpInventoryCollector() *NoOpInventoryCollector {
	return &NoOpInventoryCollector{}
}

// Collect returns empty inventory without executing any commands.
func (c *NoOpInventoryCollector) Collect(ctx context.Context) (*Inventory, error) {
	return &Inventory{OperationMode: "test"}, nil
}

// NewInventoryCollector creates a new inventory collector.
func NewInventoryCollector() *InventoryCollector {
	return &InventoryCollector{}
}

// Collect gathers all inventory information from the DPU.
func (c *InventoryCollector) Collect(ctx context.Context) (*Inventory, error) {
	inv := &Inventory{}

	// Collect firmware versions
	inv.Firmwares = c.collectFirmwares(ctx)

	// Collect installed packages
	inv.Packages = c.collectPackages(ctx)

	// Collect kernel modules
	inv.Modules = c.collectModules()

	// Collect boot info
	inv.Boot = c.collectBootInfo(ctx)

	// Collect operation mode
	inv.OperationMode = c.collectOperationMode(ctx)

	return inv, nil
}

// collectFirmwares gathers firmware versions from various sources.
func (c *InventoryCollector) collectFirmwares(ctx context.Context) []FirmwareComponent {
	var firmwares []FirmwareComponent

	// NIC firmware from flint (already used in system.go)
	if fw := c.getNICFirmware(ctx); fw != nil {
		firmwares = append(firmwares, *fw)
	}

	// BMC firmware will be added via Redfish client separately

	return firmwares
}

// getNICFirmware gets NIC firmware version using flint.
func (c *InventoryCollector) getNICFirmware(ctx context.Context) *FirmwareComponent {
	// Find MST device
	mstOut, err := execCommand(ctx, "sudo", "mst", "status").Output()
	if err != nil {
		return nil
	}

	var devicePath string
	for _, line := range strings.Split(string(mstOut), "\n") {
		if strings.Contains(line, "/dev/mst/") && strings.Contains(line, "pciconf") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				devicePath = fields[0]
				break
			}
		}
	}

	if devicePath == "" {
		return nil
	}

	// Get firmware version from flint
	out, err := execCommand(ctx, "sudo", "flint", "-d", devicePath, "q").Output()
	if err != nil {
		return nil
	}

	fw := &FirmwareComponent{Name: "nic"}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "FW Version:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				fw.Version = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "FW Release Date:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				fw.BuildDate = strings.TrimSpace(parts[1])
			}
		}
	}

	if fw.Version != "" {
		return fw
	}
	return nil
}

// collectPackages gets installed Debian packages.
func (c *InventoryCollector) collectPackages(ctx context.Context) []InstalledPackage {
	// Get DOCA-related packages only to keep the list manageable
	out, err := execCommand(ctx, "dpkg-query", "-W", "-f", "${Package} ${Version}\n").Output()
	if err != nil {
		return nil
	}

	var packages []InstalledPackage
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Filter to DOCA, mlnx, and bluefield packages
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "doca") &&
			!strings.Contains(lower, "mlnx") &&
			!strings.Contains(lower, "mlx") &&
			!strings.Contains(lower, "bluefield") &&
			!strings.Contains(lower, "ofed") {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			packages = append(packages, InstalledPackage{
				Name:    parts[0],
				Version: parts[1],
			})
		}
	}

	return packages
}

// collectModules reads loaded kernel modules from /proc/modules.
func (c *InventoryCollector) collectModules() []KernelModule {
	f, err := osOpen("/proc/modules")
	if err != nil {
		return nil
	}
	defer f.Close()

	var modules []KernelModule
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		// Format: name size refcount deps state offset
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		// Filter to Mellanox/NVIDIA modules
		name := fields[0]
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "mlx") &&
			!strings.HasPrefix(lower, "ib_") &&
			!strings.HasPrefix(lower, "rdma") &&
			!strings.Contains(lower, "bluefield") &&
			!strings.Contains(lower, "openvswitch") {
			continue
		}

		usedBy, _ := strconv.Atoi(fields[2])
		modules = append(modules, KernelModule{
			Name:   name,
			Size:   fields[1],
			UsedBy: usedBy,
		})
	}

	return modules
}

// collectBootInfo gathers boot configuration.
func (c *InventoryCollector) collectBootInfo(ctx context.Context) BootInfo {
	info := BootInfo{}

	// Check if UEFI mode
	if _, err := osStat("/sys/firmware/efi"); err == nil {
		info.UEFIMode = true
	}

	// Check secure boot status
	out, err := execCommand(ctx, "mokutil", "--sb-state").Output()
	if err == nil {
		if strings.Contains(string(out), "SecureBoot enabled") {
			info.SecureBoot = true
		}
	}

	// Get boot device from /proc/cmdline
	if data, err := osReadFile("/proc/cmdline"); err == nil {
		cmdline := string(data)
		// Look for root= parameter
		for _, part := range strings.Fields(cmdline) {
			if strings.HasPrefix(part, "root=") {
				info.BootDevice = strings.TrimPrefix(part, "root=")
				break
			}
		}
	}

	return info
}

// collectOperationMode gets the DPU operation mode from mlxconfig.
func (c *InventoryCollector) collectOperationMode(ctx context.Context) string {
	// Find MST device
	mstOut, err := execCommand(ctx, "sudo", "mst", "status").Output()
	if err != nil {
		return "unknown"
	}

	var devicePath string
	for _, line := range strings.Split(string(mstOut), "\n") {
		if strings.Contains(line, "/dev/mst/") && strings.Contains(line, "pciconf") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				devicePath = fields[0]
				break
			}
		}
	}

	if devicePath == "" {
		return "unknown"
	}

	// Query mlxconfig for INTERNAL_CPU_MODEL
	out, err := execCommand(ctx, "sudo", "mlxconfig", "-d", devicePath, "q", "INTERNAL_CPU_MODEL").Output()
	if err != nil {
		return "unknown"
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "INTERNAL_CPU_MODEL") {
			// Parse: INTERNAL_CPU_MODEL            EMBEDDED_CPU(1)
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val := parts[1]
				// Extract the mode name from format like "EMBEDDED_CPU(1)"
				if idx := strings.Index(val, "("); idx > 0 {
					val = val[:idx]
				}
				switch strings.ToUpper(val) {
				case "EMBEDDED_CPU":
					return "embedded"
				case "SEPARATED_HOST":
					return "separated"
				case "SMART_NIC":
					return "smart-nic"
				default:
					return strings.ToLower(val)
				}
			}
		}
	}

	return "unknown"
}
