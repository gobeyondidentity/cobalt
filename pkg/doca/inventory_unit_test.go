package doca

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

// saveAndRestoreInventory saves all function variables and returns a restore function.
func saveAndRestoreInventory(t *testing.T) func() {
	t.Helper()
	origReadFile := osReadFile
	origOpen := osOpen
	origStat := osStat
	origCommand := execCommand

	return func() {
		osReadFile = origReadFile
		osOpen = origOpen
		osStat = origStat
		execCommand = origCommand
	}
}

func TestNewInventoryCollector(t *testing.T) {
	t.Log("Testing NewInventoryCollector returns non-nil collector")
	c := NewInventoryCollector()
	if c == nil {
		t.Fatal("NewInventoryCollector() returned nil")
	}
}

func TestInventoryCollector_Collect_Packages(t *testing.T) {
	t.Log("Testing Collect gathers DOCA packages from dpkg-query")
	restore := saveAndRestoreInventory(t)
	defer restore()

	dpkgOutput := `doca-runtime 3.2.0-1
mlnx-fw-updater 24.10
libdoca-common 3.2.0
regular-package 1.0
bluefield-utils 2.0
some-other-pkg 3.0
mlx5-core-dkms 24.10.1
`

	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "dpkg-query" {
			return exec.Command("echo", dpkgOutput)
		}
		return exec.Command("false")
	}

	c := NewInventoryCollector()
	inv, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	// Should have: doca-runtime, mlnx-fw-updater, libdoca-common, bluefield-utils, mlx5-core-dkms
	// Should NOT have: regular-package, some-other-pkg
	if len(inv.Packages) != 5 {
		t.Errorf("Packages count = %d, want 5", len(inv.Packages))
		for _, p := range inv.Packages {
			t.Logf("  Package: %s %s", p.Name, p.Version)
		}
	}

	// Verify specific package filtering
	found := make(map[string]bool)
	for _, p := range inv.Packages {
		found[p.Name] = true
	}
	if !found["doca-runtime"] {
		t.Error("doca-runtime should be in packages")
	}
	if found["regular-package"] {
		t.Error("regular-package should NOT be in packages")
	}
}

func TestInventoryCollector_Collect_BootInfo_UEFI(t *testing.T) {
	t.Log("Testing Collect detects UEFI boot mode")
	restore := saveAndRestoreInventory(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		if name == "/sys/firmware/efi" {
			return nil, nil // exists
		}
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}

	c := NewInventoryCollector()
	inv, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !inv.Boot.UEFIMode {
		t.Error("UEFIMode = false, want true when /sys/firmware/efi exists")
	}
}

func TestInventoryCollector_Collect_BootInfo_SecureBoot(t *testing.T) {
	t.Log("Testing Collect detects Secure Boot status")
	restore := saveAndRestoreInventory(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "mokutil" && len(args) > 0 && args[0] == "--sb-state" {
			return exec.Command("echo", "SecureBoot enabled")
		}
		return exec.Command("false")
	}

	c := NewInventoryCollector()
	inv, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !inv.Boot.SecureBoot {
		t.Error("SecureBoot = false, want true when mokutil reports enabled")
	}
}

func TestInventoryCollector_Collect_BootDevice(t *testing.T) {
	t.Log("Testing Collect extracts boot device from /proc/cmdline")
	restore := saveAndRestoreInventory(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		if name == "/proc/cmdline" {
			return []byte("BOOT_IMAGE=/boot/vmlinuz root=/dev/nvme0n1p2 ro quiet splash"), nil
		}
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}

	c := NewInventoryCollector()
	inv, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if inv.Boot.BootDevice != "/dev/nvme0n1p2" {
		t.Errorf("BootDevice = %q, want %q", inv.Boot.BootDevice, "/dev/nvme0n1p2")
	}
}

func TestInventoryCollector_Collect_OperationMode_Embedded(t *testing.T) {
	t.Log("Testing Collect detects embedded operation mode")
	restore := saveAndRestoreInventory(t)
	defer restore()

	mstOutput := `/dev/mst/mt41692_pciconf0 - PCI configuration`
	mlxconfigOutput := `INTERNAL_CPU_MODEL            EMBEDDED_CPU(1)`

	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "sudo" && len(args) > 0 {
			if args[0] == "mst" {
				return exec.Command("echo", mstOutput)
			}
			if args[0] == "mlxconfig" {
				return exec.Command("echo", mlxconfigOutput)
			}
		}
		return exec.Command("false")
	}

	c := NewInventoryCollector()
	inv, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if inv.OperationMode != "embedded" {
		t.Errorf("OperationMode = %q, want %q", inv.OperationMode, "embedded")
	}
}

func TestInventoryCollector_Collect_OperationMode_Separated(t *testing.T) {
	t.Log("Testing Collect detects separated operation mode")
	restore := saveAndRestoreInventory(t)
	defer restore()

	mstOutput := `/dev/mst/mt41692_pciconf0 - PCI configuration`
	mlxconfigOutput := `INTERNAL_CPU_MODEL            SEPARATED_HOST(2)`

	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "sudo" && len(args) > 0 {
			if args[0] == "mst" {
				return exec.Command("echo", mstOutput)
			}
			if args[0] == "mlxconfig" {
				return exec.Command("echo", mlxconfigOutput)
			}
		}
		return exec.Command("false")
	}

	c := NewInventoryCollector()
	inv, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if inv.OperationMode != "separated" {
		t.Errorf("OperationMode = %q, want %q", inv.OperationMode, "separated")
	}
}

func TestInventoryCollector_collectModules_FiltersMellanox(t *testing.T) {
	t.Log("Testing collectModules filters to Mellanox/RDMA modules only")
	// Note: This test requires a real file handle for /proc/modules
	// The function uses osOpen which returns *os.File
	t.Skip("Requires real /proc/modules or file descriptor mocking")
}

func TestInventoryCollector_collectPackages_FiltersDOCA(t *testing.T) {
	t.Log("Testing collectPackages filters to DOCA-related packages only")
	restore := saveAndRestoreInventory(t)
	defer restore()

	dpkgOutput := `doca-sdk 3.2.0
mlnx-ofed-kernel 24.10
mlx5-firmware-tools 24.10.1
unrelated-package 1.0
another-package 2.0
ofed-scripts 5.9
`

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "dpkg-query" {
			return exec.Command("echo", dpkgOutput)
		}
		return exec.Command("false")
	}

	c := NewInventoryCollector()
	packages := c.collectPackages(context.Background())

	// Should include: doca-sdk, mlnx-ofed-kernel, mlx5-firmware-tools, ofed-scripts
	// Should exclude: unrelated-package, another-package
	if len(packages) != 4 {
		t.Errorf("packages count = %d, want 4", len(packages))
		for _, p := range packages {
			t.Logf("  Package: %s", p.Name)
		}
	}
}

func TestInventoryCollector_collectBootInfo_NoUEFI(t *testing.T) {
	t.Log("Testing collectBootInfo handles non-UEFI system")
	restore := saveAndRestoreInventory(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}

	c := NewInventoryCollector()
	boot := c.collectBootInfo(context.Background())

	if boot.UEFIMode {
		t.Error("UEFIMode = true, want false when /sys/firmware/efi doesn't exist")
	}
	if boot.SecureBoot {
		t.Error("SecureBoot = true, want false when mokutil fails")
	}
}

func TestInventoryCollector_Collect_NICFirmware(t *testing.T) {
	t.Log("Testing Collect extracts NIC firmware from flint")
	restore := saveAndRestoreInventory(t)
	defer restore()

	mstOutput := `/dev/mst/mt41692_pciconf0 - PCI configuration`
	flintOutput := `FW Version:            32.39.1002
FW Release Date:       9/5/2024
Product Version:       rel-32_39_1002
`

	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "sudo" && len(args) > 0 {
			if args[0] == "mst" {
				return exec.Command("echo", mstOutput)
			}
			if args[0] == "flint" {
				return exec.Command("echo", flintOutput)
			}
		}
		return exec.Command("false")
	}

	c := NewInventoryCollector()
	inv, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(inv.Firmwares) != 1 {
		t.Fatalf("Firmwares count = %d, want 1", len(inv.Firmwares))
	}
	if inv.Firmwares[0].Name != "nic" {
		t.Errorf("Firmware name = %q, want %q", inv.Firmwares[0].Name, "nic")
	}
	if inv.Firmwares[0].Version != "32.39.1002" {
		t.Errorf("Firmware version = %q, want %q", inv.Firmwares[0].Version, "32.39.1002")
	}
	if inv.Firmwares[0].BuildDate != "9/5/2024" {
		t.Errorf("Firmware build date = %q, want %q", inv.Firmwares[0].BuildDate, "9/5/2024")
	}
}
