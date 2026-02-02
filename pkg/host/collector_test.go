package host

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// saveAndRestore saves all function variables and returns a restore function.
func saveAndRestore(t *testing.T) func() {
	t.Helper()
	origHostname := osHostname
	origReadFile := osReadFile
	origStat := osStat
	origReadlink := osReadlink
	origGlob := filepathGlob
	origBase := filepathBase
	origLookPath := execLookPath
	origCommand := execCommand

	return func() {
		osHostname = origHostname
		osReadFile = origReadFile
		osStat = origStat
		osReadlink = origReadlink
		filepathGlob = origGlob
		filepathBase = origBase
		execLookPath = origLookPath
		execCommand = origCommand
	}
}

func TestNewCollector(t *testing.T) {
	t.Log("Testing NewCollector returns non-nil collector")
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector() returned nil")
	}
}

func TestCollector_CollectHostInfo(t *testing.T) {
	t.Log("Testing CollectHostInfo gathers all host information")
	restore := saveAndRestore(t)
	defer restore()

	osHostname = func() (string, error) {
		return "test-host", nil
	}
	osReadFile = func(name string) ([]byte, error) {
		switch name {
		case "/etc/os-release":
			return []byte(`NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu`), nil
		case "/proc/version":
			return []byte("Linux version 6.8.0-40-generic (buildd@lcy02-amd64-115) (x86_64-linux-gnu-gcc-13)"), nil
		case "/proc/meminfo":
			return []byte("MemTotal:       131926168 kB\nMemFree:        12345678 kB"), nil
		case "/proc/uptime":
			return []byte("12345.67 890.12"), nil
		}
		return nil, os.ErrNotExist
	}

	c := NewCollector()
	info, err := c.CollectHostInfo(context.Background())

	if err != nil {
		t.Fatalf("CollectHostInfo() error = %v", err)
	}
	if info.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", info.Hostname, "test-host")
	}
	if info.OSName != "Ubuntu" {
		t.Errorf("OSName = %q, want %q", info.OSName, "Ubuntu")
	}
	if info.OSVersion != "24.04 LTS (Noble Numbat)" {
		t.Errorf("OSVersion = %q, want %q", info.OSVersion, "24.04 LTS (Noble Numbat)")
	}
	if info.KernelVersion != "6.8.0-40-generic" {
		t.Errorf("KernelVersion = %q, want %q", info.KernelVersion, "6.8.0-40-generic")
	}
	if info.MemoryGB != 125 {
		t.Errorf("MemoryGB = %d, want %d", info.MemoryGB, 125)
	}
	if info.UptimeSeconds != 12345 {
		t.Errorf("UptimeSeconds = %d, want %d", info.UptimeSeconds, 12345)
	}
}

func TestCollector_CollectHostInfo_HostnameError(t *testing.T) {
	t.Log("Testing CollectHostInfo handles hostname error gracefully")
	restore := saveAndRestore(t)
	defer restore()

	osHostname = func() (string, error) {
		return "", errors.New("hostname lookup failed")
	}
	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}

	c := NewCollector()
	info, err := c.CollectHostInfo(context.Background())

	if err != nil {
		t.Fatalf("CollectHostInfo() should not return error, got %v", err)
	}
	if info.Hostname != "" {
		t.Errorf("Hostname should be empty when error occurs, got %q", info.Hostname)
	}
}

func TestCollector_CollectHostInfo_NoOSRelease(t *testing.T) {
	t.Log("Testing CollectHostInfo handles missing os-release gracefully")
	restore := saveAndRestore(t)
	defer restore()

	osHostname = func() (string, error) {
		return "test-host", nil
	}
	osReadFile = func(name string) ([]byte, error) {
		if name == "/etc/os-release" {
			return nil, os.ErrNotExist
		}
		return nil, os.ErrNotExist
	}

	c := NewCollector()
	info, err := c.CollectHostInfo(context.Background())

	if err != nil {
		t.Fatalf("CollectHostInfo() should not return error, got %v", err)
	}
	if info.OSName != "" {
		t.Errorf("OSName should be empty when os-release missing, got %q", info.OSName)
	}
}

func TestCollector_CollectGPUInfo_NoNvidiaSmi(t *testing.T) {
	t.Log("Testing CollectGPUInfo returns nil when nvidia-smi not found")
	restore := saveAndRestore(t)
	defer restore()

	execLookPath = func(file string) (string, error) {
		return "", exec.ErrNotFound
	}

	c := NewCollector()
	gpus, err := c.CollectGPUInfo(context.Background())

	if err != nil {
		t.Fatalf("CollectGPUInfo() error = %v, want nil", err)
	}
	if gpus != nil {
		t.Errorf("CollectGPUInfo() = %v, want nil when nvidia-smi not found", gpus)
	}
}

func TestCollector_CollectGPUInfo_WithGPUs(t *testing.T) {
	t.Log("Testing CollectGPUInfo parses nvidia-smi output correctly")
	restore := saveAndRestore(t)
	defer restore()

	execLookPath = func(file string) (string, error) {
		return "/usr/bin/nvidia-smi", nil
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "nvidia-smi" {
			// Create a command that echoes the expected output
			return exec.Command("echo", "0, NVIDIA RTX 5080, GPU-abc123, 565.90, 16384, 45, 150.5, 30")
		}
		if name == "nvcc" {
			return exec.Command("echo", "nvcc: NVIDIA (R) Cuda compiler driver\nrelease 12.6, V12.6.77")
		}
		return exec.Command("false")
	}

	c := NewCollector()
	gpus, err := c.CollectGPUInfo(context.Background())

	if err != nil {
		t.Fatalf("CollectGPUInfo() error = %v", err)
	}
	if len(gpus) != 1 {
		t.Fatalf("CollectGPUInfo() returned %d GPUs, want 1", len(gpus))
	}
	if gpus[0].Name != "NVIDIA RTX 5080" {
		t.Errorf("GPU Name = %q, want %q", gpus[0].Name, "NVIDIA RTX 5080")
	}
	if gpus[0].UUID != "GPU-abc123" {
		t.Errorf("GPU UUID = %q, want %q", gpus[0].UUID, "GPU-abc123")
	}
	if gpus[0].DriverVersion != "565.90" {
		t.Errorf("GPU DriverVersion = %q, want %q", gpus[0].DriverVersion, "565.90")
	}
	if gpus[0].MemoryMB != 16384 {
		t.Errorf("GPU MemoryMB = %d, want %d", gpus[0].MemoryMB, 16384)
	}
	if gpus[0].TemperatureC != 45 {
		t.Errorf("GPU TemperatureC = %d, want %d", gpus[0].TemperatureC, 45)
	}
}

func TestCollector_CollectGPUInfo_ParseError(t *testing.T) {
	t.Log("Testing CollectGPUInfo handles malformed output gracefully")
	restore := saveAndRestore(t)
	defer restore()

	execLookPath = func(file string) (string, error) {
		return "/usr/bin/nvidia-smi", nil
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// Return malformed output (too few fields)
		return exec.Command("echo", "0, NVIDIA RTX 5080")
	}

	c := NewCollector()
	gpus, err := c.CollectGPUInfo(context.Background())

	if err != nil {
		t.Fatalf("CollectGPUInfo() error = %v", err)
	}
	if len(gpus) != 0 {
		t.Errorf("CollectGPUInfo() should return empty slice for malformed output, got %d GPUs", len(gpus))
	}
}

func TestCollector_CollectSecurityInfo_SecureBootEnabled(t *testing.T) {
	t.Log("Testing CollectSecurityInfo detects Secure Boot enabled")
	restore := saveAndRestore(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		if name == "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c" {
			// Secure Boot enabled: 5 bytes with last byte = 1
			return []byte{0x06, 0x00, 0x00, 0x00, 0x01}, nil
		}
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}

	c := NewCollector()
	info, err := c.CollectSecurityInfo(context.Background())

	if err != nil {
		t.Fatalf("CollectSecurityInfo() error = %v", err)
	}
	if !info.SecureBootEnabled {
		t.Error("SecureBootEnabled = false, want true")
	}
	if !info.UEFIMode {
		t.Error("UEFIMode = false, want true")
	}
}

func TestCollector_CollectSecurityInfo_NoEFI(t *testing.T) {
	t.Log("Testing CollectSecurityInfo handles non-UEFI system")
	restore := saveAndRestore(t)
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

	c := NewCollector()
	info, err := c.CollectSecurityInfo(context.Background())

	if err != nil {
		t.Fatalf("CollectSecurityInfo() error = %v", err)
	}
	if info.UEFIMode {
		t.Error("UEFIMode = true, want false for non-UEFI system")
	}
	if info.SecureBootEnabled {
		t.Error("SecureBootEnabled = true, want false for non-UEFI system")
	}
}

func TestCollector_CollectSecurityInfo_TPMPresent(t *testing.T) {
	t.Log("Testing CollectSecurityInfo detects TPM 2.0")
	restore := saveAndRestore(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		if name == "/sys/class/tpm/tpm0/tpm_version_major" {
			return []byte("2\n"), nil
		}
		return nil, os.ErrNotExist
	}
	osStat = func(name string) (os.FileInfo, error) {
		if name == "/dev/tpm0" {
			return nil, nil // exists
		}
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}

	c := NewCollector()
	info, err := c.CollectSecurityInfo(context.Background())

	if err != nil {
		t.Fatalf("CollectSecurityInfo() error = %v", err)
	}
	if !info.TPMPresent {
		t.Error("TPMPresent = false, want true")
	}
	if info.TPMVersion != "2.0" {
		t.Errorf("TPMVersion = %q, want %q", info.TPMVersion, "2.0")
	}
}

func TestCollector_CollectDPUConnections_WithRshim(t *testing.T) {
	t.Log("Testing CollectDPUConnections finds rshim devices")
	restore := saveAndRestore(t)
	defer restore()

	filepathGlob = func(pattern string) ([]string, error) {
		if pattern == "/dev/rshim*" {
			return []string{"/dev/rshim0", "/dev/rshim0boot", "/dev/rshim0misc"}, nil
		}
		if pattern == "/sys/class/infiniband/mlx5_*/device" {
			return []string{"/sys/class/infiniband/mlx5_0/device"}, nil
		}
		return nil, nil
	}
	filepathBase = func(path string) string {
		switch path {
		case "/dev/rshim0":
			return "rshim0"
		case "/dev/rshim0boot":
			return "rshim0boot"
		case "/dev/rshim0misc":
			return "rshim0misc"
		}
		return ""
	}
	osReadlink = func(name string) (string, error) {
		return "../../../0000:03:00.0", nil
	}

	c := NewCollector()
	conns, err := c.CollectDPUConnections(context.Background())

	if err != nil {
		t.Fatalf("CollectDPUConnections() error = %v", err)
	}
	// Should only return rshim0, filtering out boot and misc
	if len(conns) != 1 {
		t.Fatalf("CollectDPUConnections() returned %d connections, want 1", len(conns))
	}
	if conns[0].Name != "rshim0" {
		t.Errorf("Connection Name = %q, want %q", conns[0].Name, "rshim0")
	}
	if conns[0].RShimDevice != "/dev/rshim0" {
		t.Errorf("RShimDevice = %q, want %q", conns[0].RShimDevice, "/dev/rshim0")
	}
	if conns[0].PCIAddress != "0000:03:00.0" {
		t.Errorf("PCIAddress = %q, want %q", conns[0].PCIAddress, "0000:03:00.0")
	}
	if !conns[0].Connected {
		t.Error("Connected = false, want true")
	}
}

func TestCollector_CollectDPUConnections_NoRshim(t *testing.T) {
	t.Log("Testing CollectDPUConnections returns empty when no rshim devices")
	restore := saveAndRestore(t)
	defer restore()

	filepathGlob = func(pattern string) ([]string, error) {
		return nil, nil
	}

	c := NewCollector()
	conns, err := c.CollectDPUConnections(context.Background())

	if err != nil {
		t.Fatalf("CollectDPUConnections() error = %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("CollectDPUConnections() returned %d connections, want 0", len(conns))
	}
}

func TestCollector_getMemoryGB(t *testing.T) {
	t.Log("Testing getMemoryGB parses /proc/meminfo correctly")
	restore := saveAndRestore(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		if name == "/proc/meminfo" {
			return []byte(`MemTotal:       131926168 kB
MemFree:        65432100 kB
MemAvailable:   98765432 kB`), nil
		}
		return nil, os.ErrNotExist
	}

	c := NewCollector()
	memGB := c.getMemoryGB()

	// 131926168 KB / 1024 / 1024 = ~125 GB
	if memGB != 125 {
		t.Errorf("getMemoryGB() = %d, want %d", memGB, 125)
	}
}

func TestCollector_getUptime(t *testing.T) {
	t.Log("Testing getUptime parses /proc/uptime correctly")
	restore := saveAndRestore(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		if name == "/proc/uptime" {
			return []byte("98765.43 12345.67"), nil
		}
		return nil, os.ErrNotExist
	}

	c := NewCollector()
	uptime := c.getUptime()

	if uptime != 98765 {
		t.Errorf("getUptime() = %d, want %d", uptime, 98765)
	}
}

func TestCollector_readOSRelease(t *testing.T) {
	t.Log("Testing readOSRelease parses /etc/os-release correctly")
	restore := saveAndRestore(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		if name == "/etc/os-release" {
			return []byte(`NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04 LTS"
VERSION_ID="24.04"`), nil
		}
		return nil, os.ErrNotExist
	}

	c := NewCollector()
	release, err := c.readOSRelease()

	if err != nil {
		t.Fatalf("readOSRelease() error = %v", err)
	}
	if release["NAME"] != "Ubuntu" {
		t.Errorf("NAME = %q, want %q", release["NAME"], "Ubuntu")
	}
	if release["VERSION"] != "24.04 LTS (Noble Numbat)" {
		t.Errorf("VERSION = %q, want %q", release["VERSION"], "24.04 LTS (Noble Numbat)")
	}
	if release["ID"] != "ubuntu" {
		t.Errorf("ID = %q, want %q", release["ID"], "ubuntu")
	}
	if release["VERSION_ID"] != "24.04" {
		t.Errorf("VERSION_ID = %q, want %q", release["VERSION_ID"], "24.04")
	}
}

func TestCollector_findPCIForRShim(t *testing.T) {
	t.Log("Testing findPCIForRShim extracts PCI address from symlink")
	restore := saveAndRestore(t)
	defer restore()

	filepathGlob = func(pattern string) ([]string, error) {
		if pattern == "/sys/class/infiniband/mlx5_*/device" {
			return []string{"/sys/class/infiniband/mlx5_0/device"}, nil
		}
		return nil, nil
	}
	osReadlink = func(name string) (string, error) {
		return "../../../0000:af:00.0", nil
	}

	c := NewCollector()
	pci, err := c.findPCIForRShim("rshim0")

	if err != nil {
		t.Fatalf("findPCIForRShim() error = %v", err)
	}
	if pci != "0000:af:00.0" {
		t.Errorf("findPCIForRShim() = %q, want %q", pci, "0000:af:00.0")
	}
}

func TestCollector_findPCIForRShim_NoDevices(t *testing.T) {
	t.Log("Testing findPCIForRShim returns error when no mlx5 devices")
	restore := saveAndRestore(t)
	defer restore()

	filepathGlob = func(pattern string) ([]string, error) {
		return nil, nil
	}

	c := NewCollector()
	_, err := c.findPCIForRShim("rshim0")

	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("findPCIForRShim() error = %v, want os.ErrNotExist", err)
	}
}

func TestCollector_getTPMVersion_TPM20(t *testing.T) {
	t.Log("Testing getTPMVersion detects TPM 2.0")
	restore := saveAndRestore(t)
	defer restore()

	osStat = func(name string) (os.FileInfo, error) {
		if name == "/dev/tpm0" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	osReadFile = func(name string) ([]byte, error) {
		if name == "/sys/class/tpm/tpm0/tpm_version_major" {
			return []byte("2"), nil
		}
		return nil, os.ErrNotExist
	}

	c := NewCollector()
	version, err := c.getTPMVersion()

	if err != nil {
		t.Fatalf("getTPMVersion() error = %v", err)
	}
	if version != "2.0" {
		t.Errorf("getTPMVersion() = %q, want %q", version, "2.0")
	}
}

func TestCollector_getTPMVersion_TPM12(t *testing.T) {
	t.Log("Testing getTPMVersion detects TPM 1.2")
	restore := saveAndRestore(t)
	defer restore()

	osStat = func(name string) (os.FileInfo, error) {
		if name == "/dev/tpm" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}

	c := NewCollector()
	version, err := c.getTPMVersion()

	if err != nil {
		t.Fatalf("getTPMVersion() error = %v", err)
	}
	if version != "1.2" {
		t.Errorf("getTPMVersion() = %q, want %q", version, "1.2")
	}
}

func TestCollector_getTPMVersion_NoTPM(t *testing.T) {
	t.Log("Testing getTPMVersion returns error when no TPM present")
	restore := saveAndRestore(t)
	defer restore()

	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}

	c := NewCollector()
	_, err := c.getTPMVersion()

	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("getTPMVersion() error = %v, want os.ErrNotExist", err)
	}
}
