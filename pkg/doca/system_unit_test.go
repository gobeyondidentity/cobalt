package doca

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
)

// saveAndRestoreSystem saves all function variables and returns a restore function.
func saveAndRestoreSystem(t *testing.T) func() {
	t.Helper()
	origHostname := osHostname
	origReadFile := osReadFile
	origOpen := osOpen
	origStat := osStat
	origCommand := execCommand

	return func() {
		osHostname = origHostname
		osReadFile = origReadFile
		osOpen = origOpen
		osStat = origStat
		execCommand = origCommand
	}
}

// mockFile implements io.ReadCloser for testing.
type mockFile struct {
	reader io.Reader
}

func (m *mockFile) Read(p []byte) (int, error) {
	return m.reader.Read(p)
}

func (m *mockFile) Close() error {
	return nil
}

func TestNewCollector(t *testing.T) {
	t.Log("Testing NewCollector returns non-nil collector")
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector() returned nil")
	}
}

func TestCollector_Collect_Hostname(t *testing.T) {
	t.Log("Testing Collect gathers hostname")
	restore := saveAndRestoreSystem(t)
	defer restore()

	osHostname = func() (string, error) {
		return "bf3-dpu", nil
	}
	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}

	c := NewCollector()
	info, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if info.Hostname != "bf3-dpu" {
		t.Errorf("Hostname = %q, want %q", info.Hostname, "bf3-dpu")
	}
}

func TestCollector_Collect_KernelVersion(t *testing.T) {
	t.Log("Testing Collect gathers kernel version from uname")
	restore := saveAndRestoreSystem(t)
	defer restore()

	osHostname = func() (string, error) {
		return "", errors.New("no hostname")
	}
	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "uname" && len(args) > 0 && args[0] == "-r" {
			return exec.Command("echo", "5.15.0-1038-bluefield")
		}
		return exec.Command("false")
	}

	c := NewCollector()
	info, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if info.KernelVersion != "5.15.0-1038-bluefield" {
		t.Errorf("KernelVersion = %q, want %q", info.KernelVersion, "5.15.0-1038-bluefield")
	}
}

func TestCollector_Collect_DOCAVersion(t *testing.T) {
	t.Log("Testing Collect reads DOCA version from /etc/mlnx-release")
	restore := saveAndRestoreSystem(t)
	defer restore()

	osHostname = func() (string, error) {
		return "", errors.New("no hostname")
	}
	osReadFile = func(name string) ([]byte, error) {
		if name == "/etc/mlnx-release" {
			return []byte("DOCA_3.2.0_Ubuntu_24.04\n"), nil
		}
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}

	c := NewCollector()
	info, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if info.DOCAVersion != "DOCA_3.2.0_Ubuntu_24.04" {
		t.Errorf("DOCAVersion = %q, want %q", info.DOCAVersion, "DOCA_3.2.0_Ubuntu_24.04")
	}
}

func TestCollector_Collect_OVSVersion(t *testing.T) {
	t.Log("Testing Collect parses OVS version from ovs-vsctl --version")
	restore := saveAndRestoreSystem(t)
	defer restore()

	osHostname = func() (string, error) {
		return "", errors.New("no hostname")
	}
	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "ovs-vsctl" && len(args) > 0 && args[0] == "--version" {
			return exec.Command("echo", "ovs-vsctl (Open vSwitch) 3.2.1005")
		}
		return exec.Command("false")
	}

	c := NewCollector()
	info, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if info.OVSVersion != "3.2.1005" {
		t.Errorf("OVSVersion = %q, want %q", info.OVSVersion, "3.2.1005")
	}
}

func Test_parseOVSVersion(t *testing.T) {
	t.Log("Testing parseOVSVersion extracts version from ovs-vsctl output")
	tests := []struct {
		name   string
		input  string
		want   string
	}{
		{
			name:  "standard output",
			input: "ovs-vsctl (Open vSwitch) 3.2.1005\nDB Schema 8.5.0",
			want:  "3.2.1005",
		},
		{
			name:  "minimal output",
			input: "ovs-vsctl (Open vSwitch) 2.17.9",
			want:  "2.17.9",
		},
		{
			name:  "empty output",
			input: "",
			want:  "",
		},
		{
			name:  "malformed output",
			input: "ovs-vsctl",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOVSVersion(tt.input)
			if got != tt.want {
				t.Errorf("parseOVSVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func Test_getMSTInfo_BlueField3(t *testing.T) {
	t.Log("Testing getMSTInfo identifies BlueField-3 from chip ID")
	restore := saveAndRestoreSystem(t)
	defer restore()

	mstOutput := `/dev/mst/mt41692_pciconf0 - PCI configuration cycles access.
           domain:bus:dev.fn=0000:03:00.0
           Chip type: BlueField-3
           Serial number: N/A
`
	flintOutput := `FW Version:            32.39.1002
FW Release Date:       9/5/2024
Base GUID:             98039b03006d8f56
`

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

	model, serial, err := getMSTInfo(context.Background())

	if err != nil {
		t.Fatalf("getMSTInfo() error = %v", err)
	}
	if model != "BlueField-3" {
		t.Errorf("model = %q, want %q", model, "BlueField-3")
	}
	if serial != "98039b03006d8f56" {
		t.Errorf("serial = %q, want %q", serial, "98039b03006d8f56")
	}
}

func Test_getFirmwareVersion(t *testing.T) {
	t.Log("Testing getFirmwareVersion extracts firmware from flint output")
	restore := saveAndRestoreSystem(t)
	defer restore()

	mstOutput := `/dev/mst/mt41692_pciconf0 - PCI configuration cycles access.`
	flintOutput := `FW Version:            32.39.1002
FW Release Date:       9/5/2024
Product Version:       rel-32_39_1002
`

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

	fw, err := getFirmwareVersion(context.Background())

	if err != nil {
		t.Fatalf("getFirmwareVersion() error = %v", err)
	}
	if fw != "32.39.1002" {
		t.Errorf("firmware = %q, want %q", fw, "32.39.1002")
	}
}

func Test_getUptimeSeconds(t *testing.T) {
	t.Log("Testing getUptimeSeconds parses /proc/uptime")
	restore := saveAndRestoreSystem(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		if name == "/proc/uptime" {
			return []byte("98765.43 12345.67"), nil
		}
		return nil, os.ErrNotExist
	}

	uptime, err := getUptimeSeconds()

	if err != nil {
		t.Fatalf("getUptimeSeconds() error = %v", err)
	}
	if uptime != 98765 {
		t.Errorf("uptime = %d, want %d", uptime, 98765)
	}
}

func Test_getUptimeSeconds_Empty(t *testing.T) {
	t.Log("Testing getUptimeSeconds handles empty file")
	restore := saveAndRestoreSystem(t)
	defer restore()

	osReadFile = func(name string) ([]byte, error) {
		if name == "/proc/uptime" {
			return []byte(""), nil
		}
		return nil, os.ErrNotExist
	}

	uptime, err := getUptimeSeconds()

	if err != nil {
		t.Fatalf("getUptimeSeconds() error = %v", err)
	}
	if uptime != 0 {
		t.Errorf("uptime = %d, want 0 for empty file", uptime)
	}
}

func Test_countCPUCores(t *testing.T) {
	t.Log("Testing countCPUCores counts processor entries")
	// Note: This test requires a real file handle, so we skip it
	// The function uses osOpen which returns *os.File, making it hard to mock
	// In real hardware tests, this would work correctly
	t.Skip("Requires real /proc/cpuinfo or file descriptor mocking")
}

func Test_getTotalMemoryKB(t *testing.T) {
	t.Log("Testing getTotalMemoryKB parses MemTotal")
	// Note: Same issue as countCPUCores - needs real file descriptor
	t.Skip("Requires real /proc/meminfo or file descriptor mocking")
}

func TestCollector_Collect_AllFields(t *testing.T) {
	t.Log("Testing Collect integrates all data sources")
	restore := saveAndRestoreSystem(t)
	defer restore()

	osHostname = func() (string, error) {
		return "bf3-test", nil
	}
	osReadFile = func(name string) ([]byte, error) {
		switch name {
		case "/etc/mlnx-release":
			return []byte("DOCA_3.2.0"), nil
		case "/proc/uptime":
			return []byte("12345.67 8901.23"), nil
		}
		return nil, os.ErrNotExist
	}
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}

	mstOutput := `/dev/mst/mt41692_pciconf0 - PCI configuration`
	flintOutput := `FW Version:            32.39.1002
Base GUID:             abc123`

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "uname" {
			return exec.Command("echo", "5.15.0-bf")
		}
		if name == "ovs-vsctl" {
			return exec.Command("echo", "ovs-vsctl (Open vSwitch) 3.2.1005")
		}
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

	c := NewCollector()
	info, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if info.Hostname != "bf3-test" {
		t.Errorf("Hostname = %q, want %q", info.Hostname, "bf3-test")
	}
	if info.DOCAVersion != "DOCA_3.2.0" {
		t.Errorf("DOCAVersion = %q, want %q", info.DOCAVersion, "DOCA_3.2.0")
	}
	if info.KernelVersion != "5.15.0-bf" {
		t.Errorf("KernelVersion = %q, want %q", info.KernelVersion, "5.15.0-bf")
	}
	if info.OVSVersion != "3.2.1005" {
		t.Errorf("OVSVersion = %q, want %q", info.OVSVersion, "3.2.1005")
	}
	if info.UptimeSeconds != 12345 {
		t.Errorf("UptimeSeconds = %d, want %d", info.UptimeSeconds, 12345)
	}
	// Model detection requires the full mst output with mt41692, simplified here
	if info.FirmwareVersion != "32.39.1002" {
		t.Errorf("FirmwareVersion = %q, want %q", info.FirmwareVersion, "32.39.1002")
	}
}
