// Package doca provides collectors for DOCA/BlueField system information.
package doca

import (
	"bufio"
	"context"
	"regexp"
	"strconv"
	"strings"
)

// SystemInfo contains DPU hardware and software information.
type SystemInfo struct {
	Hostname        string
	Model           string
	SerialNumber    string
	FirmwareVersion string
	DOCAVersion     string
	ARMCores        int
	MemoryGB        int
	UptimeSeconds   int64
	OVSVersion      string
	KernelVersion   string
}

// SystemCollector defines the interface for system info collection.
// This allows injecting mock implementations for testing.
type SystemCollector interface {
	Collect(ctx context.Context) (*SystemInfo, error)
}

// Collector gathers system information from various sources.
type Collector struct{}

// NewCollector creates a new system info collector.
func NewCollector() *Collector {
	return &Collector{}
}

// NoOpCollector is a no-op system collector for testing.
type NoOpCollector struct{}

// NewNoOpCollector creates a no-op system collector for testing.
func NewNoOpCollector() *NoOpCollector {
	return &NoOpCollector{}
}

// Collect returns empty system info without executing any commands.
func (c *NoOpCollector) Collect(ctx context.Context) (*SystemInfo, error) {
	return &SystemInfo{Hostname: "test-host"}, nil
}

// Collect gathers all system information.
func (c *Collector) Collect(ctx context.Context) (*SystemInfo, error) {
	info := &SystemInfo{}

	// Hostname
	if hostname, err := osHostname(); err == nil {
		info.Hostname = hostname
	}

	// Kernel version
	if out, err := execCommand(ctx, "uname", "-r").Output(); err == nil {
		info.KernelVersion = strings.TrimSpace(string(out))
	}

	// DOCA version from /etc/mlnx-release
	if data, err := osReadFile("/etc/mlnx-release"); err == nil {
		info.DOCAVersion = strings.TrimSpace(string(data))
	}

	// CPU cores from /proc/cpuinfo
	if cores, err := countCPUCores(); err == nil {
		info.ARMCores = cores
	}

	// Memory from /proc/meminfo
	if memKB, err := getTotalMemoryKB(); err == nil {
		info.MemoryGB = int(memKB / 1024 / 1024)
	}

	// Uptime from /proc/uptime
	if uptime, err := getUptimeSeconds(); err == nil {
		info.UptimeSeconds = uptime
	}

	// OVS version
	if out, err := execCommand(ctx, "ovs-vsctl", "--version").Output(); err == nil {
		info.OVSVersion = parseOVSVersion(string(out))
	}

	// Model and serial from mst status
	if model, serial, err := getMSTInfo(ctx); err == nil {
		info.Model = model
		info.SerialNumber = serial
	}

	// Firmware version from mlxconfig
	if fw, err := getFirmwareVersion(ctx); err == nil {
		info.FirmwareVersion = fw
	}

	return info, nil
}

func countCPUCores() (int, error) {
	f, err := osOpen("/proc/cpuinfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "processor") {
			count++
		}
	}
	return count, scanner.Err()
}

func getTotalMemoryKB() (int64, error) {
	f, err := osOpen("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.ParseInt(fields[1], 10, 64)
			}
		}
	}
	return 0, scanner.Err()
}

func getUptimeSeconds() (int64, error) {
	data, err := osReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, nil
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	return int64(uptime), nil
}

func parseOVSVersion(output string) string {
	// Parse: "ovs-vsctl (Open vSwitch) 3.2.1005"
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 4 {
			return parts[3]
		}
	}
	return ""
}

func getMSTInfo(ctx context.Context) (model, serial string, err error) {
	out, err := execCommand(ctx, "sudo", "mst", "status").Output()
	if err != nil {
		return "", "", err
	}

	// Parse output for device info and find device path
	var devicePath string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/dev/mst/") {
			// Extract chip type from device name like mt41692
			re := regexp.MustCompile(`mt(\d+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				// Map chip ID to model name
				switch matches[1] {
				case "41692":
					model = "BlueField-3"
				case "41686":
					model = "BlueField-2"
				default:
					model = "BlueField"
				}
			}
			// Extract device path for serial lookup
			if strings.Contains(line, "pciconf") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					devicePath = fields[0]
				}
			}
		}
	}

	// Get serial (Base GUID) from flint if we have a device path
	if devicePath != "" {
		flintOut, err := execCommand(ctx, "sudo", "flint", "-d", devicePath, "q").Output()
		if err == nil {
			for _, line := range strings.Split(string(flintOut), "\n") {
				if strings.Contains(line, "Base GUID:") {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						serial = parts[2]
					}
				}
			}
		}
	}

	return model, serial, nil
}

func getFirmwareVersion(ctx context.Context) (string, error) {
	// Find MST device first (requires sudo)
	mstOut, err := execCommand(ctx, "sudo", "mst", "status").Output()
	if err != nil {
		return "", err
	}

	// Extract device path
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
		return "", nil
	}

	// Query flint for firmware version (requires sudo)
	out, err := execCommand(ctx, "sudo", "flint", "-d", devicePath, "q").Output()
	if err != nil {
		return "", err
	}

	// Parse for "FW Version:" line
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "FW Version:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", nil
}
