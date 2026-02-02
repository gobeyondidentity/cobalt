// Package host provides system information collection for host machines.
package host

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// HostInfo contains basic information about the host machine.
type HostInfo struct {
	Hostname      string
	OSName        string
	OSVersion     string
	KernelVersion string
	Architecture  string
	CPUCores      int
	MemoryGB      int64
	UptimeSeconds int64
}

// GPUInfo contains information about a GPU device.
type GPUInfo struct {
	Index          int
	Name           string
	UUID           string
	DriverVersion  string
	CUDAVersion    string
	MemoryMB       int64
	TemperatureC   int
	PowerUsageW    int
	UtilizationPct int
}

// SecurityInfo contains security posture information.
type SecurityInfo struct {
	SecureBootEnabled bool
	TPMPresent        bool
	TPMVersion        string
	UEFIMode          bool
	FirewallStatus    string
	SELinuxStatus     string
}

// DPUConnection contains info about a connected DPU.
type DPUConnection struct {
	Name        string
	PCIAddress  string
	RShimDevice string
	MACAddress  string
	Connected   bool
}

// Collector gathers host system information.
type Collector struct{}

// NewCollector creates a new host collector.
func NewCollector() *Collector {
	return &Collector{}
}

// CollectHostInfo gathers basic host information.
func (c *Collector) CollectHostInfo(ctx context.Context) (*HostInfo, error) {
	info := &HostInfo{
		Architecture: runtime.GOARCH,
		CPUCores:     runtime.NumCPU(),
	}

	// Hostname
	hostname, err := osHostname()
	if err == nil {
		info.Hostname = hostname
	}

	// OS info from /etc/os-release
	if osRelease, err := c.readOSRelease(); err == nil {
		info.OSName = osRelease["NAME"]
		info.OSVersion = osRelease["VERSION"]
	}

	// Kernel version
	if data, err := osReadFile("/proc/version"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			info.KernelVersion = parts[2]
		}
	}

	// Memory
	info.MemoryGB = c.getMemoryGB()

	// Uptime
	info.UptimeSeconds = c.getUptime()

	return info, nil
}

// CollectGPUInfo gathers GPU information using nvidia-smi.
func (c *Collector) CollectGPUInfo(ctx context.Context) ([]GPUInfo, error) {
	// Check if nvidia-smi exists
	if _, err := execLookPath("nvidia-smi"); err != nil {
		return nil, nil // No NVIDIA GPUs or drivers not installed
	}

	cmd := execCommand(ctx, "nvidia-smi",
		"--query-gpu=index,name,uuid,driver_version,memory.total,temperature.gpu,power.draw,utilization.gpu",
		"--format=csv,noheader,nounits")

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var gpus []GPUInfo
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ", ")
		if len(parts) < 8 {
			continue
		}

		idx, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
		memMB, _ := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
		tempC, _ := strconv.Atoi(strings.TrimSpace(parts[5]))
		powerW, _ := strconv.Atoi(strings.TrimSpace(strings.Split(parts[6], ".")[0]))
		utilPct, _ := strconv.Atoi(strings.TrimSpace(parts[7]))

		gpu := GPUInfo{
			Index:          idx,
			Name:           strings.TrimSpace(parts[1]),
			UUID:           strings.TrimSpace(parts[2]),
			DriverVersion:  strings.TrimSpace(parts[3]),
			MemoryMB:       memMB,
			TemperatureC:   tempC,
			PowerUsageW:    powerW,
			UtilizationPct: utilPct,
		}
		gpus = append(gpus, gpu)
	}

	// Get CUDA version
	if len(gpus) > 0 {
		cudaVersion := c.getCUDAVersion(ctx)
		for i := range gpus {
			gpus[i].CUDAVersion = cudaVersion
		}
	}

	return gpus, nil
}

// CollectSecurityInfo gathers security posture information.
func (c *Collector) CollectSecurityInfo(ctx context.Context) (*SecurityInfo, error) {
	info := &SecurityInfo{}

	// Check Secure Boot
	if data, err := osReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil {
		if len(data) >= 5 {
			info.SecureBootEnabled = data[4] == 1
		}
		info.UEFIMode = true
	} else if _, err := osStat("/sys/firmware/efi"); err == nil {
		info.UEFIMode = true
	}

	// Check TPM
	if tpmVersion, err := c.getTPMVersion(); err == nil {
		info.TPMPresent = true
		info.TPMVersion = tpmVersion
	}

	// Check firewall status
	info.FirewallStatus = c.getFirewallStatus(ctx)

	// Check SELinux status
	info.SELinuxStatus = c.getSELinuxStatus(ctx)

	return info, nil
}

// CollectDPUConnections finds connected DPUs via rshim devices.
func (c *Collector) CollectDPUConnections(ctx context.Context) ([]DPUConnection, error) {
	var connections []DPUConnection

	// Look for rshim devices
	matches, err := filepathGlob("/dev/rshim*")
	if err != nil {
		return nil, err
	}

	for _, rshimPath := range matches {
		if strings.Contains(rshimPath, "boot") || strings.Contains(rshimPath, "misc") {
			continue // Skip rshim sub-devices
		}

		conn := DPUConnection{
			RShimDevice: rshimPath,
			Connected:   true,
		}

		// Try to get name from rshim path
		base := filepathBase(rshimPath)
		conn.Name = base

		// Try to find PCI address
		// rshim devices are typically associated with mlx5 devices
		if pciAddr, err := c.findPCIForRShim(base); err == nil {
			conn.PCIAddress = pciAddr
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// Helper functions

func (c *Collector) readOSRelease() (map[string]string, error) {
	data, err := osReadFile("/etc/os-release")
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "="); idx > 0 {
			key := line[:idx]
			value := strings.Trim(line[idx+1:], "\"")
			result[key] = value
		}
	}
	return result, nil
}

func (c *Collector) getMemoryGB() int64 {
	data, err := osReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb / 1024 / 1024 // Convert KB to GB
			}
		}
	}
	return 0
}

func (c *Collector) getUptime() int64 {
	// Read uptime from /proc/uptime (Linux)
	data, err := osReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		uptime, _ := strconv.ParseFloat(fields[0], 64)
		return int64(uptime)
	}
	return 0
}

func (c *Collector) getCUDAVersion(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := execCommand(ctx, "nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Try nvcc for CUDA version
	nvccCmd := execCommand(ctx, "nvcc", "--version")
	nvccOutput, err := nvccCmd.Output()
	if err == nil {
		lines := strings.Split(string(nvccOutput), "\n")
		for _, line := range lines {
			if strings.Contains(line, "release") {
				parts := strings.Split(line, "release ")
				if len(parts) >= 2 {
					version := strings.Split(parts[1], ",")[0]
					return strings.TrimSpace(version)
				}
			}
		}
	}

	return strings.TrimSpace(string(output))
}

func (c *Collector) getTPMVersion() (string, error) {
	// Check TPM 2.0
	if _, err := osStat("/dev/tpm0"); err == nil {
		// Try to read TPM version from sysfs
		if data, err := osReadFile("/sys/class/tpm/tpm0/tpm_version_major"); err == nil {
			version := strings.TrimSpace(string(data))
			if version == "2" {
				return "2.0", nil
			}
			return version + ".0", nil
		}
		return "2.0", nil // Assume 2.0 if device exists
	}

	// Check TPM 1.2
	if _, err := osStat("/dev/tpm"); err == nil {
		return "1.2", nil
	}

	return "", os.ErrNotExist
}

func (c *Collector) getFirewallStatus(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Try ufw first (Ubuntu/Debian)
	if cmd := execCommand(ctx, "ufw", "status"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			if strings.Contains(string(output), "active") {
				return "active"
			}
			return "inactive"
		}
	}

	// Try firewalld (RHEL/Fedora)
	if cmd := execCommand(ctx, "firewall-cmd", "--state"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	}

	// Try iptables
	if cmd := execCommand(ctx, "iptables", "-L", "-n"); cmd != nil {
		if _, err := cmd.Output(); err == nil {
			return "iptables"
		}
	}

	return "unknown"
}

func (c *Collector) getSELinuxStatus(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Check if SELinux is available
	if _, err := osStat("/etc/selinux"); os.IsNotExist(err) {
		return "n/a"
	}

	cmd := execCommand(ctx, "getenforce")
	output, err := cmd.Output()
	if err != nil {
		return "n/a"
	}

	return strings.ToLower(strings.TrimSpace(string(output)))
}

func (c *Collector) findPCIForRShim(rshimName string) (string, error) {
	// rshim devices are numbered, try to find corresponding mlx5 device
	// This is a simplified implementation
	matches, err := filepathGlob("/sys/class/infiniband/mlx5_*/device")
	if err != nil {
		return "", err
	}

	for _, match := range matches {
		// Get the PCI address from symlink
		target, err := osReadlink(match)
		if err != nil {
			continue
		}
		// Extract PCI address from path like ../../../0000:03:00.0
		parts := strings.Split(target, "/")
		for _, part := range parts {
			if strings.Contains(part, ":") && strings.Contains(part, ".") {
				return part, nil
			}
		}
	}

	return "", os.ErrNotExist
}
