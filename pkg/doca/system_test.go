//go:build bluefield

package doca

import (
	"context"
	"testing"
	"time"
)

// TestCollector_Collect tests system info collection on real BlueField hardware.
// Run with: go test -tags=bluefield -v ./pkg/doca/...
func TestCollector_Collect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	collector := NewCollector()
	info, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	// Verify we got basic system info
	if info.Hostname == "" {
		t.Error("Hostname should not be empty")
	}
	if info.KernelVersion == "" {
		t.Error("KernelVersion should not be empty")
	}
	if info.ARMCores == 0 {
		t.Error("ARMCores should be > 0 on BlueField")
	}
	if info.MemoryGB == 0 {
		t.Error("MemoryGB should be > 0")
	}
	if info.UptimeSeconds == 0 {
		t.Error("UptimeSeconds should be > 0")
	}

	t.Logf("System info collected:")
	t.Logf("  Hostname: %s", info.Hostname)
	t.Logf("  Model: %s", info.Model)
	t.Logf("  Serial: %s", info.SerialNumber)
	t.Logf("  Kernel: %s", info.KernelVersion)
	t.Logf("  DOCA: %s", info.DOCAVersion)
	t.Logf("  Firmware: %s", info.FirmwareVersion)
	t.Logf("  OVS: %s", info.OVSVersion)
	t.Logf("  ARM Cores: %d", info.ARMCores)
	t.Logf("  Memory: %d GB", info.MemoryGB)
	t.Logf("  Uptime: %d seconds", info.UptimeSeconds)
}
