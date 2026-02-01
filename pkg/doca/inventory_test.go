//go:build bluefield

package doca

import (
	"context"
	"testing"
	"time"
)

// TestInventoryCollector_Collect tests inventory collection on real BlueField hardware.
// Run with: go test -tags=bluefield -v ./pkg/doca/...
func TestInventoryCollector_Collect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	collector := NewInventoryCollector()
	inv, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	// Verify we got inventory data
	if len(inv.Firmwares) == 0 {
		t.Log("Warning: no firmware components found")
	}
	if len(inv.Packages) == 0 {
		t.Error("Packages should not be empty on a configured BlueField")
	}
	if len(inv.Modules) == 0 {
		t.Error("Modules should not be empty")
	}
	if inv.OperationMode == "" {
		t.Log("Warning: OperationMode not detected")
	}

	t.Logf("Inventory collected:")
	t.Logf("  Firmwares: %d components", len(inv.Firmwares))
	for _, fw := range inv.Firmwares {
		t.Logf("    - %s: %s", fw.Name, fw.Version)
	}
	t.Logf("  Packages: %d installed", len(inv.Packages))
	t.Logf("  Modules: %d loaded", len(inv.Modules))
	t.Logf("  Boot: UEFI=%v SecureBoot=%v Device=%s", inv.Boot.UEFIMode, inv.Boot.SecureBoot, inv.Boot.BootDevice)
	t.Logf("  OperationMode: %s", inv.OperationMode)
}
