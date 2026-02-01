package doca

import (
	"context"
	"testing"
)

// TestNoOpCollector_Collect verifies the no-op system collector works.
func TestNoOpCollector_Collect(t *testing.T) {
	collector := NewNoOpCollector()
	info, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("NoOpCollector.Collect() error: %v", err)
	}
	if info == nil {
		t.Fatal("NoOpCollector.Collect() returned nil")
	}
	if info.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", info.Hostname, "test-host")
	}
}

// TestNoOpInventoryCollector_Collect verifies the no-op inventory collector works.
func TestNoOpInventoryCollector_Collect(t *testing.T) {
	collector := NewNoOpInventoryCollector()
	inv, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("NoOpInventoryCollector.Collect() error: %v", err)
	}
	if inv == nil {
		t.Fatal("NoOpInventoryCollector.Collect() returned nil")
	}
	if inv.OperationMode != "test" {
		t.Errorf("OperationMode = %q, want %q", inv.OperationMode, "test")
	}
}
