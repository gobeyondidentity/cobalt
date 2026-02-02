//go:build integration
// +build integration

package integration

import (
	"context"
	"strings"
	"testing"
)

// TestVMsRunning verifies all VMs are accessible
func TestVMsRunning(t *testing.T) {
	cfg := newTestConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.CommandTimeout)
	defer cancel()

	vms := []string{cfg.ServerVM, cfg.DPUVM, cfg.HostVM}
	for _, vm := range vms {
		vm := vm // capture range variable
		t.Run(vm, func(t *testing.T) {
			output, err := cfg.multipassExec(ctx, vm, "echo", "ok")
			if err != nil {
				t.Fatalf("VM %s not accessible: %v", vm, err)
			}
			if !strings.Contains(output, "ok") {
				t.Fatalf("VM %s unexpected output: %s", vm, output)
			}
		})
	}
}
