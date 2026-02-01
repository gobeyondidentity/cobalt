//go:build workbench

// Package workbench provides component tests that run on the Linux workbench.
// These tests validate sentry functionality in a non-VM environment with direct
// access to the DPU over TMFIFO.
//
// Run with: go test -tags=workbench -v ./test/workbench/...
//
// Prerequisites:
//   - Linux workbench (192.168.1.235 or similar)
//   - TMFIFO access to DPU (/dev/tmfifo_net0 or TCP fallback)
//   - Built sentry binary
package workbench

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Default TMFIFO address (tmfifo_net0 network interface on DPU)
const defaultTMFIFOAddr = "192.168.100.2:9444"

// getTMFIFOAddr returns the TMFIFO address from env or default.
func getTMFIFOAddr() string {
	if addr := os.Getenv("TMFIFO_ADDR"); addr != "" {
		return addr
	}
	return defaultTMFIFOAddr
}

// skipIfNotWorkbench skips the test if not running on a Linux workbench.
func skipIfNotWorkbench(t *testing.T) {
	t.Helper()

	// Check if we're on Linux
	if _, err := os.Stat("/etc/os-release"); err != nil {
		t.Skip("requires Linux workbench")
	}

	// Check for TMFIFO device or network access
	if _, err := os.Stat("/dev/tmfifo_net0"); err != nil {
		// Check if we can reach the TMFIFO network address
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "nc", "-z", "192.168.100.2", "9444")
		if err := cmd.Run(); err != nil {
			t.Skip("requires TMFIFO device or network access to DPU")
		}
	}
}

// TestCredentialInstallation verifies that credentials are properly installed.
func TestCredentialInstallation(t *testing.T) {
	skipIfNotWorkbench(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if trusted-user-ca-keys.d directory exists and has correct permissions
	caDir := "/etc/ssh/trusted-user-ca-keys.d"
	info, err := os.Stat(caDir)
	if err != nil {
		t.Logf("CA directory %s does not exist (normal if no CAs pushed yet)", caDir)
		return
	}

	if !info.IsDir() {
		t.Errorf("%s is not a directory", caDir)
		return
	}

	// Check directory permissions (should be 755 or similar)
	perm := info.Mode().Perm()
	t.Logf("CA directory permissions: %o", perm)

	// List any existing CA files
	entries, err := os.ReadDir(caDir)
	if err != nil {
		t.Errorf("Failed to read CA directory: %v", err)
		return
	}

	t.Logf("Found %d CA files in %s", len(entries), caDir)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pub") {
			t.Logf("  CA file: %s", entry.Name())

			// Verify file is a valid SSH public key
			content, err := os.ReadFile(caDir + "/" + entry.Name())
			if err != nil {
				t.Errorf("Failed to read %s: %v", entry.Name(), err)
				continue
			}

			if !strings.HasPrefix(string(content), "ssh-") && !strings.HasPrefix(string(content), "ecdsa-") {
				t.Errorf("CA file %s does not contain valid SSH public key", entry.Name())
			}
		}
	}

	_ = ctx // silence unused warning
}

// TestTransportSelection verifies transport auto-discovery works correctly.
func TestTransportSelection(t *testing.T) {
	skipIfNotWorkbench(t)

	// Test 1: Check for TMFIFO device
	hasTMFIFO := false
	if _, err := os.Stat("/dev/tmfifo_net0"); err == nil {
		hasTMFIFO = true
		t.Log("TMFIFO device available: /dev/tmfifo_net0")
	}

	// Test 2: Check for DOCA ComCh
	hasDOCA := false
	if _, err := os.Stat("/opt/mellanox/doca"); err == nil {
		hasDOCA = true
		t.Log("DOCA SDK available")
	}
	if _, err := os.Stat("/dev/infiniband"); err == nil {
		t.Log("InfiniBand device available")
	}

	// Test 3: Check TMFIFO network fallback
	hasNetwork := false
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nc", "-z", "192.168.100.2", "9444")
	if err := cmd.Run(); err == nil {
		hasNetwork = true
		t.Log("TMFIFO network fallback available (192.168.100.2:9444)")
	}

	// At least one transport should be available
	if !hasTMFIFO && !hasDOCA && !hasNetwork {
		t.Error("No transport method available")
	} else {
		t.Logf("Transport summary: TMFIFO=%v, DOCA=%v, Network=%v", hasTMFIFO, hasDOCA, hasNetwork)
	}
}

// TestPostureCollection verifies posture collection works on this host.
func TestPostureCollection(t *testing.T) {
	skipIfNotWorkbench(t)

	// Test 1: Check /proc/cpuinfo (basic system info)
	if _, err := os.Stat("/proc/cpuinfo"); err == nil {
		content, err := os.ReadFile("/proc/cpuinfo")
		if err != nil {
			t.Errorf("Failed to read /proc/cpuinfo: %v", err)
		} else {
			t.Logf("CPU info available (%d bytes)", len(content))
		}
	}

	// Test 2: Check disk encryption status
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "lsblk", "-o", "NAME,FSTYPE,MOUNTPOINT,SIZE")
	output, err := cmd.Output()
	if err != nil {
		t.Logf("lsblk failed (may require root): %v", err)
	} else {
		t.Logf("Block devices:\n%s", string(output))

		// Check for LUKS encrypted partitions
		if strings.Contains(string(output), "crypt") {
			t.Log("Encrypted partition detected")
		}
	}

	// Test 3: Check secure boot (if available)
	if _, err := os.Stat("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil {
		t.Log("Secure Boot EFI variable exists")
	} else {
		t.Log("Secure Boot EFI variable not found (may be disabled or legacy BIOS)")
	}

	// Test 4: Check firewall status
	cmd = exec.CommandContext(ctx, "iptables", "-L", "-n")
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Logf("iptables check failed (may require root): %v", err)
	} else {
		lines := strings.Count(string(output), "\n")
		t.Logf("Firewall rules: %d lines", lines)
	}
}

// TestSentryBinaryAvailable verifies sentry binary is accessible.
func TestSentryBinaryAvailable(t *testing.T) {
	skipIfNotWorkbench(t)

	// Check common sentry binary locations
	locations := []string{
		"/usr/local/bin/sentry",
		"/usr/bin/sentry",
		"./sentry",
		"./bin/sentry",
		os.Getenv("HOME") + "/sentry",
	}

	found := false
	for _, loc := range locations {
		if info, err := os.Stat(loc); err == nil && !info.IsDir() {
			if info.Mode().Perm()&0111 != 0 {
				t.Logf("Found sentry binary: %s", loc)
				found = true

				// Check version
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				cmd := exec.CommandContext(ctx, loc, "--version")
				output, err := cmd.Output()
				if err != nil {
					t.Logf("  Could not get version: %v", err)
				} else {
					t.Logf("  Version: %s", strings.TrimSpace(string(output)))
				}
			}
		}
	}

	if !found {
		t.Skip("sentry binary not found in common locations")
	}
}
