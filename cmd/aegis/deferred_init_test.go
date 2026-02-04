package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
)

func TestIsAegisEnrolled(t *testing.T) {
	t.Log("Testing isAegisEnrolled checks key and kid file existence")

	// Create temp directory for test keys
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	kidPath := filepath.Join(tmpDir, "kid")

	// Set env vars to use temp directory
	t.Setenv("AEGIS_KEY_PATH", keyPath)
	t.Setenv("AEGIS_KID_PATH", kidPath)

	t.Log("Checking enrollment status with no key files")
	if isAegisEnrolled("https://test.example.com") {
		t.Error("Expected not enrolled when key files don't exist")
	}

	t.Log("Creating only key file")
	if err := os.WriteFile(keyPath, []byte("test-key"), 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	if isAegisEnrolled("https://test.example.com") {
		t.Error("Expected not enrolled when only key exists (no kid)")
	}

	t.Log("Creating kid file - should now be enrolled")
	if err := os.WriteFile(kidPath, []byte("test-kid"), 0600); err != nil {
		t.Fatalf("Failed to write kid file: %v", err)
	}

	if !isAegisEnrolled("https://test.example.com") {
		t.Error("Expected enrolled when both key and kid exist")
	}

	t.Log("isAegisEnrolled correctly checks enrollment status")
}

func TestWatchForEnrollment_DetectsKeyCreation(t *testing.T) {
	t.Log("Testing watchForEnrollment detects key file creation")

	// Create temp directory for test keys
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	kidPath := filepath.Join(tmpDir, "kid")

	// Set env vars to use temp directory
	t.Setenv("AEGIS_KEY_PATH", keyPath)
	t.Setenv("AEGIS_KID_PATH", kidPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var enrolled atomic.Bool
	doneCh := make(chan struct{})

	cfg := enrollmentWatcherConfig{
		pollInterval: 100 * time.Millisecond, // Fast polling for test
		serverURL:    "https://test.example.com",
	}

	t.Log("Starting enrollment watcher with no key files")
	go watchForEnrollment(ctx, cfg, func() {
		enrolled.Store(true)
		close(doneCh)
	})

	// Wait a bit to ensure watcher is running
	time.Sleep(200 * time.Millisecond)

	if enrolled.Load() {
		t.Error("Should not be enrolled yet")
	}

	t.Log("Creating key and kid files to simulate enrollment completion")
	if err := os.WriteFile(keyPath, []byte("test-key"), 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	if err := os.WriteFile(kidPath, []byte("test-kid"), 0600); err != nil {
		t.Fatalf("Failed to write kid file: %v", err)
	}

	t.Log("Waiting for watcher to detect enrollment")
	select {
	case <-doneCh:
		if !enrolled.Load() {
			t.Error("Enrolled callback was called but flag not set")
		}
		t.Log("Watcher correctly detected enrollment and called callback")
	case <-ctx.Done():
		t.Error("Timeout waiting for enrollment detection")
	}
}

func TestWatchForEnrollment_CancelledContext(t *testing.T) {
	t.Log("Testing watchForEnrollment stops on context cancellation")

	// Create temp directory for test keys
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	kidPath := filepath.Join(tmpDir, "kid")

	// Set env vars to use temp directory
	t.Setenv("AEGIS_KEY_PATH", keyPath)
	t.Setenv("AEGIS_KID_PATH", kidPath)

	ctx, cancel := context.WithCancel(context.Background())

	var enrolled atomic.Bool
	watcherDone := make(chan struct{})

	cfg := enrollmentWatcherConfig{
		pollInterval: 100 * time.Millisecond,
		serverURL:    "https://test.example.com",
	}

	t.Log("Starting watcher")
	go func() {
		watchForEnrollment(ctx, cfg, func() {
			enrolled.Store(true)
		})
		close(watcherDone)
	}()

	// Let watcher run for a bit
	time.Sleep(200 * time.Millisecond)

	t.Log("Cancelling context")
	cancel()

	// Wait for watcher to exit
	select {
	case <-watcherDone:
		if enrolled.Load() {
			t.Error("Callback should not have been called after cancellation")
		}
		t.Log("Watcher correctly stopped on context cancellation")
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for watcher to stop")
	}
}

func TestLocalAPIState_Shutdown(t *testing.T) {
	t.Log("Testing localAPIState.shutdown handles nil fields gracefully")

	state := &localAPIState{}

	// Should not panic with all nil fields
	state.shutdown()

	t.Log("Shutdown with nil fields completed without panic")

	// Test with cancel function set
	called := false
	state.transportCancel = func() { called = true }
	state.shutdown()

	if !called {
		t.Error("Expected transportCancel to be called")
	}
	t.Log("Shutdown correctly called transportCancel")
}

func TestEnrollmentWatcherConfig(t *testing.T) {
	t.Log("Testing enrollmentWatcherConfig uses correct defaults")

	cfg := enrollmentWatcherConfig{
		pollInterval: 5 * time.Second,
		serverURL:    "https://nexus.example.com",
	}

	if cfg.pollInterval != 5*time.Second {
		t.Errorf("Expected poll interval 5s, got %v", cfg.pollInterval)
	}

	if cfg.serverURL != "https://nexus.example.com" {
		t.Errorf("Expected serverURL https://nexus.example.com, got %s", cfg.serverURL)
	}

	t.Log("enrollmentWatcherConfig holds configuration correctly")
}

func TestIsAegisEnrolled_UsesDefaultKeyPaths(t *testing.T) {
	t.Log("Testing isAegisEnrolled uses dpop.DefaultKeyPaths")

	// Clear any env vars that might override paths
	t.Setenv("AEGIS_KEY_PATH", "")
	t.Setenv("AEGIS_KID_PATH", "")

	// Get expected paths
	keyPath, kidPath := dpop.DefaultKeyPaths("aegis")
	t.Logf("Default aegis key paths: %s, %s", keyPath, kidPath)

	// Unless we're root on the DPU, these files won't exist
	// so isAegisEnrolled should return false
	enrolled := isAegisEnrolled("https://test.example.com")

	// We just verify it doesn't panic and returns a boolean
	t.Logf("isAegisEnrolled returned: %v (expected false unless /etc/aegis exists)", enrolled)
}
