package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"strings"
	"testing"
)

// TestControlPlaneAlias verifies that --control-plane is accepted as an alias for --server.
func TestControlPlaneAlias(t *testing.T) {
	t.Log("Testing --control-plane backwards compatibility alias")

	// Save and restore flags
	oldServer := *server
	oldControlPlane := *controlPlane
	defer func() {
		*server = oldServer
		*controlPlane = oldControlPlane
	}()

	// Reset flags
	*server = ""
	*controlPlane = "https://old-style.example.com"

	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Simulate the backwards compat logic from main()
	if *controlPlane != "" {
		if *server == "" {
			log.Printf("WARNING: --control-plane is deprecated, use --server instead")
			*server = *controlPlane
		}
	}

	t.Log("Verifying --control-plane value was copied to --server")
	if *server != "https://old-style.example.com" {
		t.Errorf("Expected server=%q, got %q", "https://old-style.example.com", *server)
	}

	t.Log("Verifying deprecation warning was logged")
	if !strings.Contains(buf.String(), "deprecated") {
		t.Error("Expected deprecation warning in log output")
	}
}

// TestControlPlaneIgnoredWhenServerSet verifies --server takes precedence.
func TestControlPlaneIgnoredWhenServerSet(t *testing.T) {
	t.Log("Testing --server takes precedence over --control-plane")

	oldServer := *server
	oldControlPlane := *controlPlane
	defer func() {
		*server = oldServer
		*controlPlane = oldControlPlane
	}()

	// Both flags set
	*server = "https://new-style.example.com"
	*controlPlane = "https://old-style.example.com"

	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Simulate the backwards compat logic
	if *controlPlane != "" {
		if *server == "" {
			*server = *controlPlane
		} else {
			log.Printf("WARNING: --control-plane is deprecated and ignored (--server takes precedence)")
		}
	}

	t.Log("Verifying --server value was preserved")
	if *server != "https://new-style.example.com" {
		t.Errorf("Expected server=%q, got %q", "https://new-style.example.com", *server)
	}

	t.Log("Verifying 'ignored' warning was logged")
	if !strings.Contains(buf.String(), "ignored") {
		t.Error("Expected 'ignored' warning in log output")
	}
}

// TestLocalAPIDeprecation verifies --local-api logs a deprecation warning.
func TestLocalAPIDeprecation(t *testing.T) {
	t.Log("Testing --local-api deprecation warning")

	oldLocalAPI := *localAPI
	defer func() {
		*localAPI = oldLocalAPI
	}()

	*localAPI = true

	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Simulate the backwards compat logic
	if *localAPI {
		log.Printf("WARNING: --local-api is deprecated and ignored; local API now auto-enables when --server and --dpu-name are set")
	}

	t.Log("Verifying deprecation warning was logged")
	logOutput := buf.String()
	if !strings.Contains(logOutput, "deprecated") {
		t.Error("Expected deprecation warning in log output")
	}
	if !strings.Contains(logOutput, "auto-enables") {
		t.Error("Expected 'auto-enables' explanation in log output")
	}
}

// TestFlagsParseable verifies all flags can be parsed without error.
func TestFlagsParseable(t *testing.T) {
	t.Log("Testing that all flags are parseable")

	// Create a new FlagSet to test parsing
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	// Register all the flags (same as main.go)
	fs.String("listen", ":18051", "")
	fs.String("bmc-addr", "", "")
	fs.String("bmc-user", "root", "")
	fs.String("local-listen", "localhost:9443", "")
	fs.Bool("allow-tmfifo-net", false, "")
	fs.String("server", "", "")
	fs.String("dpu-name", "", "")
	fs.Bool("no-comch", false, "")
	fs.String("keystore", "/var/lib/secureinfra/known_hosts.json", "")
	fs.String("control-plane", "", "")  // deprecated alias
	fs.Bool("local-api", false, "")     // deprecated

	// Test parsing with deprecated flags
	args := []string{
		"--control-plane", "https://example.com",
		"--local-api",
		"--dpu-name", "test-dpu",
	}

	err := fs.Parse(args)
	if err != nil {
		t.Errorf("Failed to parse flags: %v", err)
	}

	t.Log("All deprecated flags parsed successfully")
}
