package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestGetServerURL_EnvVar(t *testing.T) {
	t.Log("Testing KM_SERVER env var takes precedence over flags (but triggers deprecation)")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Clear any env vars that might interfere
	os.Unsetenv("SERVER_URL")

	// Set env var
	os.Setenv("KM_SERVER", "http://env-server.example.com")
	defer os.Unsetenv("KM_SERVER")

	// Set flags to different values
	cmd.Flags().Set("server", "http://flag-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://env-server.example.com" {
		t.Errorf("Expected URL from env var 'http://env-server.example.com', got %q", url)
	}
	// KM_SERVER is now deprecated, so it should return deprecated=true
	if !deprecated {
		t.Error("Expected deprecation warning when using KM_SERVER (it's deprecated)")
	}
	t.Log("KM_SERVER correctly takes precedence over flags and triggers deprecation")
}

func TestGetServerURL_ServerURLEnvVar(t *testing.T) {
	t.Log("Testing SERVER_URL env var takes precedence over KM_SERVER")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Set both env vars
	os.Setenv("SERVER_URL", "http://server-url.example.com")
	os.Setenv("KM_SERVER", "http://km-server.example.com")
	defer func() {
		os.Unsetenv("SERVER_URL")
		os.Unsetenv("KM_SERVER")
	}()

	// Set flags to different values
	cmd.Flags().Set("server", "http://flag-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://server-url.example.com" {
		t.Errorf("Expected URL from SERVER_URL 'http://server-url.example.com', got %q", url)
	}
	if deprecated {
		t.Error("Expected no deprecation warning when using SERVER_URL env var")
	}
	t.Log("SERVER_URL correctly takes precedence over KM_SERVER")
}

func TestGetServerURL_KMServerDeprecationWarning(t *testing.T) {
	t.Log("Testing KM_SERVER triggers deprecation warning when SERVER_URL not set")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Clear SERVER_URL, set only KM_SERVER
	os.Unsetenv("SERVER_URL")
	os.Setenv("KM_SERVER", "http://km-server.example.com")
	defer os.Unsetenv("KM_SERVER")

	url, deprecated := getServerURL(&cmd)

	if url != "http://km-server.example.com" {
		t.Errorf("Expected URL from KM_SERVER 'http://km-server.example.com', got %q", url)
	}
	if !deprecated {
		t.Error("Expected deprecation warning when using KM_SERVER without SERVER_URL")
	}
	t.Log("KM_SERVER triggers deprecation warning as expected")
}

func TestGetServerURL_ServerFlag(t *testing.T) {
	t.Log("Testing --server flag works without deprecation warning")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Ensure no env var interference
	os.Unsetenv("SERVER_URL")
	os.Unsetenv("KM_SERVER")

	// Set --server flag
	cmd.Flags().Set("server", "http://my-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://my-server.example.com" {
		t.Errorf("Expected URL 'http://my-server.example.com', got %q", url)
	}
	if deprecated {
		t.Error("Expected no deprecation warning when using --server flag")
	}
	t.Log("--server flag works correctly")
}

func TestGetServerURL_ControlPlaneFlag(t *testing.T) {
	t.Log("Testing --control-plane flag returns deprecation warning")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Ensure no env var interference
	os.Unsetenv("SERVER_URL")
	os.Unsetenv("KM_SERVER")

	// Set only --control-plane flag
	cmd.Flags().Set("control-plane", "http://legacy-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://legacy-server.example.com" {
		t.Errorf("Expected URL 'http://legacy-server.example.com', got %q", url)
	}
	if !deprecated {
		t.Error("Expected deprecation warning when using --control-plane flag")
	}
	t.Log("--control-plane flag triggers deprecation warning as expected")
}

func TestGetServerURL_Default(t *testing.T) {
	t.Log("Testing default value when no env var or flags set")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Ensure no env var interference
	os.Unsetenv("SERVER_URL")
	os.Unsetenv("KM_SERVER")

	// Don't set any flags (use defaults)
	url, deprecated := getServerURL(&cmd)

	if url != "http://localhost:18080" {
		t.Errorf("Expected default URL 'http://localhost:18080', got %q", url)
	}
	if deprecated {
		t.Error("Expected no deprecation warning when using default")
	}
	t.Log("Default value returned correctly")
}

func TestGetServerURL_ServerOverridesControlPlane(t *testing.T) {
	t.Log("Testing --server flag takes precedence over --control-plane")

	// Create a new init command for testing
	cmd := *initCmd // Copy the command
	cmd.ResetFlags()
	cmd.Flags().String("server", "http://localhost:18080", "Control Plane URL")
	cmd.Flags().String("control-plane", "http://localhost:18080", "Deprecated: use --server")

	// Ensure no env var interference
	os.Unsetenv("SERVER_URL")
	os.Unsetenv("KM_SERVER")

	// Set both flags
	cmd.Flags().Set("server", "http://new-server.example.com")
	cmd.Flags().Set("control-plane", "http://old-server.example.com")

	url, deprecated := getServerURL(&cmd)

	if url != "http://new-server.example.com" {
		t.Errorf("Expected --server value 'http://new-server.example.com', got %q", url)
	}
	if deprecated {
		t.Error("Expected no deprecation warning when --server is set")
	}
	t.Log("--server correctly takes precedence over --control-plane")
}

func TestInitCmd_HasServerFlag(t *testing.T) {
	t.Log("Verifying init command has --server flag defined")

	flag := initCmd.Flags().Lookup("server")
	if flag == nil {
		t.Fatal("Expected --server flag to be defined on init command")
	}

	if flag.DefValue != "http://localhost:18080" {
		t.Errorf("Expected default value 'http://localhost:18080', got %q", flag.DefValue)
	}
	t.Log("--server flag is correctly defined")
}

func TestInitCmd_HasControlPlaneFlag(t *testing.T) {
	t.Log("Verifying init command has --control-plane flag (deprecated alias)")

	flag := initCmd.Flags().Lookup("control-plane")
	if flag == nil {
		t.Fatal("Expected --control-plane flag to be defined on init command")
	}

	if flag.DefValue != "http://localhost:18080" {
		t.Errorf("Expected default value 'http://localhost:18080', got %q", flag.DefValue)
	}
	t.Log("--control-plane flag is correctly defined")
}

func TestInitCmd_HelpShowsServer(t *testing.T) {
	t.Log("Verifying help output shows --server flag")

	var stdout bytes.Buffer
	initCmd.SetOut(&stdout)

	// Get usage string directly instead of executing
	usage := initCmd.UsageString()

	if !strings.Contains(usage, "--server") {
		t.Errorf("Expected usage output to contain '--server', got:\n%s", usage)
	}
	t.Log("Help output correctly shows --server flag")
}

func TestInitCmd_LongDescriptionMentionsEnvVar(t *testing.T) {
	t.Log("Verifying Long description mentions SERVER_URL env var as primary")

	if !strings.Contains(initCmd.Long, "SERVER_URL") {
		t.Errorf("Expected Long description to mention SERVER_URL env var, got:\n%s", initCmd.Long)
	}
	t.Log("Long description correctly mentions SERVER_URL")
}

func TestInitCmd_LongDescriptionMentionsKMServer(t *testing.T) {
	t.Log("Verifying Long description mentions KM_SERVER env var as deprecated")

	if !strings.Contains(initCmd.Long, "KM_SERVER") {
		t.Errorf("Expected Long description to mention KM_SERVER env var, got:\n%s", initCmd.Long)
	}
	t.Log("Long description correctly mentions KM_SERVER")
}

func TestInitCmd_ExampleUsesServer(t *testing.T) {
	t.Log("Verifying command example uses --server instead of --control-plane")

	// Check the Long description contains the example with --server
	if strings.Contains(initCmd.Long, "--control-plane https://") {
		t.Error("Expected examples to use --server instead of --control-plane")
	}
	if !strings.Contains(initCmd.Long, "--server https://") {
		t.Errorf("Expected Long description to have example with --server, got:\n%s", initCmd.Long)
	}
	t.Log("Examples correctly use --server")
}
