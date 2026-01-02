package agent

import (
	"fmt"
	"os"
	"strings"
)

// Config holds agent configuration.
type Config struct {
	// ListenAddr is the gRPC listen address (e.g., ":50051")
	ListenAddr string

	// BMCAddr is the BMC address for Redfish API (optional)
	BMCAddr string

	// BMCUser is the BMC username (default: root)
	BMCUser string

	// BMCPassword is the BMC password (from environment)
	BMCPassword string

	// LocalAPIEnabled enables the local HTTP API for Host Agent communication
	LocalAPIEnabled bool

	// LocalAPIAddr is the local API listen address (e.g., "localhost:9443" or "unix:///var/run/dpu-agent.sock")
	LocalAPIAddr string

	// ControlPlaneURL is the Control Plane API endpoint for proxied requests
	ControlPlaneURL string

	// DPUName is this DPU's registered name (used for pairing with hosts)
	DPUName string

	// DPUID is this DPU's unique identifier
	DPUID string

	// DPUSerial is this DPU's serial number (for attestation binding)
	DPUSerial string

	// AllowedHostnames restricts which hostnames can register via local API (empty = allow all)
	AllowedHostnames []string
}

// DefaultConfig returns configuration with defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:   ":50051",
		BMCUser:      "root",
		LocalAPIAddr: "localhost:9443",
	}
}

// LoadFromEnv loads sensitive config from environment variables.
func (c *Config) LoadFromEnv() error {
	// BMC password from environment (never from CLI flags)
	if c.BMCAddr != "" {
		c.BMCPassword = os.Getenv("FC_BMC_PASSWORD")
		if c.BMCPassword == "" {
			return fmt.Errorf("FC_BMC_PASSWORD environment variable required when --bmc-addr is set")
		}
	}

	// Local API configuration from environment
	if url := os.Getenv("CONTROL_PLANE_URL"); url != "" {
		c.ControlPlaneURL = url
	}
	if name := os.Getenv("DPU_NAME"); name != "" {
		c.DPUName = name
	}
	if id := os.Getenv("DPU_ID"); id != "" {
		c.DPUID = id
	}
	if serial := os.Getenv("DPU_SERIAL"); serial != "" {
		c.DPUSerial = serial
	}
	if hosts := os.Getenv("ALLOWED_HOSTNAMES"); hosts != "" {
		c.AllowedHostnames = strings.Split(hosts, ",")
	}

	return nil
}

// Validate checks configuration for errors.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}

	// Validate local API configuration if enabled
	if c.LocalAPIEnabled {
		if c.ControlPlaneURL == "" {
			return fmt.Errorf("control plane URL is required when local API is enabled")
		}
		if c.DPUName == "" {
			return fmt.Errorf("DPU name is required when local API is enabled")
		}
	}

	return nil
}
