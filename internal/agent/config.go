package agent

import (
	"fmt"
	"os"
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

	// HostSSHAddr is the host SSH address for credential distribution (e.g., "192.168.1.100:22")
	HostSSHAddr string

	// HostSSHUser is the SSH user for connecting to the host (default: root)
	HostSSHUser string

	// HostSSHKeyPath is the path to the SSH private key for host authentication
	HostSSHKeyPath string
}

// DefaultConfig returns configuration with defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:  ":50051",
		BMCUser:     "root",
		HostSSHUser: "root",
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

	// Host SSH configuration from environment
	if addr := os.Getenv("HOST_SSH_ADDR"); addr != "" {
		c.HostSSHAddr = addr
	}
	if user := os.Getenv("HOST_SSH_USER"); user != "" {
		c.HostSSHUser = user
	}
	if keyPath := os.Getenv("HOST_SSH_KEY"); keyPath != "" {
		c.HostSSHKeyPath = keyPath
	}

	return nil
}

// Validate checks configuration for errors.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	return nil
}
