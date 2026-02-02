package sentry

import (
	"fmt"
	"os"
)

// Config holds the host agent configuration.
type Config struct {
	ListenAddr string
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: ":50052",
	}
}

// LoadFromEnv loads configuration from environment variables.
func (c *Config) LoadFromEnv() error {
	if addr := os.Getenv("HOST_AGENT_LISTEN"); addr != "" {
		c.ListenAddr = addr
	}
	return nil
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	return nil
}
