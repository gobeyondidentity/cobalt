package cmd

import (
	"strings"
	"testing"

	"github.com/gobeyondidentity/cobalt/internal/testutil/cli"
)

func TestRootCmd_ShortContainsEmoji(t *testing.T) {
	// Cannot run in parallel - uses shared global rootCmd
	t.Log("Verifying Short description contains ice cube emoji")

	if !strings.Contains(rootCmd.Short, "🧊") {
		t.Errorf("expected Short to contain ice cube emoji, got: %s", rootCmd.Short)
	}
}

func TestRootCmd_HelpShowsSubcommands(t *testing.T) {
	// Cannot run in parallel - uses shared global rootCmd
	t.Log("Verifying help output shows available subcommands")

	result := cli.Run(rootCmd, "--help")
	result.AssertSuccess(t)

	// Should contain "Available Commands" section
	result.AssertContains(t, "Available Commands")

	// Should list at least the completion command (added in init)
	result.AssertContains(t, "completion")

	// Should list help command
	result.AssertContains(t, "help")
}

func TestRootCmd_ShortDescription(t *testing.T) {
	// Cannot run in parallel - uses shared global rootCmd
	t.Log("Verifying root command Short description contains emoji and expected text")

	expected := "🧊 Fabric Console CLI for DPU management"
	if rootCmd.Short != expected {
		t.Errorf("expected Short to be %q, got %q", expected, rootCmd.Short)
	}
}
