package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCmd_ShortContainsEmoji(t *testing.T) {
	t.Log("Verifying Short description contains ice cube emoji")

	if !strings.Contains(rootCmd.Short, "🧊") {
		t.Errorf("expected Short to contain ice cube emoji, got: %s", rootCmd.Short)
	}
}

func TestRootCmd_HelpShowsSubcommands(t *testing.T) {
	t.Log("Verifying help output shows available subcommands")

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetArgs([]string{"--help"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("help command failed: %v", err)
	}

	output := stdout.String()

	// Should contain "Available Commands" section
	if !strings.Contains(output, "Available Commands") {
		t.Errorf("expected help output to contain 'Available Commands', got:\n%s", output)
	}

	// Should list at least the completion command (added in init)
	if !strings.Contains(output, "completion") {
		t.Errorf("expected help output to list 'completion' subcommand, got:\n%s", output)
	}

	// Should list help command
	if !strings.Contains(output, "help") {
		t.Errorf("expected help output to list 'help' subcommand, got:\n%s", output)
	}
}

func TestRootCmd_ShortDescription(t *testing.T) {
	t.Log("Verifying root command Short description contains emoji and expected text")

	expected := "🧊 Fabric Console CLI for DPU management"
	if rootCmd.Short != expected {
		t.Errorf("expected Short to be %q, got %q", expected, rootCmd.Short)
	}
}
