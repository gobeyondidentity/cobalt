package doca

import (
	"context"
	"os"
	"os/exec"
)

// Package-level function variables for dependency injection in tests.
var (
	osHostname = os.Hostname
	osReadFile = os.ReadFile
	osOpen     = os.Open
	osStat     = os.Stat
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, name, args...)
	}
)
