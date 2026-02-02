package host

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

// Package-level function variables for dependency injection in tests.
var (
	osHostname   = os.Hostname
	osReadFile   = os.ReadFile
	osStat       = os.Stat
	osReadlink   = os.Readlink
	filepathGlob = filepath.Glob
	filepathBase = filepath.Base
	execLookPath = exec.LookPath
	execCommand  = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, name, args...)
	}
)
