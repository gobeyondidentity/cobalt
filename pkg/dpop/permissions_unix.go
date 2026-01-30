//go:build unix

package dpop

import (
	"fmt"
	"os"
)

// checkFilePermissions verifies a file has owner-only access (0600 on Unix).
// Returns ErrInvalidPermissions if the file is accessible to others.
func checkFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		return fmt.Errorf("%w: got %04o, want 0600", ErrInvalidPermissions, mode)
	}
	return nil
}

// setFilePermissions sets owner-only access (0600 on Unix).
func setFilePermissions(path string) error {
	return os.Chmod(path, 0600)
}
