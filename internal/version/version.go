// Package version provides the version string for all Secure Infrastructure binaries.
package version

import "strings"

// Version is the current release version.
// This is a var (not const) so ldflags -X can override it at build time.
var Version = "dev"

// String returns the version with a single 'v' prefix for display.
// Handles cases where Version already has 'v' prefix (from git tags)
// or has no prefix (dev builds, snapshots).
func String() string {
	v := strings.TrimPrefix(Version, "v")
	return "v" + v
}
