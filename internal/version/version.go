// Package version provides the version string for all Secure Infrastructure binaries.
package version

// Version is the current release version.
// This is a var (not const) so ldflags -X can override it at build time.
var Version = "0.5.2"
