// Package version holds build metadata injected with -ldflags.
package version

// Version and Commit are overridden at build time:
//
//	go build -ldflags "-X mrk/dns-engine/internal/version.Version=1.0.0 -X mrk/dns-engine/internal/version.Commit=abc"
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
)

// String returns "version (commit)".
func String() string { return Version + " (" + Commit + ")" }
