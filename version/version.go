package version

import (
	"runtime"
)

// Variables describing version and build info - these should be populated
// via build-time arguments.
var (
	BuildDate string
	Commit    string
	Tag       string
	Version   string
)

// BinVersion describes build and version information about the binary
// for the CLI.
//
// The fields for this are populated from package variables, which are
// populated from build-time arguments.
type BinVersion struct {
	Arch      string
	BuildDate string
	Commit    string
	Compiler  string
	OS        string
	Tag       string
	Version   string
}

// GetVersion gets the build and version information, populating it with
// package variables, populated via build-time arguments.
func GetVersion() BinVersion {
	return BinVersion{
		Arch:      runtime.GOARCH,
		BuildDate: BuildDate,
		Commit:    Commit,
		Compiler:  runtime.Compiler,
		OS:        runtime.GOOS,
		Tag:       Tag,
		Version:   Version,
	}
}
