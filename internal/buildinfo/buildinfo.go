package buildinfo

import "runtime"

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func Current(program string) map[string]string {
	return map[string]string{
		"program":    program,
		"version":    Version,
		"commit":     Commit,
		"build_date": BuildDate,
		"go_version": runtime.Version(),
		"goos":       runtime.GOOS,
		"goarch":     runtime.GOARCH,
	}
}
