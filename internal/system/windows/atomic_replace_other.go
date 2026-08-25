//go:build !windows

package windows

import "os"

func atomicReplaceFile(source, destination string) error {
	return os.Rename(source, destination)
}

func publishDirectory(source, destination string) error {
	return os.Rename(source, destination)
}
