//go:build !windows

package apply

import "os"

func recoverRegularFileForRead(string) error {
	return nil
}

func atomicReplaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
