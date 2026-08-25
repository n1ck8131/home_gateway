//go:build !windows

package apply

import "os"

func openRegularFile(path string) (*os.File, error) {
	return os.Open(path)
}
