//go:build !windows

package redshield

import "os"

func createTestDirectoryLink(target, link string) error {
	return os.Symlink(target, link)
}
