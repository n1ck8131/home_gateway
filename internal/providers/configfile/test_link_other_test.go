//go:build !windows

package configfile

import "os"

func createTestDirectoryLink(target, link string) error {
	return os.Symlink(target, link)
}
