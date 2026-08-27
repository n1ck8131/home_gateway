//go:build windows

package configfile

import "os/exec"

func createTestDirectoryLink(target, link string) error {
	return exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).Run()
}
