//go:build !linux && !windows

package apply

import (
	"errors"
	"os"
)

func openAdvisoryLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}

func tryAdvisoryLock(*os.File) (bool, error) {
	return false, errors.New("advisory operation locks are supported only on Linux and Windows")
}

func unlockAdvisoryLock(*os.File) error { return nil }
