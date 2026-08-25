//go:build windows

package windows

import (
	"errors"

	xwindows "golang.org/x/sys/windows"
)

func resolveNativeInventoryPaths() (nativeInventoryPaths, error) {
	windowsDirectory, err := xwindows.GetWindowsDirectory()
	if err != nil {
		return nativeInventoryPaths{}, errors.New("trusted Windows directory resolution failed")
	}
	systemDirectory, err := xwindows.GetSystemDirectory()
	if err != nil {
		return nativeInventoryPaths{}, errors.New("trusted Windows system directory resolution failed")
	}
	return nativeInventoryPaths{
		WindowsDirectory: windowsDirectory,
		SystemDirectory:  systemDirectory,
	}, nil
}
