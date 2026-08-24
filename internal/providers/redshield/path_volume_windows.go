//go:build windows

package redshield

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type driveTypeClassifier func(root string) uint32

func validateLocalConfigVolume(path string) error {
	return validateWindowsConfigVolume(path, classifyWindowsDrive)
}

func validateWindowsConfigVolume(path string, classify driveTypeClassifier) error {
	volume := filepath.VolumeName(filepath.Clean(path))
	if len(volume) != 2 || volume[1] != ':' {
		return errors.New("config source must use a local volume")
	}
	driveType := classify(volume + `\`)
	switch driveType {
	case windows.DRIVE_REMOVABLE, windows.DRIVE_FIXED, windows.DRIVE_CDROM, windows.DRIVE_RAMDISK:
		return nil
	default:
		return errors.New("config source must use a local volume")
	}
}

func classifyWindowsDrive(root string) uint32 {
	rootPointer, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return windows.DRIVE_UNKNOWN
	}
	return windows.GetDriveType(rootPointer)
}
