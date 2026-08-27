//go:build windows

package configfile

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateWindowsConfigVolumeClassifiesDriveRoot(t *testing.T) {
	tests := []struct {
		name      string
		driveType uint32
		wantError bool
	}{
		{name: "remote", driveType: windows.DRIVE_REMOTE, wantError: true},
		{name: "unknown", driveType: windows.DRIVE_UNKNOWN, wantError: true},
		{name: "missing root", driveType: windows.DRIVE_NO_ROOT_DIR, wantError: true},
		{name: "unexpected", driveType: 99, wantError: true},
		{name: "removable", driveType: windows.DRIVE_REMOVABLE},
		{name: "fixed", driveType: windows.DRIVE_FIXED},
		{name: "optical", driveType: windows.DRIVE_CDROM},
		{name: "RAM disk", driveType: windows.DRIVE_RAMDISK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var classifiedRoot string
			err := validateWindowsConfigVolume(`Z:\configs\provider.conf`, func(root string) uint32 {
				classifiedRoot = root
				return test.driveType
			})
			if classifiedRoot != `Z:\` {
				t.Fatalf("classified root = %q", classifiedRoot)
			}
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError = %t", err, test.wantError)
			}
		})
	}
}

func TestValidateLocalConfigVolumeAcceptsCurrentLocalDrive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.conf")
	if err := validateLocalConfigVolume(path); err != nil {
		t.Fatalf("current local drive rejected: %v", err)
	}
}
