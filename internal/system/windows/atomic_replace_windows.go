//go:build windows

package windows

import "golang.org/x/sys/windows"

func atomicReplaceFile(source, destination string) error {
	return moveFile(source, destination, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func publishDirectory(source, destination string) error {
	return moveFile(source, destination, windows.MOVEFILE_WRITE_THROUGH)
}

func moveFile(source, destination string, flags uint32) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, flags)
}
