//go:build windows

package apply

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	xwindows "golang.org/x/sys/windows"
)

const replaceFileBackupSuffix = ".routerd.replace-backup"

var replaceFileW = xwindows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

// recoverRegularFileForRead repairs the only crash state in which no
// destination is visible but ReplaceFileW's durable backup is present. A
// malformed backup is never treated as an absent logical record.
func recoverRegularFileForRead(destination string) error {
	backup := destination + replaceFileBackupSuffix
	backupInfo, backupErr := os.Lstat(backup)
	if errors.Is(backupErr, os.ErrNotExist) {
		return nil
	}
	if backupErr != nil {
		return backupErr
	}
	if !backupInfo.Mode().IsRegular() || backupInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("atomic replacement backup is not a regular file")
	}
	destinationInfo, destinationErr := os.Lstat(destination)
	if destinationErr == nil {
		if !destinationInfo.Mode().IsRegular() || destinationInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("atomic replacement destination is not a regular file")
		}
		return nil
	}
	if !errors.Is(destinationErr, os.ErrNotExist) {
		return destinationErr
	}
	return moveFileWriteThrough(backup, destination)
}

// atomicReplaceFile publishes a fully synced temporary file while readers hold
// FILE_SHARE_DELETE handles. ReplaceFileW is the Windows replacement primitive
// designed for that case; MoveFileEx(REPLACE_EXISTING) can still fail with
// ERROR_ACCESS_DENIED even when the reader requested delete sharing.
func atomicReplaceFile(source, destination string) error {
	backup := destination + replaceFileBackupSuffix
	if err := recoverReplaceBackup(destination, backup); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); errors.Is(err, os.ErrNotExist) {
		return moveFileWriteThrough(source, destination)
	} else if err != nil {
		return err
	}

	replaced, err := xwindows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	replacement, err := xwindows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	backupPath, err := xwindows.UTF16PtrFromString(backup)
	if err != nil {
		return err
	}
	result, _, callErr := replaceFileW.Call(
		// #nosec G103 -- UTF-16 pointers are allocated by x/sys/windows and kept alive after the syscall.
		uintptr(unsafe.Pointer(replaced)),
		// #nosec G103 -- UTF-16 pointers are allocated by x/sys/windows and kept alive after the syscall.
		uintptr(unsafe.Pointer(replacement)),
		// #nosec G103 -- UTF-16 pointers are allocated by x/sys/windows and kept alive after the syscall.
		uintptr(unsafe.Pointer(backupPath)),
		0,
		0,
		0,
	)
	runtime.KeepAlive(replaced)
	runtime.KeepAlive(replacement)
	runtime.KeepAlive(backupPath)
	if result == 0 {
		if restoreErr := restoreReplaceFailure(destination, backup); restoreErr != nil {
			return errors.Join(normalizeWindowsCallError(callErr), restoreErr)
		}
		return normalizeWindowsCallError(callErr)
	}
	// The destination is already the new, complete file. Backup cleanup is
	// best-effort and idempotently retried by recoverReplaceBackup on the next
	// publication; reporting failure here would invite a duplicate mutation.
	_ = os.Remove(backup)
	return nil
}

func recoverReplaceBackup(destination, backup string) error {
	info, err := os.Lstat(backup)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("atomic replacement backup is not a regular file")
	}
	if _, err := os.Lstat(destination); errors.Is(err, os.ErrNotExist) {
		return moveFileWriteThrough(backup, destination)
	} else if err != nil {
		return err
	}
	return os.Remove(backup)
}

func restoreReplaceFailure(destination, backup string) error {
	if _, err := os.Lstat(destination); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(backup); err != nil {
		return errors.New("atomic replacement failed without a recoverable destination")
	}
	return moveFileWriteThrough(backup, destination)
}

func moveFileWriteThrough(source, destination string) error {
	from, err := xwindows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := xwindows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return xwindows.MoveFileEx(from, to, xwindows.MOVEFILE_WRITE_THROUGH)
}

func normalizeWindowsCallError(err error) error {
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New("ReplaceFileW failed")
	}
	if err == nil {
		return errors.New("ReplaceFileW failed")
	}
	return err
}
