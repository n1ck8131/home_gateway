//go:build windows

package apply

import (
	"os"

	xwindows "golang.org/x/sys/windows"
)

// openRegularFile permits a concurrently published atomic replacement. The
// Windows journal poller otherwise holds a handle without FILE_SHARE_DELETE,
// which can make MoveFileEx fail while Apply waits for watchdog resolution.
func openRegularFile(path string) (*os.File, error) {
	pathUTF16, err := xwindows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := xwindows.CreateFile(
		pathUTF16,
		xwindows.GENERIC_READ,
		xwindows.FILE_SHARE_READ|xwindows.FILE_SHARE_WRITE|xwindows.FILE_SHARE_DELETE,
		nil,
		xwindows.OPEN_EXISTING,
		xwindows.FILE_ATTRIBUTE_NORMAL|xwindows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
