//go:build !windows

package windows

import "errors"

func resolveNativeInventoryPaths() (nativeInventoryPaths, error) {
	return nativeInventoryPaths{}, errors.New("native Windows inventory is unavailable on this operating system")
}
