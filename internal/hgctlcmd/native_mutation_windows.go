//go:build windows

package hgctlcmd

import windowssystem "github.com/vsevo/home-gateway/internal/system/windows"

func defaultMutationBackend(root string) (windowssystem.MutationBackend, error) {
	return windowssystem.NewNativeMutationBackend(root)
}
