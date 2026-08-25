//go:build !windows

package hgctlcmd

import (
	"errors"

	windowssystem "github.com/vsevo/home-gateway/internal/system/windows"
)

func defaultMutationBackend(string) (windowssystem.MutationBackend, error) {
	return nil, errors.New("native Windows mutation is unavailable on this operating system")
}
