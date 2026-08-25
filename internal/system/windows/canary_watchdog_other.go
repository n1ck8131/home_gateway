//go:build !windows

package windows

import (
	"errors"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
)

func newDefaultCanaryWatchdog(string) (apply.Watchdog, error) {
	return nil, errors.New("durable P3.5 watchdog requires Windows")
}

func DisarmProductionCanaryWatchdog(string) error {
	return errors.New("durable P3.5 watchdog requires Windows")
}
