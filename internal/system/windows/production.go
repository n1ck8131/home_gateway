package windows

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
)

const (
	DefaultCanaryConfirmTimeout  = 2 * time.Minute
	DefaultCanaryRecoveryTimeout = 30 * time.Second
	maxCanaryConfirmTimeout      = 10 * time.Minute
)

type CanaryRuntimeConfig struct {
	Root               string
	Backend            MutationBackend
	QualifiedEndpoints []string
	RecoveryOnly       bool
	ConfirmTimeout     time.Duration
	RecoveryTimeout    time.Duration
	Watchdog           apply.Watchdog
}

func NewCanaryTransaction(config CanaryRuntimeConfig) (*apply.Transaction, error) {
	if config.Root == "" || !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || filepath.Dir(config.Root) == config.Root || strings.ContainsRune(config.Root, '\x00') {
		return nil, errors.New("canary state root must be an absolute clean non-volume-root path")
	}
	if config.ConfirmTimeout == 0 {
		config.ConfirmTimeout = DefaultCanaryConfirmTimeout
	}
	if config.RecoveryTimeout == 0 {
		config.RecoveryTimeout = DefaultCanaryRecoveryTimeout
	}
	if config.ConfirmTimeout < time.Second || config.ConfirmTimeout > maxCanaryConfirmTimeout {
		return nil, errors.New("canary confirmation timeout must be between 1 second and 10 minutes")
	}
	if config.RecoveryTimeout < time.Second || config.RecoveryTimeout > config.ConfirmTimeout {
		return nil, errors.New("canary recovery timeout must be between 1 second and the confirmation timeout")
	}
	runtime := &Runtime{
		Root:               config.Root,
		Backend:            config.Backend,
		QualifiedEndpoints: append([]string(nil), config.QualifiedEndpoints...),
		recoveryOnly:       config.RecoveryOnly,
	}
	if err := runtime.validateConfiguration(); err != nil {
		return nil, err
	}
	watchdog := config.Watchdog
	if watchdog == nil {
		var err error
		watchdog, err = newDefaultCanaryWatchdog(config.Root)
		if err != nil {
			return nil, err
		}
	}
	return &apply.Transaction{
		Runtime:         runtime,
		Journal:         apply.FileJournal{Path: filepath.Join(config.Root, "journal.json")},
		Locker:          apply.FileLocker{Path: filepath.Join(config.Root, "operation.lock")},
		Watchdog:        watchdog,
		ConfirmTimeout:  config.ConfirmTimeout,
		RecoveryTimeout: config.RecoveryTimeout,
		RecoveryOnly:    config.RecoveryOnly,
	}, nil
}
