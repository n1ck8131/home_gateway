package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const defaultLockRetryInterval = 25 * time.Millisecond

type Locker interface {
	Lock(context.Context) (func() error, error)
}

type FileLocker struct {
	Path          string
	RetryInterval time.Duration
}

func (locker FileLocker) Lock(ctx context.Context) (func() error, error) {
	if ctx == nil {
		return nil, errors.New("lock context is required")
	}
	if locker.Path == "" || !filepath.IsAbs(locker.Path) || filepath.Clean(locker.Path) != locker.Path {
		return nil, errors.New("absolute clean lock path is required")
	}
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("acquire operation lock: %w", ctx.Err())
	default:
	}
	directory := filepath.Dir(locker.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	if err := requireDirectory(directory); err != nil {
		return nil, fmt.Errorf("unsafe lock directory: %w", err)
	}
	file, err := openAdvisoryLockFile(locker.Path)
	if err != nil {
		return nil, fmt.Errorf("open operation lock: %w", err)
	}
	retry := locker.RetryInterval
	if retry <= 0 {
		retry = defaultLockRetryInterval
	}
	for {
		locked, lockErr := tryAdvisoryLock(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("acquire operation lock: %w", lockErr)
		}
		if locked {
			var once sync.Once
			var releaseErr error
			return func() error {
				once.Do(func() {
					releaseErr = errors.Join(unlockAdvisoryLock(file), file.Close())
				})
				return releaseErr
			}, nil
		}
		timer := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = file.Close()
			return nil, fmt.Errorf("acquire operation lock: %w", ctx.Err())
		case <-timer.C:
		}
	}
}
