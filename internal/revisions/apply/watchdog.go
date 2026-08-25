package apply

import (
	"errors"
	"sync"
	"time"
)

type Watchdog interface {
	Arm(time.Time, func()) (func(), error)
}

// PersistentWatchdog is implemented by watchdogs whose rollback and committed
// startup-reconcile triggers survive the current process. Commit and Disarm
// must be idempotent because confirmation and recovery can happen in a
// different process than Apply.
type PersistentWatchdog interface {
	Watchdog
	Commit() error
	Disarm() error
}

type TimerWatchdog struct{}

func (TimerWatchdog) Arm(deadline time.Time, action func()) (func(), error) {
	if deadline.IsZero() {
		return nil, errors.New("watchdog deadline is required")
	}
	if action == nil {
		return nil, errors.New("watchdog action is required")
	}
	delay := time.Until(deadline)
	if delay < 0 {
		delay = 0
	}
	timer := time.AfterFunc(delay, action)
	var once sync.Once
	return func() {
		once.Do(func() {
			timer.Stop()
		})
	}, nil
}
