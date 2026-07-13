package apply

import (
	"errors"
	"sync"
	"time"
)

type Watchdog interface {
	Arm(time.Time, func()) (func(), error)
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
