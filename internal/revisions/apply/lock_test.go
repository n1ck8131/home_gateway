package apply

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileLockerSerializesIndependentInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "apply.lock")
	first := FileLocker{Path: path, RetryInterval: time.Millisecond}
	second := FileLocker{Path: path, RetryInterval: time.Millisecond}
	releaseFirst, err := first.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := second.Lock(ctx); err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("contended Lock() error = %v", err)
	}
	if err := releaseFirst(); err != nil {
		t.Fatal(err)
	}
	if err := releaseFirst(); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}

	releaseSecond, err := second.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseSecond(); err != nil {
		t.Fatal(err)
	}
}

func TestTimerWatchdogRunsExpiredActionOnce(t *testing.T) {
	fired := make(chan struct{}, 2)
	cancel, err := (TimerWatchdog{}).Arm(time.Now().Add(-time.Second), func() {
		fired <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("watchdog action did not run")
	}
	select {
	case <-fired:
		t.Fatal("watchdog action ran more than once")
	case <-time.After(20 * time.Millisecond):
	}
}
