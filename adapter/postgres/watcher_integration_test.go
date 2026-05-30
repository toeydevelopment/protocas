//go:build integration

package postgres

import (
	"testing"
	"time"
)

func TestWatcherNotifyRoundTrip(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()

	w, err := NewWatcher(pool, "casbin_policy_changes_it")
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	reloaded := make(chan struct{}, 4)
	if err := w.Start(func() error { reloaded <- struct{}{}; return nil }); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer w.Close()

	// Update issues NOTIFY; the listener goroutine should fire reload.
	if err := w.Update(); err != nil {
		t.Fatalf("update/notify: %v", err)
	}

	select {
	case <-reloaded:
	case <-time.After(5 * time.Second):
		t.Fatal("expected reload from LISTEN/NOTIFY")
	}
}

func TestWatcherCloseIdempotent(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()

	w, err := NewWatcher(pool, "casbin_close_it")
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if err := w.Start(func() error { return nil }); err != nil {
		t.Fatalf("start: %v", err)
	}
	w.Close()
	w.Close() // must not panic
}
