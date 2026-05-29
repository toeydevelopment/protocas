package polling

import (
	"testing"
	"time"
)

func TestPollingTriggersReload(t *testing.T) {
	reloaded := make(chan struct{}, 8)
	w := New(5 * time.Millisecond)
	w.Start(func() error {
		reloaded <- struct{}{}
		return nil
	})
	defer w.Close()

	select {
	case <-reloaded:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected a reload within 500ms")
	}
}

func TestSatisfiesWatcherContract(t *testing.T) {
	w := New(time.Second)
	defer w.Close()
	if err := w.SetUpdateCallback(func(string) {}); err != nil {
		t.Fatalf("SetUpdateCallback: %v", err)
	}
	if err := w.Update(); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	w := New(time.Second)
	w.Start(func() error { return nil })
	w.Close()
	w.Close() // must not panic on a second Close

	w2 := New(time.Second)
	w2.Close() // Close before any Start must also be safe
}

func TestRestartAfterClose(t *testing.T) {
	w := New(5 * time.Millisecond)
	w.Start(func() error { return nil })
	w.Close()

	reloaded := make(chan struct{}, 8)
	w.Start(func() error {
		reloaded <- struct{}{}
		return nil
	})
	defer w.Close()

	select {
	case <-reloaded:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("restarted watcher should reload again")
	}
}
