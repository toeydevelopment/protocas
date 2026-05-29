// Package polling provides a store-agnostic Casbin watcher that periodically
// reloads policy. It works with ANY adapter and needs no replica set, trading
// freshness latency (up to one interval) for simplicity. Satisfies
// persist.Watcher so it can be passed to enforcer.Config.Watcher, and exposes
// Start to drive periodic reloads.
package polling

import (
	"sync"
	"time"

	"github.com/casbin/casbin/v2/persist"
)

var _ persist.Watcher = (*Watcher)(nil)

type Watcher struct {
	interval time.Duration
	cb       func(string)
	mu       sync.Mutex
	done     chan struct{}
	started  bool
}

// New returns a polling watcher with the given reload interval.
func New(interval time.Duration) *Watcher {
	return &Watcher{interval: interval, done: make(chan struct{})}
}

// SetUpdateCallback stores Casbin's notify callback (persist.Watcher).
func (w *Watcher) SetUpdateCallback(cb func(string)) error {
	w.mu.Lock()
	w.cb = cb
	w.mu.Unlock()
	return nil
}

// Update notifies other instances (persist.Watcher). For polling this is a
// best-effort local callback; cross-instance freshness comes from the poll loop.
func (w *Watcher) Update() error {
	w.mu.Lock()
	cb := w.cb
	w.mu.Unlock()
	if cb != nil {
		cb("")
	}
	return nil
}

// Close stops the poll loop (persist.Watcher).
func (w *Watcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		close(w.done)
		w.started = false
	}
}

// Start launches the poll loop, calling reload (typically Enforcer.LoadPolicy)
// every interval until Close. Safe to call once.
func (w *Watcher) Start(reload func() error) {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return
	}
	w.started = true
	w.mu.Unlock()

	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-w.done:
				return
			case <-ticker.C:
				_ = reload()
			}
		}
	}()
}
