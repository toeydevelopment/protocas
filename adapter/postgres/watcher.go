package postgres

import (
	"context"
	"fmt"
	"sync"

	"github.com/casbin/casbin/v2/persist"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ persist.Watcher = (*Watcher)(nil)

// Watcher is a Casbin persist.Watcher backed by PostgreSQL LISTEN/NOTIFY. When
// this instance changes policy, Casbin calls Update, which issues a NOTIFY; other
// instances listening on the same channel reload. Start begins listening on a
// dedicated pooled connection and invokes the reload function on each
// notification.
type Watcher struct {
	pool    *pgxpool.Pool
	channel string

	mu      sync.Mutex
	cb      func(string)
	cancel  context.CancelFunc
	started bool
}

// NewWatcher returns a watcher over the given NOTIFY channel. The channel must be
// a plain SQL identifier (it is used verbatim in a LISTEN statement).
func NewWatcher(pool *pgxpool.Pool, channel string) (*Watcher, error) {
	if pool == nil {
		return nil, fmt.Errorf("postgres: nil pool")
	}
	if err := validateIdentifier("channel", channel); err != nil {
		return nil, err
	}
	return &Watcher{pool: pool, channel: channel}, nil
}

// SetUpdateCallback stores Casbin's callback (persist.Watcher).
func (w *Watcher) SetUpdateCallback(cb func(string)) error {
	w.mu.Lock()
	w.cb = cb
	w.mu.Unlock()
	return nil
}

// Update notifies other instances that policy changed (persist.Watcher). The
// channel is passed as a parameter to pg_notify, so no identifier interpolation
// is needed here.
func (w *Watcher) Update() error {
	if _, err := w.pool.Exec(context.Background(), "SELECT pg_notify($1, '')", w.channel); err != nil {
		return fmt.Errorf("postgres: notify: %w", err)
	}
	return nil
}

// Close stops the listener (persist.Watcher). Idempotent.
func (w *Watcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.started {
		return
	}
	w.cancel()
	w.started = false
}

// Start begins listening for notifications and calls reload (typically
// Enforcer.LoadPolicy) on each one, until Close. It acquires one connection from
// the pool for the listener's lifetime. Calling Start while already running is a
// no-op; a watcher may be restarted after Close.
func (w *Watcher) Start(reload func() error) error {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.started = true
	w.mu.Unlock()

	conn, err := w.pool.Acquire(ctx)
	if err != nil {
		cancel()
		w.mu.Lock()
		w.started = false
		w.mu.Unlock()
		return fmt.Errorf("postgres: acquire listener conn: %w", err)
	}
	// LISTEN cannot be parameterized; channel was validated as an identifier.
	if _, err := conn.Exec(ctx, "LISTEN "+w.channel); err != nil {
		conn.Release()
		cancel()
		w.mu.Lock()
		w.started = false
		w.mu.Unlock()
		return fmt.Errorf("postgres: listen: %w", err)
	}

	go func() {
		defer conn.Release()
		for {
			if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
				return // context cancelled (Close) or connection lost
			}
			_ = reload()
		}
	}()
	return nil
}
