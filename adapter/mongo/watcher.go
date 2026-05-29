package mongo

import (
	"context"
	"sync"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/casbin/casbin/v2/persist"
)

var _ persist.Watcher = (*Watcher)(nil)

// Watcher reloads policy when the policy collection changes.
type Watcher struct {
	coll   *mongo.Collection
	cb     func(string)
	mu     sync.Mutex
	cancel context.CancelFunc
}

// New returns a change-stream watcher over the given policy collection.
// Call Start(reload) to begin watching.
func New(coll *mongo.Collection) *Watcher {
	return &Watcher{coll: coll}
}

func (w *Watcher) SetUpdateCallback(cb func(string)) error {
	w.mu.Lock()
	w.cb = cb
	w.mu.Unlock()
	return nil
}

func (w *Watcher) Update() error {
	w.mu.Lock()
	cb := w.cb
	w.mu.Unlock()
	if cb != nil {
		cb("")
	}
	return nil
}

func (w *Watcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
}

// Start opens a change stream and calls reload on every change event until Close.
func (w *Watcher) Start(reload func() error) error {
	ctx, cancel := context.WithCancel(context.Background())
	w.mu.Lock()
	w.cancel = cancel
	w.mu.Unlock()

	stream, err := w.coll.Watch(ctx, mongo.Pipeline{})
	if err != nil {
		cancel()
		return err
	}
	go func() {
		defer stream.Close(ctx)
		for stream.Next(ctx) {
			_ = reload()
		}
	}()
	return nil
}
