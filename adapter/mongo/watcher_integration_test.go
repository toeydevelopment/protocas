//go:build integration

package mongo

import (
	"context"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestChangeStreamTriggersReload(t *testing.T) {
	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		t.Skip("MONGO_URI not set")
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(context.Background())

	coll := client.Database("rbac_test").Collection("casbin_rule")
	w := New(coll)
	reloaded := make(chan struct{}, 4)
	if err := w.Start(func() error { reloaded <- struct{}{}; return nil }); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer w.Close()

	_, _ = coll.InsertOne(context.Background(), map[string]string{"ptype": "p"})
	select {
	case <-reloaded:
	case <-time.After(5 * time.Second):
		t.Fatal("expected reload from change stream")
	}
}
