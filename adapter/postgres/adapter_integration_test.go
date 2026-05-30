//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/toeydevelopment/protocas/enforcer"
)

// testPool connects using PG_DSN, skipping the test if it is unset.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PG_DSN")
	if dsn == "" {
		t.Skip("PG_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

func TestAdapterRoundTrip(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	defer pool.Close()

	const table = "casbin_rule_it"
	if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
		t.Fatalf("drop: %v", err)
	}

	ad, err := New(ctx, pool, WithTable(table))
	if err != nil {
		t.Fatalf("New (auto-create): %v", err)
	}

	// Write through an enforcer (autosave persists to Postgres).
	enf, err := enforcer.New(ad, enforcer.Config{})
	if err != nil {
		t.Fatalf("enforcer.New: %v", err)
	}
	if _, err := enf.AddPolicy("biz1:viewer", "biz1:*", "financial", "view"); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	if _, err := enf.AddGroupingPolicy("u1", "biz1:viewer", "biz1:branch1"); err != nil {
		t.Fatalf("add grouping: %v", err)
	}

	// A fresh enforcer over the same table must load the persisted rules.
	ad2, err := New(ctx, pool, WithTable(table))
	if err != nil {
		t.Fatalf("New 2: %v", err)
	}
	enf2, err := enforcer.New(ad2, enforcer.Config{})
	if err != nil {
		t.Fatalf("enforcer.New 2: %v", err)
	}
	ok, err := enf2.HasPermission("u1", "biz1", "branch1", "financial", "view")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !ok {
		t.Fatal("policy written by enf should be visible to enf2 after load")
	}

	// RemoveFilteredPolicy: drop the grouping for u1, access should disappear.
	if _, err := enf.RemoveFilteredGroupingPolicy(0, "u1"); err != nil {
		t.Fatalf("remove filtered grouping: %v", err)
	}
	ad3, _ := New(ctx, pool, WithTable(table))
	enf3, _ := enforcer.New(ad3, enforcer.Config{})
	ok, _ = enf3.HasPermission("u1", "biz1", "branch1", "financial", "view")
	if ok {
		t.Fatal("grouping removed; access should be denied after reload")
	}

	// SavePolicy round-trips the full model.
	if err := ad.SavePolicy(enf.GetModel()); err != nil {
		t.Fatalf("save policy: %v", err)
	}
}
