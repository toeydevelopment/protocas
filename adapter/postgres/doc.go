// Package postgres provides a PostgreSQL-backed Casbin persist.Adapter (using
// the pgx driver) and a LISTEN/NOTIFY watcher for live, cross-instance policy
// reload.
//
// The adapter stores policy rules in a casbin_rule-style table (configurable
// name) with columns ptype, v0..v5. New optionally creates the table if missing.
// Pair it with the Watcher to keep multiple instances fresh without polling:
//
//	pool, _ := pgxpool.New(ctx, dsn)
//	ad, _ := postgres.New(ctx, pool)            // auto-creates casbin_rule
//	w, _ := postgres.NewWatcher(pool, "casbin_policy_changes")
//	enf, _ := enforcer.New(ad, enforcer.Config{Watcher: w})
//	w.Start(func() error { return enf.LoadPolicy() })
//	defer w.Close()
//
// For deployments without LISTEN/NOTIFY, use adapter/polling instead.
//
// Operational notes:
//
//   - The Watcher's Start holds one connection from the pool for the entire
//     lifetime of the listener (PostgreSQL LISTEN is connection-scoped). Size the
//     pool >= 2 (or give the watcher its own pool), otherwise adapter writes and
//     NOTIFY calls will block waiting for a connection.
//   - Rules round-trip by value column. A trailing empty token is treated as an
//     unused column (the casbin_rule convention) and is dropped on reload, so do
//     not rely on a significant trailing "" token in a policy rule. Interior
//     empty tokens are preserved.
package postgres
