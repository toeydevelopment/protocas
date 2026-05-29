// Package mongo provides a Casbin watcher backed by a MongoDB change stream.
// Pair it with any Casbin Mongo adapter for live, cross-instance policy reload.
//
// REQUIRES a replica set (change streams are unavailable on standalone mongod).
// For non-replica-set deployments use adapter/polling instead.
package mongo
