// Package kratos provides a Kratos v2 middleware that enforces proto-annotated
// RBAC using the transport-agnostic enforcer core.
//
// New returns a middleware.Middleware that, for each RPC matching one of the
// configured OperationPrefixes, resolves the require/skip annotation, extracts
// the subject and tenant from context via the injected Subject and Domain
// functions, and calls the enforcer. It is fail-closed: an un-annotated RPC is
// denied. Each denial is classified by a [Reason] and mapped to a transport error
// by DenyMapper (default: Kratos errors). Permissive mode logs would-be denials
// and forwards the request, for safe rollout.
//
// Install this middleware AFTER authentication and tenant-context middleware so
// that Subject and Domain can read populated context.
package kratos
