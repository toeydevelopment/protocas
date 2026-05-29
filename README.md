# casbin-rbac-kratos

Generic, config-driven [Casbin](https://casbin.org) RBAC with **proto-annotation
authorization** for Go. Transport-agnostic core, first-class [Kratos v2](https://go-kratos.dev)
middleware, and any Casbin-supported store.

Declare the permission an RPC needs directly on the proto method, and a single
middleware enforces it — multi-tenant, fail-closed, with no per-handler auth code.

```proto
rpc VoidBill(VoidBillRequest) returns (VoidBillResponse) {
  option (rbac.v1.require) = { resource: "bills" action: "void" };
}
rpc ListPublic(ListPublicRequest) returns (ListPublicResponse) {
  option (rbac.v1.skip) = true; // public / authorized elsewhere
}
```

---

## Why

- **Annotation-driven.** Permissions live next to the RPC they protect, read at
  dispatch time via proto reflection. No scattered `if`-checks in handlers.
- **Fail-closed by default.** An un-annotated RPC is denied, not allowed. You
  cannot forget to protect an endpoint.
- **Multi-tenant on Casbin's domain axis.** `tenant:subtenant` domains with
  `keyMatch2` mean a tenant-wide grant (`tenant:*`) covers every sub-tenant with
  no fan-out policy writes.
- **Generic.** The core depends on neither a transport nor a store. Bring any
  Casbin `persist.Adapter`; drop in the Kratos middleware or wire your own.
- **Configurable, not hardcoded.** Root subject, system roles, domain shape, and
  the model itself are configuration with sensible defaults.

---

## Install

```bash
go get github.com/toeydevelopment/protocas@latest
```

Requires Go 1.26+. Core depends on `github.com/casbin/casbin/v2`. The Kratos
middleware adds `github.com/go-kratos/kratos/v2`; the Mongo watcher adds
`go.mongodb.org/mongo-driver/v2` — both are isolated in their own sub-packages,
so you only pull what you import.

### Packages

| Import path | Purpose |
|---|---|
| `.../enforcer` | Core: enforcer, domain/role composition, annotation resolver, policy-coverage check. Transport- and store-agnostic. |
| `.../rbacmodel` | The default Casbin model text + root-clause rendering. |
| `.../middleware/kratos` | Kratos v2 middleware adapter. |
| `.../adapter/polling` | Store-agnostic polling watcher (live reload, any store). |
| `.../adapter/mongo` | MongoDB change-stream watcher (requires a replica set). |
| `.../proto/rbac/v1` | The `require` / `skip` `MethodOptions` extensions (committed generated code). |

---

## Quickstart (Kratos)

```go
import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport/http"

	"github.com/toeydevelopment/protocas/enforcer"
	rbacmw "github.com/toeydevelopment/protocas/middleware/kratos"
)

// 1. Build the enforcer. Pass any Casbin persist.Adapter; nil = in-memory.
enf, err := enforcer.New(myAdapter, enforcer.Config{})
if err != nil {
	return err
}

// 2. Build the middleware. Inject how to read the subject and tenant from ctx.
mw := rbacmw.New(rbacmw.Config{
	Enforcer:          enf,
	OperationPrefixes: []string{"/myapp.v1."}, // only enforce your own RPCs
	Subject: func(ctx context.Context) (string, error) {
		u, err := myauth.User(ctx)
		if err != nil {
			return "", err
		}
		return u.ID, nil
	},
	Domain: func(ctx context.Context) (tenantID, subTenantID string, err error) {
		t := mytenant.From(ctx)
		return t.OrgID, t.BranchID, nil
	},
})

// 3. Install AFTER auth + tenant middleware so subject/tenant are populated.
srv := http.NewServer(http.Middleware(
	recovery.Recovery(),
	myauth.Middleware(),
	mytenant.Middleware(),
	mw,
))
```

A complete, runnable wiring lives in [`examples/kratos-service`](examples/kratos-service).

## Quickstart (no Kratos)

The core is usable directly — no transport required:

```go
enf, _ := enforcer.New(myAdapter, enforcer.Config{})

ok, err := enf.HasPermission(userID, "biz1", "branch1", "financial", "view")
// or, for the resolved annotation of an operation string:
req, err := enforcer.RequirementFor("/myapp.v1.Billing/VoidBill")
```

---

## Proto annotation

Import the extensions and annotate your methods:

```proto
import "rbac/v1/rbac.proto";

service Billing {
  rpc VoidBill(VoidBillRequest) returns (VoidBillResponse) {
    option (rbac.v1.require) = { resource: "bills" action: "void" };
  }
  rpc Health(HealthRequest) returns (HealthResponse) {
    option (rbac.v1.skip) = true;
  }
}
```

- **`require {resource, action}`** — caller must hold this permission.
- **`skip`** — RPC is public or authorized elsewhere.
- **Neither** — fail-closed: the RPC is denied (treated as a configuration error).

The Go extensions are at `github.com/toeydevelopment/protocas/proto/rbac/v1`
(package `rbacv1`: `E_Require`, `E_Skip`, `Requirement`). Generated code is
committed, so consumers get the extension without regenerating.

> **Extension field numbers** are `require = 56811` and `skip = 56812`. If you
> define your own `MethodOptions` extensions, do not reuse these numbers.

---

## The model

Default request shape: `r = sub, dom, obj, act`.

- `sub` — subject (user id, or a role name in `g` parent links).
- `dom` — tenant domain: `tenant:subtenant`; `tenant:*` is tenant-wide; `*` is global.
- `obj` — resource (e.g. `financial`).
- `act` — action (e.g. `view`).

Role inheritance is domain-scoped (`g = _, _, _`). A configurable **root** subject
and a `super_owner` role short-circuit to full access.

See [`docs/GUIDE.md`](docs/GUIDE.md) for the full model walkthrough, custom-model
contract, policy/role management patterns, and the `keyMatch2` trap.

---

## Configuration

```go
type Config struct {
	Model          string          // empty -> default model
	DomainComposer DomainComposer  // nil   -> tenant:subtenant with :* wildcards
	RootSubject    string          // empty -> "root"
	DisableRoot    bool            // true  -> no superuser short-circuit
	Watcher        persist.Watcher // nil   -> no live reload (single-instance only)
}
```

The zero value is usable and reproduces the canonical multi-tenant behavior.

Role namespacing (system vs custom roles) is a **caller-side** concern: use the
exported helpers `DefaultSystemRoles()`, `IsSystemRole(name, set)`, and
`NamespacedRole(tenant, name, set)` to build your policy data. The enforcer does
not namespace roles automatically.

---

## Multi-instance staleness (read this before going to production)

Casbin loads policy once at boot. On N instances, a role/policy change on instance
A is **invisible to B until B reloads**. If you run more than one replica, set a
`Watcher`:

| Watcher | Freshness | Requirements |
|---|---|---|
| `adapter/polling` | up to one interval | none — works with any store |
| `adapter/mongo` | near-instant | a MongoDB replica set (change streams) |

```go
w := polling.New(15 * time.Second)
enf, _ := enforcer.New(myAdapter, enforcer.Config{Watcher: w})
w.Start(func() error { return enf.LoadPolicy() })
defer w.Close()
```

A nil `Watcher` is fine for a single instance; it is a correctness hazard for many.

---

## Rollout: permissive mode

Audit before you enforce. `Permissive: true` logs would-be denials and forwards
the request, so you can find missing policies without breaking traffic:

```go
mw := rbacmw.New(rbacmw.Config{ /* ... */, Permissive: os.Getenv("RBAC_PERMISSIVE") == "true"})
```

Flip it off once the logs are clean.

---

## Documentation

- [`docs/GUIDE.md`](docs/GUIDE.md) — usage guide: model, policies, roles, custom
  models, watchers, testing, troubleshooting.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — building, regenerating proto, running tests.
- [`examples/kratos-service`](examples/kratos-service) — runnable wiring.
- [`docs/superpowers/specs`](docs/superpowers/specs) — the design spec.

---

## Version matrix

| Component | Version |
|---|---|
| Go | 1.26+ |
| casbin/v2 | v2.135.x |
| go-kratos/kratos/v2 (middleware only) | v2.9.x |
| mongo-driver/v2 (mongo watcher only) | v2.6.x |

SemVer; current line `v0.1.x` (pre-release).

## License

Apache-2.0. See [LICENSE](LICENSE).
