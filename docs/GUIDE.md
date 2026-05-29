# Usage Guide

A deeper walkthrough of `casbin-rbac-kratos`: how enforcement works, how to manage
policies and roles, how to bring your own model, how to keep multiple instances
fresh, and how to avoid the sharp edges.

If you only want to wire it up, the [README quickstart](../README.md#quickstart-kratos)
is enough. Read this when you need to understand or extend the behavior.

---

## 1. Architecture

Three layers, dependencies flow one way:

```
proto/rbac/v1      require / skip MethodOptions (no Go deps beyond descriptor)
      ^
enforcer/          CORE — transport- and store-agnostic
                   model rendering, domain/role composition,
                   annotation resolver, enforcement, policy-coverage check
      ^
middleware/kratos  thin adapter: reads ctx, calls the core
adapter/polling    optional Watcher (any store)
adapter/mongo      optional Watcher (change stream)
```

The core never imports Kratos or Mongo. That is what makes it reusable: a
non-Kratos service uses `enforcer` + `enforcer.RequirementFor` directly; a
non-Mongo service brings any Casbin `persist.Adapter`.

---

## 2. How a request is authorized

For each incoming RPC the Kratos middleware does:

1. **No transport in context?** Pass (e.g. background jobs have no transport).
2. **Operation outside `OperationPrefixes`?** Pass (health checks, framework ops).
3. **Resolve the annotation** via `enforcer.RequirementFor(operation)`:
   - un-annotated → **deny** (`ReasonMissingAnnotation`) — fail-closed.
   - `skip` → pass.
   - `require` with empty resource/action → deny (`ReasonInvalidAnnotation`).
4. **Subject** via your `Subject(ctx)`. Error/empty → deny (`ReasonUnauthenticated`).
5. **Domain** via your `Domain(ctx)` → `(tenantID, subTenantID)`. Both empty →
   deny (`ReasonNoTenant`).
6. **Enforce**: `HasPermission(subject, tenantID, subTenantID, resource, action)`.
   - `false` → deny (`ReasonForbidden`).
   - error → deny (`ReasonEnforcerError`, mapped to 500 by default).

Each `Reason` is mapped to a transport error by `DenyMapper` (default = Kratos
`errors`). Override it to, say, return 403 instead of 500 for un-annotated RPCs.

In **permissive mode**, any would-be deny is logged and the request is forwarded.

### Middleware ordering

RBAC must run **after** authentication and tenant-context middleware, because it
reads the subject and tenant out of `ctx`:

```
recovery -> validate -> ... -> auth -> tenant -> rbac -> audit
```

Putting RBAC before auth/tenant means `Subject`/`Domain` see an empty context and
every guarded RPC is denied.

---

## 3. The model in detail

Default model (rendered from `rbacmodel.DefaultModel`):

```
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == "root"
 || g(r.sub, "super_owner", r.dom)
 || (g(r.sub, p.sub, r.dom)
     && (p.dom == "*" || keyMatch2(r.dom, p.dom))
     && keyMatch(r.obj, p.obj)
     && keyMatch(r.act, p.act))
```

- **`root`** (configurable) and **`super_owner`** short-circuit to full access.
- **`g(r.sub, p.sub, r.dom)`** resolves the subject's roles in the request domain.
  The `g` link is registered with `keyMatch2` as its domain matching function, so
  a role assigned in `biz1:*` resolves for a request in `biz1:branch1`.
- **`p.dom == "*"`** is an explicit guard — see the trap below.

### Domains

`DomainComposer` maps `(tenantID, subTenantID)` to the `dom` string. The default:

| Input | `dom` | Meaning |
|---|---|---|
| `("", "")` | `*` | global / system |
| `("biz1", "")` | `biz1:*` | tenant-wide |
| `("biz1", "branch1")` | `biz1:branch1` | specific sub-tenant |

A tenant-wide policy (`biz1:*`) matches any `biz1:branch1` request via `keyMatch2`,
so you write one policy instead of one per branch. Supply a custom `DomainComposer`
if your tenancy is shaped differently — it flows through `HasPermission` end to end.

### Roles

- **System roles** (`DefaultSystemRoles`: root, super_owner, manager, operator,
  viewer) are stored un-namespaced (global).
- **Custom roles** are namespaced `tenant:name` via `NamespacedRole`, so two
  tenants can both have an `accountant` role without collision.

---

## 4. Managing policies and roles

The library enforces; it does **not** seed. You own your policy data. Use the
embedded `*casbin.Enforcer` methods on `*enforcer.Enforcer`:

```go
// Grant: role "biz1:viewer" may view "financial" tenant-wide.
enf.AddPolicy("biz1:viewer", "biz1:*", "financial", "view")

// Assign: user u1 has role biz1:viewer in domain biz1:branch1.
enf.AddGroupingPolicy("u1", "biz1:viewer", "biz1:branch1")

// Revoke / remove are the standard Casbin RemovePolicy / RemoveGroupingPolicy.
```

### Verifying required coverage at boot

To assert that a known set of grants exists (e.g. baseline system policies), use
`VerifyPolicyCoverage` — it scans the policy set directly:

```go
required := []enforcer.PolicyTuple{
	{Role: "manager", Resource: "financial", Action: "view"},
	{Role: "manager", Resource: "inventory", Action: "edit"},
}
if missing := enforcer.VerifyPolicyCoverage(enf, required); missing > 0 {
	log.Fatalf("rbac: %d required policies missing", missing)
}
```

It deliberately does **not** use `Enforce`/`HasPolicy` — see the trap below.

---

## 5. Bringing your own model

`Config.Model` overrides the model text. The library supports custom models along
a **documented contract**: the request definition must stay `r = sub, dom, obj, act`.

| Tier | Your model | Supported |
|---|---|---|
| 1 | Default model | Fully. |
| 2 | Custom matcher/roles/effects/ABAC, **same** `sub,dom,obj,act` request | Fully — `HasPermission`, `DomainComposer`, root all work. |
| 3 | **Different arity** (e.g. no `dom`, struct ABAC) | Helpers don't fit. `New` returns `ErrUnsupportedModel`. Use the raw `*casbin.Enforcer` (embedded) + `RequirementFor` and write your own glue. |

`New` validates the request shape on construction and fails fast with
`ErrUnsupportedModel` if it isn't `sub,dom,obj,act`, pointing you at the escape
hatch rather than silently misbehaving.

### The root subject

Root is configurable to keep the package generic:

```go
enforcer.Config{RootSubject: "superadmin"} // rename the magic subject
enforcer.Config{DisableRoot: true}          // remove the short-circuit entirely
enforcer.Config{}                           // default: "root" is magic
```

Leaving `RootSubject` empty yields the default `"root"` (current behavior). To turn
the superuser **off**, set `DisableRoot: true` — an empty `RootSubject` does not
disable it. (A fully custom `Model` manages root itself; templating is skipped.)

---

## 6. Choosing a watcher

Casbin loads policy once at boot. With more than one instance, changes made on one
are invisible to the others until they reload. Pick a watcher:

- **`adapter/polling`** — reloads every interval. Works with any store, needs no
  special infrastructure. Freshness lag = up to one interval. Good default.

  ```go
  w := polling.New(15 * time.Second)
  enf, _ := enforcer.New(adapter, enforcer.Config{Watcher: w})
  w.Start(func() error { return enf.LoadPolicy() })
  defer w.Close()
  ```

- **`adapter/mongo`** — opens a MongoDB change stream and reloads on every change.
  Near-instant, but **requires a replica set** (change streams are unavailable on
  standalone `mongod`).

  ```go
  w := mongo.New(policyCollection)
  enf, _ := enforcer.New(adapter, enforcer.Config{Watcher: w})
  w.Start(func() error { return enf.LoadPolicy() })
  defer w.Close()
  ```

Watcher errors are logged, never fatal — stale-but-up beats down.

---

## 7. Testing your integration

- Build an in-memory enforcer with a `nil` adapter; no database needed:

  ```go
  enf, _ := enforcer.New(nil, enforcer.Config{})
  enf.AddPolicy("biz1:viewer", "biz1:*", "financial", "view")
  enf.AddGroupingPolicy("u1", "biz1:viewer", "biz1:branch1")
  ok, _ := enf.HasPermission("u1", "biz1", "branch1", "financial", "view") // true
  ```

- Test the middleware by constructing a Kratos server context with a fake
  transporter whose `Operation()` returns your RPC's operation string (see
  `middleware/kratos/middleware_test.go`).

- The Mongo change-stream test is gated behind the `integration` build tag and
  skipped unless `MONGO_URI` is set, so the default `go test ./...` stays hermetic.
  Run it with `go test -tags integration ./adapter/mongo/...` against a replica set.

---

## 8. Troubleshooting and sharp edges

**Everything is denied.** Check middleware ordering — RBAC must run after auth and
tenant middleware. Also confirm your RPCs are actually annotated; un-annotated RPCs
fail closed by design.

**`ErrUnsupportedModel` from `New`.** Your custom `Model` doesn't use the
`sub,dom,obj,act` request shape. Either conform to it or use the raw enforcer
(tier 3 above).

**Policy changes don't take effect across instances.** You have no `Watcher`. See
section 6.

**The `keyMatch2("*","*")` trap.** `keyMatch2` compiles `*` into a regex; the pair
`("*","*")` becomes the invalid regex `^*$` and silently returns `false`. Two
defenses are baked in and must not be removed:

1. The matcher guards global policies explicitly with `p.dom == "*"` *before*
   reaching `keyMatch2`.
2. `VerifyPolicyCoverage` scans the policy slice directly instead of calling
   `Enforce`/`HasPolicy`, so a global (`*`) policy is detected reliably.

If you write a custom model, carry these guards forward.

**Background jobs are denied.** They shouldn't be — requests with no transport in
context pass through. If a job is being denied, it is going through a real
transport; give it a `skip` annotation or exclude its operation prefix.
