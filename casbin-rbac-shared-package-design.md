# Design: Extract Casbin RBAC + Proto-Annotation Authz into a Reusable Package

> **Status:** Design (to be implemented in a future session).
> **Goal:** Lift the teenaii-internal Casbin RBAC mechanism into a standalone,
> config-driven Go library publishable on GitHub, so any Kratos v2 service can
> declare per-RPC permissions on the proto and get fail-closed multi-tenant
> enforcement for free.
> **Source of truth (current impl):** `internal/wcasbin/**`,
> `apps/teenaii/internal/server/middleware/rbac.go`,
> `apis/teenaii/v1/options/rbac.proto`.

---

## 1. What this library does (one paragraph)

Declare a required permission directly on each gRPC/HTTP RPC via a custom
protobuf `MethodOptions` extension (`require {resource, action}` or `skip`). A
single Kratos middleware reads that annotation at dispatch time through proto
reflection, resolves the caller's subject and tenant domain from context, and
calls Casbin `Enforce(sub, dom, obj, act)`. Multi-tenancy rides on the Casbin
`dom` dimension (`business_id:branch_id`) with `keyMatch2` so a business-wide
policy (`biz:*`) covers every branch with **no fan-out writes**. Default is
**fail-closed**: an un-annotated RPC is rejected.

---

## 2. Current architecture (what exists today)

### 2.1 Proto annotation — `apis/teenaii/v1/options/rbac.proto`

```proto
syntax = "proto3";
package rbac.v1;
option go_package = "github.com/transformext/teenaii-apis/apis/teenaii/v1/options;optionsv1";
import "google/protobuf/descriptor.proto";

message Requirement {
  string resource = 1;   // e.g. "financial", "inventory", "customers"
  string action   = 2;   // e.g. "view", "add", "edit", "delete"
}

extend google.protobuf.MethodOptions {
  Requirement require = 56811;   // RPC needs this permission
  bool        skip    = 56812;   // RPC is public / uses other auth
}
```

Usage on an RPC:
```proto
rpc GetBusiness(GetBusinessRequest) returns (GetBusinessResponse) {
  option (google.api.http) = { get: "/v1/businesses/{id}" };
  option (rbac.v1.require) = { resource: "organization_profile" action: "view" };
}
rpc ListMyBusinesses(...) returns (...) {
  option (rbac.v1.skip) = true;   // public
}
```

### 2.2 Casbin model — `internal/wcasbin/wcasbin.go:29`

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

- `sub` = user id (or role name in `g` parent links).
- `dom` = `business_id:branch_id`; `business_id:*` = business-wide; `*` = global/system.
- `g = _,_,_` = domain-scoped role inheritance (`viewer < operator < manager < super_owner`).
- `root` and `super_owner` short-circuit (full access).
- **Trap:** `keyMatch2("*","*")` compiles to invalid regex `^*$` → silently false.
  Hence the `p.dom == "*"` guard in the matcher, and `VerifyPolicyCoverage` uses a
  slice scan instead of `Enforce`/`HasPolicy`.

Enforcer construction (`New`):
- model from string → MongoDB adapter (`mongodb-adapter/v4`) →
  `AddNamedDomainMatchingFunc("g","keyMatch2",util.KeyMatch2)` →
  `LoadPolicy()` → `EnableAutoSave(true)`.

Helpers:
- `HasPermission(e, userID, businessID, branchID, resource, action) (bool, error)`
  = `e.Enforce(userID, ComposeDom(biz,branch), resource, action)`.
- `MustHasPermission(...) error` → `ErrUnauthorized` on deny.

Domain helpers — `internal/wcasbin/policy_helper.go`:
- `ComposeDom(biz, branch)`: `""→"*"`, `biz,""→"biz:*"`, `biz,branch→"biz:branch"`.
- `IsWildcardDom(dom)`, `NamespacedRole(biz, name)` (system roles un-namespaced,
  custom roles `biz:name`), `IsSystemRole(name)`.

### 2.3 Middleware — `apps/teenaii/internal/server/middleware/rbac.go`

Request lifecycle:
1. `transport.FromServerContext(ctx)` — no transport → pass (background jobs).
2. Operation must start with `"/teenaii.v1."` else pass (healthcheck, framework ops).
3. `lookupMethodOptions(op)` — parse `/teenaii.v1.Svc/Method`, proto-reflection
   `protoregistry.GlobalFiles.FindDescriptorByName` → read `E_Skip`/`E_Require`.
   Cached in `sync.Map` (operation string stable for process life).
4. `nil` opts (un-annotated) → fail closed (`MISSING_ANNOTATION`, 500 in enforce mode).
5. `skip` → pass. Empty resource/action → `INVALID_ANNOTATION`.
6. `wkratos.GetUserInfoFromContext` → subject; `currentTenant(ctx)` → (biz, branch).
7. `wcasbin.HasPermission(...)` → deny = `403 RBAC_DENIED`; enforcer error = `500 RBAC_ERROR`.

Rollout switch: `PERMISSION_PERMISSIVE=true` → audit-only (log deny, forward).

Middleware ordering (`http.go`): recovery → validate → tracing → … →
business → businessRequired → **rbac** → audit. RBAC must run **after** auth +
business context populate ctx.

### 2.4 Wire DI — `apps/teenaii/internal/data/data.go`

`wcasbin.New` + `NewCasbinDBConfig` + `NewCasbinCollectionNameConfig("rbac")` +
`NewCasbinIEnforcer` (runs `VerifyBookingV3PolicyCoverage`). Middleware provided
by `server.ProviderSet` (`middleware.RBAC`).

### 2.5 Role management — `apps/teenaii/internal/biz/role.go`

- System roles live only in Casbin (seeded `constant.Policy`, dom `*`).
- Custom roles backed by Mongo (`RoleRepo`), namespaced `biz:name`.
- `AssignUserRole` → `AddRoleForUserInDomain(userID, sub, dom)`.
- `SetRolePermissions` → diff current vs desired `p` policies, add/remove.
- `GetMyPermissions` → walk inheritance chain across `*`, `biz:*`, `biz:branch`.

---

## 3. Coupling to remove before publishing

Everything below is hardcoded to teenaii and must become configuration:

| # | Coupling | Where | Fix |
|---|----------|-------|-----|
| 1 | Model string baked in (`super_owner`,`root`, dom shape) | `wcasbin.go:29` | `Config.Model string`, ship current as `DefaultModel` const |
| 2 | `"/teenaii.v1."` operation prefix | `rbac.go:42` | `Config.OperationPrefixes []string` |
| 3 | Subject from `wkratos.GetUserInfoFromContext` | `rbac.go:96` | inject `Subject func(ctx) (string, error)` |
| 4 | Tenant from `wkratos.GetBusinessCtx` | `rbac.go:162` | inject `Domain func(ctx) (string, error)` (returns composed dom) |
| 5 | Domain shape `biz:branch` | `policy_helper.go` | `DomainComposer` strategy; default = current |
| 6 | System-role set hardcoded | `policy_helper.go:58` | `Config.SystemRoles map[string]struct{}` |
| 7 | Proto `go_package` → teenaii repo | `rbac.proto:11` | move proto INTO published repo; consumers import that `optionsv1` |
| 8 | Env var `PERMISSION_PERMISSIVE` | `rbac.go:32` | `Config.Permissive bool` (caller reads its own env) |
| 9 | `bookingV3RequiredPolicies`, `constant.Policy` | wcasbin / constant | **do NOT ship**; provide generic `VerifyPolicyCoverage(e, required []PolicyTuple)` |
| 10 | Deny error shape (Kratos `errors.Forbidden`) | `rbac.go` | `Config.DenyMapper func(reason) error`, default = Kratos errors |

---

## 4. Correctness gaps to fix in the extraction

1. **Multi-instance policy staleness (high priority).**
   `EnableAutoSave(true)` + one `LoadPolicy()` at boot. On N Cloud Run instances,
   a role/policy change on instance A is invisible to B until B reloads. **No
   Casbin Watcher wired today.** Library must expose an optional `Watcher` hook
   (mongo change-stream or polling) and document the hazard prominently.

2. **Extension field numbers** `56811/56812` are arbitrary (valid range). Document
   them and warn consumers about collision if they define their own
   `MethodOptions` extensions.

3. **`super_owner` double-grant** — matcher short-circuit AND seed
   `super_owner,*,*,*`. Harmless but pick one source of truth and document.

4. **`keyMatch2("*","*")` invalid-regex trap** — carry the `p.dom=="*"` guard and
   the slice-scan verify into the library, with a comment so extenders don't
   reintroduce the bug.

5. **Un-annotated method → 500.** Keep fail-closed, but make the status code
   configurable via `DenyMapper` (some consumers may prefer 403).

---

## 5. Proposed package layout

```
github.com/<org>/casbin-rbac-kratos/
├── go.mod
├── README.md
├── LICENSE
├── proto/
│   └── rbac/v1/
│       ├── rbac.proto              # require/skip MethodOptions, stable go_package
│       └── rbac.pb.go              # generated, committed (consumers need the ext)
├── rbacmodel/
│   └── model.go                    # DefaultModel const + matcher-trap notes
├── enforcer/
│   ├── enforcer.go                 # New(adapter, Config); HasPermission; MustHasPermission
│   ├── domain.go                   # DomainComposer, ComposeDom, NamespacedRole, IsSystemRole
│   ├── verify.go                   # VerifyPolicyCoverage(e, []PolicyTuple) int
│   └── config.go
├── middleware/
│   ├── middleware.go               # Kratos middleware.Middleware
│   ├── lookup.go                   # proto-reflection annotation resolver + sync.Map cache
│   └── config.go
├── adapter/                        # OPTIONAL convenience
│   ├── mongo.go                    # wraps mongodb-adapter/v4
│   └── watcher.go                  # Watcher interface + mongo change-stream impl
└── examples/
    └── kratos-service/             # minimal consumer wiring + sample proto
```

**Keep out of the core:** the Mongo store choice, policy seeding, and any
app-specific resource/action lists. Consumers bring their own store + seed.

---

## 6. Proposed config-driven API

### 6.1 Enforcer config — `enforcer/config.go`

```go
package enforcer

type Config struct {
    // Model overrides the Casbin model text. Empty → rbacmodel.DefaultModel.
    Model string

    // DomainComposer maps (tenantID, subTenantID) → Casbin dom string.
    // Default: biz:branch with ":*" wildcards (see DefaultDomainComposer).
    DomainComposer DomainComposer

    // SystemRoles are stored un-namespaced (global). Others are namespaced
    // <tenant>:<role> by NamespacedRole. Default: {root, super_owner, manager, operator, viewer}.
    SystemRoles map[string]struct{}
}

type DomainComposer func(tenantID, subTenantID string) string

func New(adapter persist.Adapter, cfg Config) (*casbin.Enforcer, error)

func HasPermission(e casbin.IEnforcer, subject, tenantID, subTenantID, resource, action string) (bool, error)
func MustHasPermission(e casbin.IEnforcer, subject, tenantID, subTenantID, resource, action string) error

type PolicyTuple struct{ Role, Resource, Action string }
func VerifyPolicyCoverage(e casbin.IEnforcer, required []PolicyTuple) (missing int)
```

### 6.2 Middleware config — `middleware/config.go`

```go
package middleware

type Config struct {
    Enforcer casbin.IEnforcer

    // Subject extracts the Casbin subject (e.g. user id) from ctx.
    Subject func(ctx context.Context) (string, error)

    // Domain extracts (tenantID, subTenantID) from ctx; combined by the
    // enforcer's DomainComposer. Return ("","") to signal "no tenant".
    Domain func(ctx context.Context) (tenantID, subTenantID string, err error)

    // OperationPrefixes — only enforce on these Kratos operation namespaces.
    // Empty slice → enforce on all (not recommended).
    OperationPrefixes []string

    // Permissive — audit-only: log denials, forward request. Caller reads env.
    Permissive bool

    // DenyMapper maps a Deny reason → transport error. Default = Kratos errors.
    DenyMapper func(Reason) error

    Logger log.Logger
}

type Reason int
const (
    ReasonMissingAnnotation Reason = iota // un-annotated RPC (config error)
    ReasonInvalidAnnotation               // require with empty resource/action
    ReasonUnauthenticated                 // Subject() failed
    ReasonNoTenant                        // Domain() empty but RPC requires perm
    ReasonForbidden                       // Enforce returned false
    ReasonEnforcerError                   // Enforce returned error
)

func New(cfg Config) middleware.Middleware
```

### 6.3 Consumer wiring (example)

```go
enf, _ := enforcer.New(mongoAdapter, enforcer.Config{}) // defaults

mw := rbacmw.New(rbacmw.Config{
    Enforcer:          enf,
    OperationPrefixes: []string{"/myapp.v1."},
    Permissive:        os.Getenv("RBAC_PERMISSIVE") == "true",
    Subject: func(ctx context.Context) (string, error) {
        u, err := myauth.User(ctx); if err != nil { return "", err }
        return u.ID, nil
    },
    Domain: func(ctx context.Context) (string, string, error) {
        t := mytenant.From(ctx)
        return t.OrgID, t.BranchID, nil
    },
})

httpSrv := http.NewServer(http.Middleware(
    recovery.Recovery(), validate.Validator(),
    myauth.Middleware(), mytenant.Middleware(),
    mw, // RBAC after auth + tenant
))
```

Proto in consumer repo:
```proto
import "rbac/v1/rbac.proto";   // from the published package
rpc VoidBill(...) returns (...) {
  option (rbac.v1.require) = { resource: "bills" action: "void" };
}
```

---

## 7. Migration plan (teenaii adopts its own library)

After publishing, refactor teenaii to consume the package (keeps one impl):

1. Replace `internal/wcasbin/wcasbin.go` model with `enforcer.New(adapter, Config{})`.
2. Replace `policy_helper.go` with library `ComposeDom`/`NamespacedRole`
   (default composer == current behavior — byte-identical dom strings).
3. Rewrite `server/middleware/rbac.go` as a thin adapter:
   `Subject` = `wkratos.GetUserInfoFromContext`, `Domain` = `currentTenant`,
   `OperationPrefixes` = `["/teenaii.v1."]`, `Permissive` = env read.
4. Keep `constant.Policy` + `bookingV3RequiredPolicies` in teenaii; call
   `enforcer.VerifyPolicyCoverage(e, bookingV3Tuples)`.
5. Keep proto annotations as-is but re-import from the published `rbac/v1`
   (delete local `apis/teenaii/v1/options/rbac.proto`, repoint imports), run `make api`.
6. Wire: swap providers, `make wire`, `make build`, `make test`.

**Acceptance:** all existing biz/middleware RBAC tests pass unchanged; composed
`dom` strings and `Enforce` results are byte-for-byte identical to today.

---

## 8. Publishing checklist

- [ ] Proto `go_package` points at the new repo; commit generated `.pb.go`.
- [ ] `buf` or `protoc` gen instructions in README; document ext field numbers `56811/56812`.
- [ ] `DefaultModel` const documented with the `keyMatch2("*","*")` trap note.
- [ ] Watcher interface + mongo change-stream impl + multi-instance hazard doc.
- [ ] `examples/kratos-service/` runnable.
- [ ] Unit tests: matcher (root/super_owner/inheritance/branch-wildcard), domain
      composer, annotation lookup (skip/require/missing/invalid), permissive mode.
- [ ] README: quickstart, model explanation, fail-closed contract, rollout via Permissive.
- [ ] SemVer `v0.1.0`; note Kratos v2 + casbin/v2 + mongo-driver/v2 version matrix.
- [ ] LICENSE (Apache-2.0 or MIT).

---

## 9. Open questions for next session

1. Transport scope — Kratos-only, or also expose a transport-agnostic
   `Enforce`-from-annotation helper for non-Kratos services?
2. Adapter neutrality — ship Mongo adapter in-repo, or keep core
   adapter-agnostic (`persist.Adapter`) and put Mongo in a sub-package?
3. Watcher — change-stream (needs replica set) vs polling default?
4. Should `Requirement` support multiple (resource,action) pairs (AND/OR) for
   composite RPCs, or stay single-pair (current)?
5. Keep `root` magic subject, or make it config (`Config.RootSubject string`)?

---

## 10. File index (current impl, for reference)

| Concern | Path |
|---------|------|
| Casbin model + enforcer + helpers | `internal/wcasbin/wcasbin.go` |
| Domain/role composition | `internal/wcasbin/policy_helper.go` |
| Middleware | `apps/teenaii/internal/server/middleware/rbac.go` |
| Proto options | `apis/teenaii/v1/options/rbac.proto` |
| Middleware ordering | `apps/teenaii/internal/server/http.go` |
| Wire DI | `apps/teenaii/internal/data/data.go` |
| Role mgmt | `apps/teenaii/internal/biz/role.go` |
| Policy seed | `apps/teenaii/internal/constant/policy.go` |
| Business ctx middleware | `internal/wkratos/middleware.go` |
```
