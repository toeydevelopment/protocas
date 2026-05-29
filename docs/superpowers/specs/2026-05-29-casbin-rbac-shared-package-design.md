# Spec: `casbin-rbac-kratos` — generic, config-driven RBAC for Go

> **Status:** Approved design (2026-05-29). Ready for implementation planning.
> **Goal:** A standalone, config-driven Go library that lifts the teenaii-internal
> Casbin RBAC + proto-annotation authz mechanism into a reusable package, so any
> Go service (Kratos v2 first-class) can declare per-RPC permissions on the proto
> and get fail-closed, multi-tenant enforcement for free.
> **Source design brief:** `casbin-rbac-shared-package-design.md` (repo root).
> **Source impl (reference only, NOT in this repo):** teenaii `internal/wcasbin/**`,
> `apps/teenaii/internal/server/middleware/rbac.go`, `apis/teenaii/v1/options/rbac.proto`.

---

## 1. What the library does

Declare a required permission directly on each gRPC/HTTP RPC via a custom protobuf
`MethodOptions` extension (`require {resource, action}` or `skip`). A transport-agnostic
core reads that annotation through proto reflection, resolves the caller's subject and
tenant domain, and calls Casbin `Enforce(sub, dom, obj, act)`. Multi-tenancy rides on the
Casbin `dom` dimension (`tenant:subtenant`) with `keyMatch2`, so a tenant-wide policy
(`tenant:*`) covers every sub-tenant with **no fan-out writes**. Default is **fail-closed**:
an un-annotated RPC is rejected.

A thin Kratos middleware adapter sits on top of the core for the common case. Non-Kratos
services use the core enforcer + annotation resolver directly.

---

## 2. Locked design decisions

| # | Topic | Decision |
|---|-------|----------|
| 1 | Transport scope | **Layered**: transport-agnostic core + Kratos middleware as a thin adapter in its own subpackage. |
| 2 | Storage adapter | **Adapter-agnostic core** — `New` takes any Casbin `persist.Adapter`. Mongo helper is optional in `adapter/mongo`. |
| 3 | Watcher (multi-instance staleness) | **Generic `Watcher` interface** wired by core if provided; ship optional impls: mongo change-stream + store-agnostic polling. |
| 4 | Proto `Requirement` | **Single `(resource, action)` pair** per RPC (current behavior). Repeated field can be added back-compat later if needed. |
| 5 | Root subject | **`Config.RootSubject string`**, default `"root"`; empty string disables the magic superuser. |
| 6 | Custom model support | **Documented contract**: request def must be `r = sub, dom, obj, act`. `New` validates and fails fast otherwise. |

---

## 3. Architecture — three layers, one-way dependencies

```
proto/rbac/v1       require/skip MethodOptions (no Go deps beyond descriptor)
      ^
enforcer/           CORE: transport-agnostic, store-agnostic
                    model, domain, annotation resolver, config, verify, watcher iface
      ^
middleware/kratos   thin adapter (Subject/Domain/DenyMapper injected)
adapter/mongo       optional: mongodb-adapter/v4 wrap + change-stream Watcher
adapter/polling     optional: store-agnostic interval re-LoadPolicy Watcher
```

The core never imports Kratos or Mongo. Middleware and adapters import the core.
A non-Kratos consumer uses `enforcer` + `RequirementFor` directly; a Kratos consumer
drops in `middleware/kratos`.

---

## 4. Package layout

```
github.com/<org>/casbin-rbac-kratos/
|-- go.mod
|-- README.md
|-- LICENSE
|-- rbacmodel/
|   `-- model.go            DefaultModel const + {{root}} templating + matcher-trap notes
|-- enforcer/
|   |-- enforcer.go         New(adapter, Config); HasPermission; MustHasPermission
|   |-- domain.go           DomainComposer, ComposeDom, NamespacedRole, IsSystemRole
|   |-- annotation.go       RequirementFor(operation) — proto-reflection + sync.Map cache
|   |-- verify.go           VerifyPolicyCoverage(e, []PolicyTuple) int
|   |-- watcher.go          Watcher interface (persist.Watcher contract)
|   |-- validate.go         model request-shape validation (fail-fast)
|   `-- config.go
|-- middleware/kratos/
|   |-- middleware.go       middleware.Middleware
|   `-- config.go           Subject/Domain/OperationPrefixes/Permissive/DenyMapper/Reason
|-- adapter/
|   |-- mongo/              optional: mongodb-adapter/v4 wrap + change-stream Watcher
|   `-- polling/            optional: store-agnostic interval re-LoadPolicy Watcher
|-- proto/rbac/v1/
|   |-- rbac.proto          require/skip MethodOptions, stable go_package
|   `-- rbac.pb.go          generated, committed (consumers need the extension)
`-- examples/
    `-- kratos-service/     runnable consumer + sample proto
```

**Kept out of core:** the store choice, policy seeding, app-specific resource/action lists,
auth/tenant context extraction. No teenaii `constant.Policy` or `bookingV3RequiredPolicies`.

---

## 5. Core API (`enforcer`)

```go
package enforcer

type Config struct {
    // Model overrides the Casbin model text. Empty -> rbacmodel.DefaultModel.
    Model string

    // DomainComposer maps (tenantID, subTenantID) -> Casbin dom string.
    // Default: tenant:subtenant with ":*" wildcards (DefaultDomainComposer).
    DomainComposer DomainComposer

    // SystemRoles are stored un-namespaced (global). Others are namespaced
    // <tenant>:<role>. Default: {root, super_owner, manager, operator, viewer}.
    SystemRoles map[string]struct{}

    // RootSubject is the superuser that short-circuits all checks.
    // Empty -> default "root" (current behavior, unchanged).
    RootSubject string

    // DisableRoot removes the magic superuser entirely (no short-circuit),
    // regardless of RootSubject. Use this to turn root off; leaving RootSubject
    // empty does NOT disable it (that yields the default "root").
    DisableRoot bool

    // Watcher, if non-nil, is wired for live policy reload across instances.
    // nil -> no live reload; New logs a multi-instance staleness warning.
    Watcher persist.Watcher
}

type DomainComposer func(tenantID, subTenantID string) string
type PolicyTuple    struct{ Role, Resource, Action string }

// Enforcer wraps *casbin.Enforcer and carries the DomainComposer so that
// HasPermission composes tenant/subtenant into dom consistently. The embedded
// *casbin.Enforcer is promoted, so tier-3 (arity-different) consumers get the
// raw enforcer (AddPolicy/Enforce/etc.) for free.
type Enforcer struct {
    *casbin.Enforcer
    // composer + rootSubject stored internally
}

// New builds the enforcer. A nil adapter yields an in-memory enforcer (no
// persistence) — convenient for tests and ephemeral use.
func New(adapter persist.Adapter, cfg Config) (*Enforcer, error)

func (e *Enforcer) HasPermission(subject, tenantID, subTenantID, resource, action string) (bool, error)
func (e *Enforcer) MustHasPermission(subject, tenantID, subTenantID, resource, action string) error // ErrUnauthorized on deny

func VerifyPolicyCoverage(e casbin.IEnforcer, required []PolicyTuple) (missing int)
```

### 5.1 RootSubject templating

Because the superuser is configurable, `DefaultModel` carries a `{{ROOT_CLAUSE}}`
placeholder at the head of its matcher. `New` renders it: when root is active it becomes
`r.sub == "<RootSubject>" || `; when `DisableRoot` is set it becomes the empty string,
removing the short-circuit entirely. A fully custom `Model` string opts out of templating
(the consumer manages root themselves). This is the one real addition beyond the source
brief — it makes the superuser generic without forcing a model rewrite.

### 5.2 Domain helpers (`domain.go`)

- `ComposeDom(tenant, subtenant)`: `("","")->"*"`, `(t,"")->"t:*"`, `(t,s)->"t:s"`.
- `IsWildcardDom(dom)`, `NamespacedRole(tenant, name)` (system roles un-namespaced,
  custom roles `tenant:name`), `IsSystemRole(name)`.
- `DefaultDomainComposer` == current teenaii behavior (byte-identical dom strings).

### 5.3 keyMatch2 trap (carried forward, §4.4 of brief)

`keyMatch2("*","*")` compiles to invalid regex `^*$` -> silently false. The library:
- keeps the `p.dom == "*"` guard in `DefaultModel`'s matcher,
- implements `VerifyPolicyCoverage` as a slice scan (NOT `Enforce`/`HasPolicy`),
- documents both with comments so extenders don't reintroduce the bug.

---

## 6. Annotation resolver (`enforcer/annotation.go`) — transport-agnostic

```go
type Requirement struct {
    Resource string
    Action   string
    Skip     bool
}

// RequirementFor reads E_Require / E_Skip from the method descriptor for a
// Kratos-style operation string ("/pkg.v1.Svc/Method") via proto reflection.
// Cached in a sync.Map (operation strings are stable for process life).
// Returns (nil, nil) for un-annotated methods (caller decides fail-closed).
func RequirementFor(operation string) (*Requirement, error)
```

Model-independent and exported, so non-Kratos consumers and tier-3 (arity-different)
custom-model consumers can reuse it.

---

## 7. Custom model support (the contract)

**Contract:** the request definition must be `r = sub, dom, obj, act`.

| Tier | Custom model | Supported? |
|------|-------------|-----------|
| 1 | `DefaultModel` | Full. |
| 2 | Custom matcher / roles / effects / ABAC, **same request sig** `sub,dom,obj,act` | Full — `HasPermission`, `DomainComposer`, `RootSubject` all fit. |
| 3 | **Different arity** (e.g. `sub,obj,act`; struct ABAC) | Helpers don't fit. Consumer uses the raw `*casbin.Enforcer` from `New` + `RequirementFor` and writes own enforce/middleware glue. Documented, not silently broken. |

**Fail-fast validation (`validate.go`), run inside `New`:**
- Parse the loaded model's request definition; require tokens `{sub, dom, obj, act}`.
  Mismatch -> return `ErrUnsupportedModel` with a message citing the contract and pointing
  to the raw-enforcer escape hatch.
- If `RootSubject != ""` but the matcher text contains no root clause / unsubstituted
  placeholder, log a warning (templating had nothing to substitute).

No new config surface — just a guard plus README docs.

---

## 8. Kratos middleware (`middleware/kratos`)

```go
package kratos

type Config struct {
    Enforcer          *enforcer.Enforcer // carries the DomainComposer
    Subject           func(ctx context.Context) (string, error)
    Domain            func(ctx context.Context) (tenantID, subTenantID string, err error)
    OperationPrefixes []string                 // enforce only these namespaces; empty = all (discouraged)
    Permissive        bool                     // audit-only: log denials, forward (caller reads own env)
    DenyMapper        func(Reason) error       // default = Kratos errors
    Logger            log.Logger
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

### 8.1 Request lifecycle

1. No transport in ctx -> pass (background jobs).
2. Operation matches none of `OperationPrefixes` -> pass (healthcheck, framework ops).
3. `RequirementFor(op)`: `nil` (un-annotated) -> fail closed (`ReasonMissingAnnotation`).
4. `Skip` -> pass. Empty resource/action -> `ReasonInvalidAnnotation`.
5. `Subject(ctx)` -> subject (fail -> `ReasonUnauthenticated`).
6. `Domain(ctx)` -> (tenant, subtenant); empty but perm required -> `ReasonNoTenant`.
7. `HasPermission(...)` -> false = `ReasonForbidden`; error = `ReasonEnforcerError`.

`Permissive=true` -> log the would-be denial, forward the request anyway (rollout mode).

### 8.2 Middleware ordering (documented in README)

RBAC must run **after** auth + tenant-context middleware so subject/domain are populated:
`recovery -> validate -> ... -> auth -> tenant -> rbac -> audit`.

---

## 9. Error handling

- Core returns plain errors; never panics. `MustHasPermission` -> sentinel `ErrUnauthorized`.
- `New` -> `ErrUnsupportedModel` on contract violation; wraps adapter/model load errors.
- Middleware maps every `Reason` through `DenyMapper`. Default: `ReasonForbidden`/
  `ReasonUnauthenticated`/`ReasonNoTenant`/`ReasonInvalid/MissingAnnotation` -> Kratos
  `errors.Forbidden`; `ReasonEnforcerError` -> `errors.InternalServer`. Consumers can remap
  any reason's status (e.g. un-annotated 500 vs 403).
- Watcher errors are logged, never fatal — stale-but-up beats down.

---

## 10. Proto (`proto/rbac/v1/rbac.proto`)

```proto
syntax = "proto3";
package rbac.v1;
option go_package = "github.com/<org>/casbin-rbac-kratos/proto/rbac/v1;rbacv1";
import "google/protobuf/descriptor.proto";

message Requirement {
  string resource = 1;
  string action   = 2;
}

extend google.protobuf.MethodOptions {
  Requirement require = 56811;   // RPC needs this permission
  bool        skip    = 56812;   // RPC is public / uses other auth
}
```

- Field numbers `56811/56812` carried over (valid extension range). README documents them
  and warns about collision risk if consumers define their own `MethodOptions` extensions.
- Generated `rbac.pb.go` is committed so consumers get the extension without regenerating.
- README ships `buf`/`protoc` gen instructions.

---

## 11. Testing strategy (TDD, table-driven, target 80%+)

Every unit built test-first (RED -> GREEN -> REFACTOR). Per package:

- **enforcer/model + matcher:** root short-circuit, super_owner, role inheritance
  (viewer<operator<manager<super_owner), branch wildcard `t:*`, global `*`,
  `keyMatch2("*","*")` trap stays false.
- **enforcer/domain:** `ComposeDom` round-trips for all input combos; `NamespacedRole`/
  `IsSystemRole` for system vs custom; default composer byte-identical to teenaii.
- **enforcer/RootSubject templating:** default `"root"`, custom value, disabled (empty).
- **enforcer/validate:** valid `sub,dom,obj,act` passes; arity-different -> `ErrUnsupportedModel`.
- **enforcer/annotation:** `RequirementFor` for skip / require / un-annotated (nil) /
  invalid (empty resource/action); cache hit path.
- **enforcer/verify:** `VerifyPolicyCoverage` missing-count via slice scan.
- **middleware/kratos:** each `Reason` path -> correct `DenyMapper` output; permissive mode
  forwards on deny; no-transport pass; prefix-miss pass; ordering doc.
- **adapter/polling:** interval re-load triggers `LoadPolicy`.
- **adapter/mongo:** change-stream watcher (integration; needs replica set — gate behind a
  build tag / env so unit runs stay hermetic).
- **examples/kratos-service:** compiles and runs as an integration smoke.

Mocks only where unavoidable (transport context, clock for polling). Casbin enforcement is
tested against real in-memory adapters, not mocks.

---

## 12. Correctness gaps addressed (from brief §4)

1. **Multi-instance staleness** -> generic `Watcher` interface + mongo change-stream +
   polling impls; README documents the hazard loudly and that nil Watcher = no live reload.
2. **Extension field numbers** documented with collision warning.
3. **super_owner double-grant** (matcher short-circuit + seed) -> matcher short-circuit is
   the single source of truth; README notes it; no seeded `super_owner,*,*,*` shipped.
4. **keyMatch2 trap** -> guard + slice-scan verify carried forward with comments.
5. **Un-annotated -> 500** -> stays fail-closed, status configurable via `DenyMapper`.

---

## 13. Publishing checklist

- [ ] Proto `go_package` -> new repo; commit generated `.pb.go`.
- [ ] `buf`/`protoc` gen instructions in README; document ext numbers `56811/56812`.
- [ ] `DefaultModel` documented with `{{root}}` templating + `keyMatch2("*","*")` trap note.
- [ ] `Watcher` interface + mongo change-stream + polling impls + multi-instance hazard doc.
- [ ] `examples/kratos-service/` runnable.
- [ ] Unit tests per §11; coverage >= 80%.
- [ ] README: quickstart, model explanation + custom-model contract, fail-closed contract,
      middleware ordering, rollout via Permissive.
- [ ] SemVer `v0.1.0`; document Kratos v2 + casbin/v2 + mongo-driver version matrix.
- [ ] LICENSE (Apache-2.0 or MIT — decide before publish).

---

## 14. Out of scope (consumer responsibility)

Policy seeding, app resource/action lists, the store choice itself, auth/tenant context
extraction, and any teenaii-specific policy constants. The library provides mechanism;
the consumer provides policy + context.

---

## 15. Deferred / open (non-blocking)

- LICENSE choice (Apache-2.0 vs MIT) — pick before publish.
- Repeated `Requirement` pairs (AND/OR) — deferred; single-pair now, add back-compat later.
- `<org>` / final repo name + module path — fill in before `go.mod` is finalized.
