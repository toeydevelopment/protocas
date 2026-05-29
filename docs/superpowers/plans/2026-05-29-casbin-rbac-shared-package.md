# casbin-rbac-kratos Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a generic, config-driven Go library that enforces per-RPC RBAC declared via protobuf `MethodOptions`, with multi-tenant Casbin enforcement, a transport-agnostic core, and an optional thin Kratos middleware.

**Architecture:** Three layers, one-way deps. `proto/rbac/v1` defines `require`/`skip` `MethodOptions`. `enforcer` is the transport- and store-agnostic core (model, domain, annotation resolver, config/validation, verify, watcher interface). `middleware/kratos` is a thin adapter on top. `adapter/polling` and `adapter/mongo` are optional Watcher impls. The core never imports Kratos or Mongo.

**Tech Stack:** Go 1.26, `github.com/casbin/casbin/v2`, `google.golang.org/protobuf` (proto reflection), Kratos v2 (`github.com/go-kratos/kratos/v2`) in the middleware layer only, `go.mongodb.org/mongo-driver/v2` in `adapter/mongo` only. Module path: `github.com/toeydevelopment/protocas`. Tests use the Go stdlib `testing` package (no assertion libs).

**Reference spec:** `docs/superpowers/specs/2026-05-29-casbin-rbac-shared-package-design.md`.

**Conventions for every task below:**
- TDD: write the test, watch it fail for the right reason, write minimal code, watch it pass, commit.
- Run a single package's tests with `go test ./<pkg>/... -run <TestName> -v`.
- Generated proto code (`*.pb.go`) is the documented TDD exception — generate it, don't hand-write tests for the generator.

---

## Task 0: Repo scaffold + dependencies

**Files:**
- Modify: `go.mod` (already: `module github.com/toeydevelopment/protocas`, `go 1.26.2`)
- Create: `LICENSE`, `README.md` (skeleton), `.gitignore`

- [ ] **Step 1: Initialize git**

Run:
```bash
git init
```
Expected: `Initialized empty Git repository`.

- [ ] **Step 2: Add `.gitignore`**

Create `.gitignore`:
```gitignore
# Go
*.test
*.out
/coverage.out
/bin/
# Editor
.DS_Store
```

- [ ] **Step 3: Add core dependency**

Run:
```bash
go get github.com/casbin/casbin/v2@latest
```
Expected: `go.mod`/`go.sum` updated with `github.com/casbin/casbin/v2`.

- [ ] **Step 4: Add a placeholder LICENSE + README**

Create `LICENSE` with the Apache-2.0 license text (header line `Apache License, Version 2.0`). Create `README.md`:
```markdown
# casbin-rbac-kratos

Generic, config-driven Casbin RBAC with proto-annotation authorization for Go (Kratos v2 first-class).

See `docs/superpowers/specs/2026-05-29-casbin-rbac-shared-package-design.md` for the design.

## Status
Pre-release (v0.1.0 in progress).
```

- [ ] **Step 5: Verify the module builds**

Run:
```bash
go build ./...
```
Expected: exits 0 (no packages yet, no error).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: scaffold module, license, gitignore, casbin dep"
```

---

## Task 1: `rbacmodel` — DefaultModel + Render

**Files:**
- Create: `rbacmodel/model.go`
- Test: `rbacmodel/model_test.go`

- [ ] **Step 1: Write the failing test**

Create `rbacmodel/model_test.go`:
```go
package rbacmodel

import "strings"

import "testing"

func TestRenderRootActive(t *testing.T) {
	out := Render(DefaultModel, "root", false)
	if !strings.Contains(out, `r.sub == "root" ||`) {
		t.Fatalf("expected root clause for active root, got:\n%s", out)
	}
	if strings.Contains(out, "{{ROOT_CLAUSE}}") {
		t.Fatalf("placeholder not substituted:\n%s", out)
	}
}

func TestRenderCustomRoot(t *testing.T) {
	out := Render(DefaultModel, "superadmin", false)
	if !strings.Contains(out, `r.sub == "superadmin" ||`) {
		t.Fatalf("expected custom root clause, got:\n%s", out)
	}
}

func TestRenderRootDisabled(t *testing.T) {
	out := Render(DefaultModel, "root", true)
	if strings.Contains(out, "r.sub ==") {
		t.Fatalf("expected no root clause when disabled, got:\n%s", out)
	}
	if strings.Contains(out, "{{ROOT_CLAUSE}}") {
		t.Fatalf("placeholder not substituted:\n%s", out)
	}
}

func TestDefaultModelHasRequestShape(t *testing.T) {
	if !strings.Contains(DefaultModel, "r = sub, dom, obj, act") {
		t.Fatalf("DefaultModel missing expected request definition")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./rbacmodel/... -v`
Expected: FAIL — `undefined: Render` and `undefined: DefaultModel`.

- [ ] **Step 3: Write minimal implementation**

Create `rbacmodel/model.go`:
```go
// Package rbacmodel holds the default Casbin model text for the RBAC library.
//
// The model uses the request shape `r = sub, dom, obj, act`:
//   - sub: subject (user id, or a role name in g parent links)
//   - dom: tenant domain, e.g. "tenant:subtenant"; "tenant:*" = tenant-wide; "*" = global
//   - obj: resource (e.g. "financial")
//   - act: action (e.g. "view")
//
// TRAP: keyMatch2("*","*") compiles to the invalid regex ^*$ and silently
// returns false. The matcher therefore guards domain "*" explicitly with
// `p.dom == "*"`, and enforcer.VerifyPolicyCoverage scans policies directly
// instead of calling Enforce/HasPolicy. Do NOT remove these guards.
package rbacmodel

import "fmt"

// DefaultModel is the Casbin model with a {{ROOT_CLAUSE}} placeholder at the
// head of the matcher. Render substitutes it. The super_owner role and the
// p.dom=="*" guard are intentional; see the package doc.
const DefaultModel = `[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = {{ROOT_CLAUSE}}g(r.sub, "super_owner", r.dom) || (g(r.sub, p.sub, r.dom) && (p.dom == "*" || keyMatch2(r.dom, p.dom)) && keyMatch(r.obj, p.obj) && keyMatch(r.act, p.act))
`

// Render substitutes the {{ROOT_CLAUSE}} placeholder. When disableRoot is true
// the clause is removed; otherwise it becomes `r.sub == "<rootSubject>" || `.
func Render(model, rootSubject string, disableRoot bool) string {
	clause := ""
	if !disableRoot {
		clause = fmt.Sprintf(`r.sub == %q || `, rootSubject)
	}
	return replaceAll(model, "{{ROOT_CLAUSE}}", clause)
}

func replaceAll(s, old, new string) string {
	// stdlib strings.ReplaceAll equivalent kept local to avoid an import churn;
	// use strings.ReplaceAll directly is fine too.
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

> Note: the helper funcs above are deliberately trivial. If you prefer, replace
> `replaceAll(model, ...)` with `strings.ReplaceAll(model, ...)` and delete the
> two helpers plus add `"strings"` to imports. Keep behavior identical.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./rbacmodel/... -v`
Expected: PASS (all four tests).

- [ ] **Step 5: Commit**

```bash
git add rbacmodel/
git commit -m "feat(rbacmodel): default model + root-clause rendering"
```

---

## Task 2: `enforcer` domain helpers

**Files:**
- Create: `enforcer/domain.go`
- Test: `enforcer/domain_test.go`

- [ ] **Step 1: Write the failing test**

Create `enforcer/domain_test.go`:
```go
package enforcer

import "testing"

func TestComposeDom(t *testing.T) {
	cases := []struct {
		tenant, sub, want string
	}{
		{"", "", "*"},
		{"biz1", "", "biz1:*"},
		{"biz1", "branch1", "biz1:branch1"},
	}
	for _, c := range cases {
		if got := ComposeDom(c.tenant, c.sub); got != c.want {
			t.Errorf("ComposeDom(%q,%q) = %q, want %q", c.tenant, c.sub, got, c.want)
		}
	}
}

func TestIsWildcardDom(t *testing.T) {
	if !IsWildcardDom("*") {
		t.Error("'*' should be wildcard")
	}
	if !IsWildcardDom("biz1:*") {
		t.Error("'biz1:*' should be wildcard")
	}
	if IsWildcardDom("biz1:branch1") {
		t.Error("'biz1:branch1' should not be wildcard")
	}
}

func TestNamespacedRole(t *testing.T) {
	def := DefaultSystemRoles()
	// system role: un-namespaced regardless of tenant
	if got := NamespacedRole("biz1", "manager", def); got != "manager" {
		t.Errorf("system role should be un-namespaced, got %q", got)
	}
	// custom role: namespaced tenant:name
	if got := NamespacedRole("biz1", "accountant", def); got != "biz1:accountant" {
		t.Errorf("custom role should be namespaced, got %q", got)
	}
}

func TestIsSystemRole(t *testing.T) {
	def := DefaultSystemRoles()
	if !IsSystemRole("super_owner", def) {
		t.Error("super_owner should be a system role")
	}
	if IsSystemRole("accountant", def) {
		t.Error("accountant should not be a system role")
	}
}

func TestDefaultDomainComposerMatchesComposeDom(t *testing.T) {
	if DefaultDomainComposer("biz1", "branch1") != ComposeDom("biz1", "branch1") {
		t.Error("DefaultDomainComposer must equal ComposeDom")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./enforcer/... -run 'TestComposeDom|TestIsWildcardDom|TestNamespacedRole|TestIsSystemRole|TestDefaultDomainComposer' -v`
Expected: FAIL — undefined `ComposeDom`, `IsWildcardDom`, `NamespacedRole`, `IsSystemRole`, `DefaultSystemRoles`, `DefaultDomainComposer`.

- [ ] **Step 3: Write minimal implementation**

Create `enforcer/domain.go`:
```go
package enforcer

import "strings"

// DomainComposer maps (tenantID, subTenantID) to a Casbin dom string.
type DomainComposer func(tenantID, subTenantID string) string

// ComposeDom is the default tenant:subtenant composition:
//   ("","")        -> "*"        (global / system)
//   ("biz","")     -> "biz:*"    (tenant-wide)
//   ("biz","br")   -> "biz:br"   (specific sub-tenant)
func ComposeDom(tenantID, subTenantID string) string {
	if tenantID == "" {
		return "*"
	}
	if subTenantID == "" {
		return tenantID + ":*"
	}
	return tenantID + ":" + subTenantID
}

// DefaultDomainComposer is ComposeDom as a DomainComposer value.
func DefaultDomainComposer(tenantID, subTenantID string) string {
	return ComposeDom(tenantID, subTenantID)
}

// IsWildcardDom reports whether dom is global ("*") or tenant-wide ("tenant:*").
func IsWildcardDom(dom string) bool {
	return dom == "*" || strings.HasSuffix(dom, ":*")
}

// DefaultSystemRoles is the default set of un-namespaced (global) roles.
func DefaultSystemRoles() map[string]struct{} {
	return map[string]struct{}{
		"root":        {},
		"super_owner": {},
		"manager":     {},
		"operator":    {},
		"viewer":      {},
	}
}

// IsSystemRole reports whether name is in the system-role set.
func IsSystemRole(name string, systemRoles map[string]struct{}) bool {
	_, ok := systemRoles[name]
	return ok
}

// NamespacedRole returns the storage name for a role: system roles stay
// un-namespaced (global), custom roles become "<tenant>:<name>".
func NamespacedRole(tenantID, name string, systemRoles map[string]struct{}) string {
	if IsSystemRole(name, systemRoles) {
		return name
	}
	return tenantID + ":" + name
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./enforcer/... -run 'TestComposeDom|TestIsWildcardDom|TestNamespacedRole|TestIsSystemRole|TestDefaultDomainComposer' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add enforcer/domain.go enforcer/domain_test.go
git commit -m "feat(enforcer): domain + role composition helpers"
```

---

## Task 3: `enforcer` config + model validation

**Files:**
- Create: `enforcer/config.go`, `enforcer/validate.go`
- Test: `enforcer/validate_test.go`

- [ ] **Step 1: Write the failing test**

Create `enforcer/validate_test.go`:
```go
package enforcer

import (
	"errors"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/toeydevelopment/protocas/rbacmodel"
)

func TestValidateModelAcceptsDefault(t *testing.T) {
	m, err := model.NewModelFromString(rbacmodel.Render(rbacmodel.DefaultModel, "root", false))
	if err != nil {
		t.Fatalf("model parse: %v", err)
	}
	if err := validateModel(m); err != nil {
		t.Fatalf("default model should validate, got %v", err)
	}
}

func TestValidateModelRejectsWrongArity(t *testing.T) {
	const noDom = `[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(noDom)
	if err != nil {
		t.Fatalf("model parse: %v", err)
	}
	err = validateModel(m)
	if !errors.Is(err, ErrUnsupportedModel) {
		t.Fatalf("expected ErrUnsupportedModel, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./enforcer/... -run 'TestValidateModel' -v`
Expected: FAIL — undefined `validateModel`, `ErrUnsupportedModel`.

- [ ] **Step 3: Write minimal implementation**

Create `enforcer/config.go`:
```go
package enforcer

import (
	"errors"

	"github.com/casbin/casbin/v2/persist"
)

// ErrUnauthorized is returned by MustHasPermission when access is denied.
var ErrUnauthorized = errors.New("rbac: unauthorized")

// ErrUnsupportedModel is returned by New when the model's request definition
// is not the supported `sub, dom, obj, act` shape. Use the raw casbin enforcer
// directly for arity-different models.
var ErrUnsupportedModel = errors.New("rbac: unsupported model request shape (want sub, dom, obj, act)")

// Config configures the enforcer. The zero value is usable: it yields the
// default model, default domain composer, default system roles, and root "root".
type Config struct {
	Model          string                // empty -> rbacmodel.DefaultModel
	DomainComposer DomainComposer         // nil -> DefaultDomainComposer
	SystemRoles    map[string]struct{}    // nil -> DefaultSystemRoles()
	RootSubject    string                 // empty -> "root"
	DisableRoot    bool                   // true -> no superuser short-circuit
	Watcher        persist.Watcher        // nil -> no live reload
}

func (c Config) rootSubject() string {
	if c.RootSubject == "" {
		return "root"
	}
	return c.RootSubject
}

func (c Config) composer() DomainComposer {
	if c.DomainComposer == nil {
		return DefaultDomainComposer
	}
	return c.DomainComposer
}
```

Create `enforcer/validate.go`:
```go
package enforcer

import "github.com/casbin/casbin/v2/model"

// wantRequestTokens is the supported request definition. Casbin prefixes each
// token with the section key, so `r = sub, dom, obj, act` becomes these tokens.
var wantRequestTokens = []string{"r_sub", "r_dom", "r_obj", "r_act"}

// validateModel enforces the library's request-shape contract.
func validateModel(m model.Model) error {
	r, ok := m["r"]
	if !ok {
		return ErrUnsupportedModel
	}
	def, ok := r["r"]
	if !ok {
		return ErrUnsupportedModel
	}
	if len(def.Tokens) != len(wantRequestTokens) {
		return ErrUnsupportedModel
	}
	for i, tok := range wantRequestTokens {
		if def.Tokens[i] != tok {
			return ErrUnsupportedModel
		}
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./enforcer/... -run 'TestValidateModel' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add enforcer/config.go enforcer/validate.go enforcer/validate_test.go
git commit -m "feat(enforcer): config + model request-shape validation"
```

---

## Task 4: `enforcer` New + HasPermission/MustHasPermission

**Files:**
- Create: `enforcer/enforcer.go`
- Test: `enforcer/enforcer_test.go`

- [ ] **Step 1: Write the failing test**

Create `enforcer/enforcer_test.go`:
```go
package enforcer

import (
	"errors"
	"testing"
)

// newSeeded builds an in-memory enforcer (nil adapter) and seeds policies.
func newSeeded(t *testing.T, cfg Config) *Enforcer {
	t.Helper()
	e, err := New(nil, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestRootShortCircuits(t *testing.T) {
	e := newSeeded(t, Config{})
	ok, err := e.HasPermission("root", "biz1", "branch1", "anything", "delete")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !ok {
		t.Fatal("root must be allowed everything")
	}
}

func TestDisableRoot(t *testing.T) {
	e := newSeeded(t, Config{DisableRoot: true})
	ok, _ := e.HasPermission("root", "biz1", "branch1", "anything", "delete")
	if ok {
		t.Fatal("root must NOT be magic when DisableRoot is set")
	}
}

func TestRoleGrantWithTenantWildcard(t *testing.T) {
	e := newSeeded(t, Config{})
	// policy: role "biz1:viewer" can view financial in tenant-wide biz1:*
	if _, err := e.AddPolicy("biz1:viewer", "biz1:*", "financial", "view"); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	// user u1 has role biz1:viewer in domain biz1:branch1
	if _, err := e.AddGroupingPolicy("u1", "biz1:viewer", "biz1:branch1"); err != nil {
		t.Fatalf("add grouping: %v", err)
	}
	ok, err := e.HasPermission("u1", "biz1", "branch1", "financial", "view")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !ok {
		t.Fatal("tenant-wide policy biz1:* should cover branch1 via keyMatch2")
	}
	// negative: different action denied
	ok, _ = e.HasPermission("u1", "biz1", "branch1", "financial", "delete")
	if ok {
		t.Fatal("delete must be denied")
	}
}

func TestMustHasPermissionReturnsErrUnauthorized(t *testing.T) {
	e := newSeeded(t, Config{})
	err := e.MustHasPermission("nobody", "biz1", "branch1", "financial", "view")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestNewRejectsUnsupportedModel(t *testing.T) {
	const noDom = `[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	_, err := New(nil, Config{Model: noDom})
	if !errors.Is(err, ErrUnsupportedModel) {
		t.Fatalf("expected ErrUnsupportedModel, got %v", err)
	}
}

func TestCustomDomainComposerFlowsThrough(t *testing.T) {
	// composer that ignores subtenant entirely -> always tenant:*
	cfg := Config{DomainComposer: func(tenant, _ string) string {
		if tenant == "" {
			return "*"
		}
		return tenant + ":*"
	}}
	e := newSeeded(t, cfg)
	if _, err := e.AddPolicy("biz1:viewer", "biz1:*", "financial", "view"); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	if _, err := e.AddGroupingPolicy("u1", "biz1:viewer", "biz1:*"); err != nil {
		t.Fatalf("add grouping: %v", err)
	}
	ok, err := e.HasPermission("u1", "biz1", "ignored-branch", "financial", "view")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !ok {
		t.Fatal("custom composer should map any branch to biz1:*")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./enforcer/... -run 'TestRoot|TestDisableRoot|TestRoleGrant|TestMustHas|TestNewRejects|TestCustomDomain' -v`
Expected: FAIL — undefined `New`, `Enforcer`, methods.

- [ ] **Step 3: Write minimal implementation**

Create `enforcer/enforcer.go`:
```go
package enforcer

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"

	"github.com/toeydevelopment/protocas/rbacmodel"
)

// Enforcer wraps *casbin.Enforcer and carries the DomainComposer.
type Enforcer struct {
	*casbin.Enforcer
	composer DomainComposer
}

// New builds an Enforcer. A nil adapter yields an in-memory enforcer.
func New(adapter persist.Adapter, cfg Config) (*Enforcer, error) {
	modelText := cfg.Model
	custom := modelText != ""
	if !custom {
		modelText = rbacmodel.Render(rbacmodel.DefaultModel, cfg.rootSubject(), cfg.DisableRoot)
	}

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("rbac: parse model: %w", err)
	}
	if err := validateModel(m); err != nil {
		return nil, err
	}

	var ce *casbin.Enforcer
	if adapter == nil {
		ce, err = casbin.NewEnforcer(m)
	} else {
		ce, err = casbin.NewEnforcer(m, adapter)
	}
	if err != nil {
		return nil, fmt.Errorf("rbac: new enforcer: %w", err)
	}

	// Domain-aware role matching: g() compares r.dom against p.dom with keyMatch2
	// so a tenant-wide grant (biz:*) covers every sub-tenant.
	ce.AddNamedDomainMatchingFunc("g", "keyMatch2", util.KeyMatch2)

	if adapter != nil {
		if err := ce.LoadPolicy(); err != nil {
			return nil, fmt.Errorf("rbac: load policy: %w", err)
		}
		ce.EnableAutoSave(true)
	}
	if cfg.Watcher != nil {
		if err := ce.SetWatcher(cfg.Watcher); err != nil {
			return nil, fmt.Errorf("rbac: set watcher: %w", err)
		}
	}

	return &Enforcer{Enforcer: ce, composer: cfg.composer()}, nil
}

// HasPermission composes the dom and calls Enforce(sub, dom, obj, act).
func (e *Enforcer) HasPermission(subject, tenantID, subTenantID, resource, action string) (bool, error) {
	return e.Enforce(subject, e.composer(tenantID, subTenantID), resource, action)
}

// MustHasPermission returns ErrUnauthorized on deny, or the enforcer error.
func (e *Enforcer) MustHasPermission(subject, tenantID, subTenantID, resource, action string) error {
	ok, err := e.HasPermission(subject, tenantID, subTenantID, resource, action)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUnauthorized
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./enforcer/... -run 'TestRoot|TestDisableRoot|TestRoleGrant|TestMustHas|TestNewRejects|TestCustomDomain' -v`
Expected: PASS.

> If `TestDisableRoot` fails because the matcher still references `super_owner`
> short-circuit: note the test user is "root" not "super_owner", so disabling
> the root clause is sufficient. If casbin complains about an empty matcher
> prefix, confirm Render produced `g(r.sub, "super_owner", r.dom) || (...)` with
> no leading `||`.

- [ ] **Step 5: Run the full enforcer package to confirm no regressions**

Run: `go test ./enforcer/... -v`
Expected: PASS (domain, validate, enforcer tests all green).

- [ ] **Step 6: Commit**

```bash
git add enforcer/enforcer.go enforcer/enforcer_test.go
git commit -m "feat(enforcer): New + HasPermission/MustHasPermission with composer"
```

---

## Task 5: `enforcer` VerifyPolicyCoverage

**Files:**
- Create: `enforcer/verify.go`
- Test: `enforcer/verify_test.go`

- [ ] **Step 1: Write the failing test**

Create `enforcer/verify_test.go`:
```go
package enforcer

import "testing"

func TestVerifyPolicyCoverage(t *testing.T) {
	e := newSeeded(t, Config{})
	if _, err := e.AddPolicy("manager", "*", "financial", "view"); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	required := []PolicyTuple{
		{Role: "manager", Resource: "financial", Action: "view"}, // present
		{Role: "manager", Resource: "inventory", Action: "edit"},  // missing
	}
	if missing := VerifyPolicyCoverage(e, required); missing != 1 {
		t.Fatalf("expected 1 missing, got %d", missing)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./enforcer/... -run 'TestVerifyPolicyCoverage' -v`
Expected: FAIL — undefined `PolicyTuple`, `VerifyPolicyCoverage`.

- [ ] **Step 3: Write minimal implementation**

Create `enforcer/verify.go`:
```go
package enforcer

import "github.com/casbin/casbin/v2"

// PolicyTuple is a required (role, resource, action) grant, domain-agnostic.
type PolicyTuple struct {
	Role     string
	Resource string
	Action   string
}

// VerifyPolicyCoverage returns how many of the required tuples are absent.
//
// It scans GetPolicy() directly rather than calling Enforce/HasPolicy: the
// keyMatch2("*","*") invalid-regex trap (see rbacmodel doc) makes wildcard
// Enforce checks unreliable, so a direct slice scan is the correct approach.
func VerifyPolicyCoverage(e casbin.IEnforcer, required []PolicyTuple) (missing int) {
	policies, _ := e.GetPolicy() // [][]string of {sub, dom, obj, act}
	have := make(map[[3]string]struct{}, len(policies))
	for _, p := range policies {
		if len(p) < 4 {
			continue
		}
		have[[3]string{p[0], p[2], p[3]}] = struct{}{}
	}
	for _, r := range required {
		if _, ok := have[[3]string{r.Role, r.Resource, r.Action}]; !ok {
			missing++
		}
	}
	return missing
}
```

> Casbin v2 `GetPolicy()` signature changed across versions: older returns
> `[][]string`, newer returns `([][]string, error)`. The code above assumes the
> two-value form. If the compiler reports "assignment mismatch", change the line
> to `policies := e.GetPolicy()` and drop the `_`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./enforcer/... -run 'TestVerifyPolicyCoverage' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add enforcer/verify.go enforcer/verify_test.go
git commit -m "feat(enforcer): VerifyPolicyCoverage via direct policy scan"
```

---

## Task 6: Proto definition + generated code

**Files:**
- Create: `proto/rbac/v1/rbac.proto`
- Create: `proto/rbac/v1/rbac.pb.go` (generated)
- Create: `buf.yaml`, `buf.gen.yaml`
- Create: `internal/testdata/proto/rbactest/v1/svc.proto` + generated `svc.pb.go`, `svc_grpc.pb.go` (test fixtures for the annotation resolver)

> This task generates code. Per TDD policy, generated code is exempt — generate
> it, do not write tests for the generator. The annotation resolver tests in
> Task 7 consume these generated descriptors.

- [ ] **Step 1: Write the proto**

Create `proto/rbac/v1/rbac.proto`:
```proto
syntax = "proto3";

package rbac.v1;

option go_package = "github.com/toeydevelopment/protocas/proto/rbac/v1;rbacv1";

import "google/protobuf/descriptor.proto";

// Requirement is the permission an RPC needs.
message Requirement {
  string resource = 1; // e.g. "financial", "inventory"
  string action   = 2; // e.g. "view", "add", "edit", "delete"
}

extend google.protobuf.MethodOptions {
  // require declares the permission this RPC needs.
  Requirement require = 56811;
  // skip marks the RPC as public / authorized elsewhere.
  bool skip = 56812;
}
```

- [ ] **Step 2: Write the test fixture proto**

Create `internal/testdata/proto/rbactest/v1/svc.proto`:
```proto
syntax = "proto3";

package rbactest.v1;

option go_package = "github.com/toeydevelopment/protocas/internal/testdata/proto/rbactest/v1;rbactestv1";

import "rbac/v1/rbac.proto";

message Empty {}

service Svc {
  // annotated with a permission requirement
  rpc Guarded(Empty) returns (Empty) {
    option (rbac.v1.require) = { resource: "financial" action: "view" };
  }
  // explicitly public
  rpc Public(Empty) returns (Empty) {
    option (rbac.v1.skip) = true;
  }
  // un-annotated
  rpc Bare(Empty) returns (Empty) {}
  // invalid: require with empty fields
  rpc Invalid(Empty) returns (Empty) {
    option (rbac.v1.require) = { resource: "" action: "" };
  }
}
```

- [ ] **Step 3: Add buf config**

Create `buf.yaml`:
```yaml
version: v2
modules:
  - path: proto
  - path: internal/testdata/proto
deps: []
lint:
  use:
    - STANDARD
breaking:
  use:
    - FILE
```

Create `buf.gen.yaml`:
```yaml
version: v2
managed:
  enabled: false
plugins:
  - remote: buf.build/protocolbuffers/go
    out: .
    opt: paths=source_relative
  - remote: buf.build/grpc/go
    out: .
    opt: paths=source_relative
```

> The `paths=source_relative` + `go_package` with full module path means the
> generated files land at `proto/rbac/v1/rbac.pb.go` and
> `internal/testdata/proto/rbactest/v1/svc*.pb.go`. Adjust if your buf layout
> differs; the requirement is only that the generated Go packages are importable
> at those module paths.

- [ ] **Step 4: Generate**

Run:
```bash
buf generate
```
Expected: creates `proto/rbac/v1/rbac.pb.go` (with `E_Require`, `E_Skip`, `Requirement`) and `internal/testdata/proto/rbactest/v1/svc.pb.go` + `svc_grpc.pb.go`.

If `buf` is unavailable, fall back to `protoc` with `protoc-gen-go`/`protoc-gen-go-grpc` on the PATH and equivalent flags; STOP and ask the human partner if neither toolchain is installed.

- [ ] **Step 5: Tidy + build**

Run:
```bash
go mod tidy
go build ./...
```
Expected: exits 0; `google.golang.org/protobuf` and `google.golang.org/grpc` added to `go.mod`.

- [ ] **Step 6: Commit**

```bash
git add proto/ internal/testdata/ buf.yaml buf.gen.yaml go.mod go.sum
git commit -m "feat(proto): require/skip MethodOptions + generated code + test fixtures"
```

---

## Task 7: `enforcer` annotation resolver

**Files:**
- Create: `enforcer/annotation.go`
- Test: `enforcer/annotation_test.go`

- [ ] **Step 1: Write the failing test**

Create `enforcer/annotation_test.go`:
```go
package enforcer

import (
	"testing"

	// Blank import registers the test service descriptors in the global registry.
	_ "github.com/toeydevelopment/protocas/internal/testdata/proto/rbactest/v1"
)

func TestRequirementForGuarded(t *testing.T) {
	got, err := RequirementFor("/rbactest.v1.Svc/Guarded")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got == nil || got.Skip || got.Resource != "financial" || got.Action != "view" {
		t.Fatalf("unexpected requirement: %+v", got)
	}
}

func TestRequirementForPublic(t *testing.T) {
	got, err := RequirementFor("/rbactest.v1.Svc/Public")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got == nil || !got.Skip {
		t.Fatalf("expected skip=true, got %+v", got)
	}
}

func TestRequirementForBareIsNil(t *testing.T) {
	got, err := RequirementFor("/rbactest.v1.Svc/Bare")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != nil {
		t.Fatalf("un-annotated method should return nil requirement, got %+v", got)
	}
}

func TestRequirementForInvalid(t *testing.T) {
	got, err := RequirementFor("/rbactest.v1.Svc/Invalid")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// require present but empty fields -> Requirement with empty resource/action,
	// Skip=false. The middleware (Task 8) classifies this as ReasonInvalidAnnotation.
	if got == nil || got.Skip || got.Resource != "" || got.Action != "" {
		t.Fatalf("expected empty require, got %+v", got)
	}
}

func TestRequirementForUnknownOperation(t *testing.T) {
	_, err := RequirementFor("/rbactest.v1.Svc/DoesNotExist")
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./enforcer/... -run 'TestRequirementFor' -v`
Expected: FAIL — undefined `RequirementFor`, `Requirement`.

- [ ] **Step 3: Write minimal implementation**

Create `enforcer/annotation.go`:
```go
package enforcer

import (
	"fmt"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	rbacv1 "github.com/toeydevelopment/protocas/proto/rbac/v1"
)

// Requirement is the resolved annotation for an RPC. A nil *Requirement means
// the method is un-annotated (caller decides fail-closed).
type Requirement struct {
	Resource string
	Action   string
	Skip     bool
}

var reqCache sync.Map // operation string -> *Requirement (or nilRequirement sentinel)

type cachedResult struct {
	req *Requirement
	err error
}

// RequirementFor resolves the rbac annotation for a Kratos-style operation
// string "/pkg.v1.Svc/Method" via proto reflection. Results are cached because
// operation strings are stable for the life of the process.
func RequirementFor(operation string) (*Requirement, error) {
	if v, ok := reqCache.Load(operation); ok {
		c := v.(cachedResult)
		return c.req, c.err
	}
	req, err := resolve(operation)
	reqCache.Store(operation, cachedResult{req: req, err: err})
	return req, err
}

func resolve(operation string) (*Requirement, error) {
	svc, method, ok := splitOperation(operation)
	if !ok {
		return nil, fmt.Errorf("rbac: malformed operation %q", operation)
	}
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(svc))
	if err != nil {
		return nil, fmt.Errorf("rbac: service %q not found: %w", svc, err)
	}
	sd, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("rbac: %q is not a service", svc)
	}
	md := sd.Methods().ByName(protoreflect.Name(method))
	if md == nil {
		return nil, fmt.Errorf("rbac: method %q not found on %q", method, svc)
	}
	opts := md.Options()
	if opts == nil {
		return nil, nil
	}
	if proto.HasExtension(opts, rbacv1.E_Skip) && proto.GetExtension(opts, rbacv1.E_Skip).(bool) {
		return &Requirement{Skip: true}, nil
	}
	if proto.HasExtension(opts, rbacv1.E_Require) {
		r, _ := proto.GetExtension(opts, rbacv1.E_Require).(*rbacv1.Requirement)
		if r != nil {
			return &Requirement{Resource: r.GetResource(), Action: r.GetAction()}, nil
		}
	}
	return nil, nil
}

// splitOperation parses "/pkg.v1.Svc/Method" -> ("pkg.v1.Svc", "Method").
func splitOperation(op string) (svc, method string, ok bool) {
	op = strings.TrimPrefix(op, "/")
	i := strings.LastIndex(op, "/")
	if i <= 0 || i == len(op)-1 {
		return "", "", false
	}
	return op[:i], op[i+1:], true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./enforcer/... -run 'TestRequirementFor' -v`
Expected: PASS (all five tests).

- [ ] **Step 5: Run the whole enforcer package**

Run: `go test ./enforcer/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add enforcer/annotation.go enforcer/annotation_test.go
git commit -m "feat(enforcer): proto-reflection annotation resolver with cache"
```

---

## Task 8: `middleware/kratos`

**Files:**
- Create: `middleware/kratos/config.go`, `middleware/kratos/middleware.go`
- Test: `middleware/kratos/middleware_test.go`

- [ ] **Step 1: Add Kratos dependency**

Run:
```bash
go get github.com/go-kratos/kratos/v2@latest
```
Expected: `go.mod` updated.

- [ ] **Step 2: Write the failing test**

Create `middleware/kratos/middleware_test.go`:
```go
package kratos

import (
	"context"
	"errors"
	"testing"

	"github.com/go-kratos/kratos/v2/transport"

	"github.com/toeydevelopment/protocas/enforcer"
	_ "github.com/toeydevelopment/protocas/internal/testdata/proto/rbactest/v1"
)

// fakeTransport satisfies transport.Transporter with a fixed operation.
type fakeTransport struct {
	op string
}

func (f fakeTransport) Kind() transport.Kind            { return transport.KindGRPC }
func (f fakeTransport) Endpoint() string                { return "" }
func (f fakeTransport) Operation() string               { return f.op }
func (f fakeTransport) RequestHeader() transport.Header { return nil }
func (f fakeTransport) ReplyHeader() transport.Header   { return nil }

func ctxWithOp(op string) context.Context {
	return transport.NewServerContext(context.Background(), fakeTransport{op: op})
}

func seededEnforcer(t *testing.T) *enforcer.Enforcer {
	t.Helper()
	e, err := enforcer.New(nil, enforcer.Config{})
	if err != nil {
		t.Fatalf("enforcer.New: %v", err)
	}
	_, _ = e.AddPolicy("biz1:viewer", "biz1:*", "financial", "view")
	_, _ = e.AddGroupingPolicy("u1", "biz1:viewer", "biz1:branch1")
	return e
}

func baseConfig(t *testing.T, subject string) Config {
	return Config{
		Enforcer:          seededEnforcer(t),
		OperationPrefixes: []string{"/rbactest.v1."},
		Subject: func(context.Context) (string, error) {
			if subject == "" {
				return "", errors.New("no subject")
			}
			return subject, nil
		},
		Domain: func(context.Context) (string, string, error) {
			return "biz1", "branch1", nil
		},
	}
}

// okHandler records that it was reached.
func okHandler(reached *bool) func(context.Context, any) (any, error) {
	return func(ctx context.Context, req any) (any, error) {
		*reached = true
		return "ok", nil
	}
}

func TestAllowsPermittedRPC(t *testing.T) {
	var reached bool
	mw := New(baseConfig(t, "u1"))
	_, err := mw(okHandler(&reached))(ctxWithOp("/rbactest.v1.Svc/Guarded"), nil)
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if !reached {
		t.Fatal("handler should have been reached")
	}
}

func TestDeniesForbiddenRPC(t *testing.T) {
	var reached bool
	mw := New(baseConfig(t, "nobody"))
	_, err := mw(okHandler(&reached))(ctxWithOp("/rbactest.v1.Svc/Guarded"), nil)
	if err == nil {
		t.Fatal("expected forbidden error")
	}
	if reached {
		t.Fatal("handler must NOT be reached on deny")
	}
}

func TestSkipPasses(t *testing.T) {
	var reached bool
	mw := New(baseConfig(t, "nobody"))
	_, err := mw(okHandler(&reached))(ctxWithOp("/rbactest.v1.Svc/Public"), nil)
	if err != nil || !reached {
		t.Fatalf("skip RPC should pass; err=%v reached=%v", err, reached)
	}
}

func TestUnannotatedFailsClosed(t *testing.T) {
	var reached bool
	mw := New(baseConfig(t, "u1"))
	_, err := mw(okHandler(&reached))(ctxWithOp("/rbactest.v1.Svc/Bare"), nil)
	if err == nil {
		t.Fatal("un-annotated RPC must fail closed")
	}
	if reached {
		t.Fatal("handler must NOT be reached for un-annotated RPC")
	}
}

func TestPrefixMissPasses(t *testing.T) {
	var reached bool
	mw := New(baseConfig(t, "nobody"))
	_, err := mw(okHandler(&reached))(ctxWithOp("/other.v1.Svc/Whatever"), nil)
	if err != nil || !reached {
		t.Fatalf("non-matching prefix should pass through; err=%v reached=%v", err, reached)
	}
}

func TestNoTransportPasses(t *testing.T) {
	var reached bool
	mw := New(baseConfig(t, "u1"))
	_, err := mw(okHandler(&reached))(context.Background(), nil)
	if err != nil || !reached {
		t.Fatalf("no-transport ctx should pass; err=%v reached=%v", err, reached)
	}
}

func TestPermissiveForwardsOnDeny(t *testing.T) {
	var reached bool
	cfg := baseConfig(t, "nobody")
	cfg.Permissive = true
	mw := New(cfg)
	_, err := mw(okHandler(&reached))(ctxWithOp("/rbactest.v1.Svc/Guarded"), nil)
	if err != nil {
		t.Fatalf("permissive mode should forward, got %v", err)
	}
	if !reached {
		t.Fatal("permissive mode must reach the handler even on would-be deny")
	}
}

func TestCustomDenyMapper(t *testing.T) {
	var gotReason Reason
	cfg := baseConfig(t, "nobody")
	sentinel := errors.New("denied")
	cfg.DenyMapper = func(r Reason) error { gotReason = r; return sentinel }
	mw := New(cfg)
	_, err := mw(okHandler(new(bool)))(ctxWithOp("/rbactest.v1.Svc/Guarded"), nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if gotReason != ReasonForbidden {
		t.Fatalf("expected ReasonForbidden, got %v", gotReason)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./middleware/kratos/... -v`
Expected: FAIL — undefined `New`, `Config`, `Reason`, `ReasonForbidden`.

- [ ] **Step 4: Write minimal implementation**

Create `middleware/kratos/config.go`:
```go
package kratos

import (
	"context"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"

	"github.com/toeydevelopment/protocas/enforcer"
)

// Reason classifies why a request was (or would be) denied.
type Reason int

const (
	ReasonMissingAnnotation Reason = iota // un-annotated RPC (config error)
	ReasonInvalidAnnotation               // require with empty resource/action
	ReasonUnauthenticated                 // Subject() failed
	ReasonNoTenant                        // Domain() empty but RPC requires perm
	ReasonForbidden                       // Enforce returned false
	ReasonEnforcerError                   // Enforce returned error
)

// Config configures the Kratos RBAC middleware.
type Config struct {
	Enforcer          *enforcer.Enforcer
	Subject           func(ctx context.Context) (string, error)
	Domain            func(ctx context.Context) (tenantID, subTenantID string, err error)
	OperationPrefixes []string
	Permissive        bool
	DenyMapper        func(Reason) error
	Logger            log.Logger
}

// defaultDenyMapper maps reasons to Kratos transport errors.
func defaultDenyMapper(r Reason) error {
	switch r {
	case ReasonEnforcerError:
		return errors.InternalServer("RBAC_ERROR", "authorization check failed")
	case ReasonUnauthenticated:
		return errors.Unauthorized("RBAC_UNAUTHENTICATED", "missing or invalid subject")
	case ReasonMissingAnnotation:
		return errors.InternalServer("RBAC_MISSING_ANNOTATION", "rpc has no permission annotation")
	case ReasonInvalidAnnotation:
		return errors.InternalServer("RBAC_INVALID_ANNOTATION", "rpc annotation is invalid")
	default: // ReasonForbidden, ReasonNoTenant
		return errors.Forbidden("RBAC_DENIED", "permission denied")
	}
}

func (c Config) denyMapper() func(Reason) error {
	if c.DenyMapper == nil {
		return defaultDenyMapper
	}
	return c.DenyMapper
}

func (c Config) logger() log.Logger {
	if c.Logger == nil {
		return log.DefaultLogger
	}
	return c.Logger
}
```

Create `middleware/kratos/middleware.go`:
```go
package kratos

import (
	"context"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"

	"github.com/toeydevelopment/protocas/enforcer"
)

// New builds the RBAC middleware. RBAC must run AFTER auth + tenant-context
// middleware so Subject and Domain can read populated context.
func New(cfg Config) middleware.Middleware {
	deny := cfg.denyMapper()
	helper := log.NewHelper(cfg.logger())

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			tr, ok := transport.FromServerContext(ctx)
			if !ok {
				return handler(ctx, req) // background job, no transport
			}
			if !matchesPrefix(tr.Operation(), cfg.OperationPrefixes) {
				return handler(ctx, req)
			}

			reason, allowed := cfg.evaluate(ctx, tr.Operation(), helper)
			if allowed {
				return handler(ctx, req)
			}
			if cfg.Permissive {
				helper.Warnf("rbac: permissive forward op=%s reason=%d", tr.Operation(), reason)
				return handler(ctx, req)
			}
			return nil, deny(reason)
		}
	}
}

// evaluate returns the deny Reason and whether the request is allowed.
func (c Config) evaluate(ctx context.Context, op string, helper *log.Helper) (Reason, bool) {
	reqt, err := enforcer.RequirementFor(op)
	if err != nil || reqt == nil {
		return ReasonMissingAnnotation, false
	}
	if reqt.Skip {
		return 0, true
	}
	if reqt.Resource == "" || reqt.Action == "" {
		return ReasonInvalidAnnotation, false
	}

	subject, err := c.Subject(ctx)
	if err != nil || subject == "" {
		return ReasonUnauthenticated, false
	}
	tenantID, subTenantID, err := c.Domain(ctx)
	if err != nil {
		return ReasonNoTenant, false
	}
	if tenantID == "" && subTenantID == "" {
		return ReasonNoTenant, false
	}

	ok, err := c.Enforcer.HasPermission(subject, tenantID, subTenantID, reqt.Resource, reqt.Action)
	if err != nil {
		helper.Errorf("rbac: enforcer error op=%s: %v", op, err)
		return ReasonEnforcerError, false
	}
	if !ok {
		return ReasonForbidden, false
	}
	return 0, true
}

func matchesPrefix(op string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true // enforce on all (discouraged)
	}
	for _, p := range prefixes {
		if strings.HasPrefix(op, p) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./middleware/kratos/... -v`
Expected: PASS (all eight tests).

> If `transport.Header` is an interface your fake must satisfy with more methods,
> check the installed Kratos version's `transport` package and add the missing
> no-op methods to `fakeTransport`. If `middleware.Handler`'s request type is not
> `any` in your version, match its actual signature.

- [ ] **Step 6: Commit**

```bash
git add middleware/kratos/ go.mod go.sum
git commit -m "feat(middleware/kratos): RBAC middleware with reasons + deny mapper"
```

---

## Task 9: `adapter/polling` Watcher

**Files:**
- Create: `adapter/polling/watcher.go`
- Test: `adapter/polling/watcher_test.go`

- [ ] **Step 1: Write the failing test**

Create `adapter/polling/watcher_test.go`:
```go
package polling

import (
	"testing"
	"time"
)

func TestPollingTriggersReload(t *testing.T) {
	reloaded := make(chan struct{}, 8)
	w := New(5 * time.Millisecond)
	w.Start(func() error {
		reloaded <- struct{}{}
		return nil
	})
	defer w.Close()

	select {
	case <-reloaded:
		// got at least one reload tick
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected a reload within 500ms")
	}
}

func TestSatisfiesWatcherContract(t *testing.T) {
	w := New(time.Second)
	defer w.Close()
	if err := w.SetUpdateCallback(func(string) {}); err != nil {
		t.Fatalf("SetUpdateCallback: %v", err)
	}
	if err := w.Update(); err != nil {
		t.Fatalf("Update: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./adapter/polling/... -v`
Expected: FAIL — undefined `New`.

- [ ] **Step 3: Write minimal implementation**

Create `adapter/polling/watcher.go`:
```go
// Package polling provides a store-agnostic Casbin watcher that periodically
// reloads policy. It works with ANY adapter and needs no replica set, trading
// freshness latency (up to one interval) for simplicity. Satisfies
// persist.Watcher so it can be passed to enforcer.Config.Watcher, and exposes
// Start to drive periodic reloads.
package polling

import (
	"sync"
	"time"
)

type Watcher struct {
	interval time.Duration
	cb       func(string)
	mu       sync.Mutex
	done     chan struct{}
	started  bool
}

// New returns a polling watcher with the given reload interval.
func New(interval time.Duration) *Watcher {
	return &Watcher{interval: interval, done: make(chan struct{})}
}

// SetUpdateCallback stores Casbin's notify callback (persist.Watcher).
func (w *Watcher) SetUpdateCallback(cb func(string)) error {
	w.mu.Lock()
	w.cb = cb
	w.mu.Unlock()
	return nil
}

// Update notifies other instances (persist.Watcher). For polling this is a
// best-effort local callback; cross-instance freshness comes from the poll loop.
func (w *Watcher) Update() error {
	w.mu.Lock()
	cb := w.cb
	w.mu.Unlock()
	if cb != nil {
		cb("")
	}
	return nil
}

// Close stops the poll loop (persist.Watcher).
func (w *Watcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		close(w.done)
		w.started = false
	}
}

// Start launches the poll loop, calling reload (typically Enforcer.LoadPolicy)
// every interval until Close. Safe to call once.
func (w *Watcher) Start(reload func() error) {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return
	}
	w.started = true
	w.mu.Unlock()

	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-w.done:
				return
			case <-ticker.C:
				_ = reload()
			}
		}
	}()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./adapter/polling/... -v`
Expected: PASS.

- [ ] **Step 5: Verify it satisfies persist.Watcher at compile time**

Add to `adapter/polling/watcher.go` (after imports):
```go
import "github.com/casbin/casbin/v2/persist"

var _ persist.Watcher = (*Watcher)(nil)
```
> Merge the import into the existing import block rather than adding a second one.

Run: `go build ./adapter/polling/...`
Expected: exits 0 (confirms the interface is satisfied).

- [ ] **Step 6: Commit**

```bash
git add adapter/polling/
git commit -m "feat(adapter/polling): store-agnostic polling watcher"
```

---

## Task 10: `adapter/mongo` change-stream Watcher (integration-gated)

**Files:**
- Create: `adapter/mongo/watcher.go`
- Test: `adapter/mongo/watcher_integration_test.go` (build tag `integration`)
- Create: `adapter/mongo/doc.go`

> This package needs a MongoDB replica set (change streams require one). Its test
> is gated behind the `integration` build tag so default `go test ./...` stays
> hermetic. Verify the `go.mongodb.org/mongo-driver/v2` API version at execution;
> if the installed driver differs, adjust the change-stream calls accordingly and
> ask the human partner if unsure.

- [ ] **Step 1: Add the mongo driver dependency**

Run:
```bash
go get go.mongodb.org/mongo-driver/v2/mongo@latest
```
Expected: `go.mod` updated.

- [ ] **Step 2: Write the implementation**

Create `adapter/mongo/doc.go`:
```go
// Package mongo provides a Casbin watcher backed by a MongoDB change stream.
// Pair it with any Casbin Mongo adapter for live, cross-instance policy reload.
//
// REQUIRES a replica set (change streams are unavailable on standalone mongod).
// For non-replica-set deployments use adapter/polling instead.
package mongo
```

Create `adapter/mongo/watcher.go`:
```go
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
```

- [ ] **Step 3: Write the integration test**

Create `adapter/mongo/watcher_integration_test.go`:
```go
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
```

- [ ] **Step 4: Verify it builds (hermetic) and the integration test is excluded by default**

Run:
```bash
go build ./adapter/mongo/...
go vet ./adapter/mongo/...
go test ./adapter/mongo/...
```
Expected: build + vet exit 0; `go test` reports `no test files` (integration test excluded without the tag).

- [ ] **Step 5: Commit**

```bash
git add adapter/mongo/ go.mod go.sum
git commit -m "feat(adapter/mongo): change-stream watcher (integration-gated)"
```

---

## Task 11: `examples/kratos-service`

**Files:**
- Create: `examples/kratos-service/main.go`
- Create: `examples/kratos-service/README.md`

> The example doubles as an integration smoke check: it must compile and the
> wiring must typecheck against the real package APIs.

- [ ] **Step 1: Write the example**

Create `examples/kratos-service/main.go`:
```go
// Command kratos-service is a minimal example wiring the RBAC middleware.
package main

import (
	"context"
	"os"

	"github.com/go-kratos/kratos/v2/log"

	"github.com/toeydevelopment/protocas/enforcer"
	rbacmw "github.com/toeydevelopment/protocas/middleware/kratos"
)

func main() {
	// In-memory enforcer for the demo (nil adapter). Real services pass a
	// persist.Adapter (e.g. a Mongo adapter) and optionally a Watcher.
	enf, err := enforcer.New(nil, enforcer.Config{})
	if err != nil {
		panic(err)
	}
	// Seed a demo policy + role assignment.
	_, _ = enf.AddPolicy("biz1:viewer", "biz1:*", "financial", "view")
	_, _ = enf.AddGroupingPolicy("u1", "biz1:viewer", "biz1:branch1")

	mw := rbacmw.New(rbacmw.Config{
		Enforcer:          enf,
		OperationPrefixes: []string{"/myapp.v1."},
		Permissive:        os.Getenv("RBAC_PERMISSIVE") == "true",
		Logger:            log.DefaultLogger,
		Subject: func(ctx context.Context) (string, error) {
			// Replace with your auth: extract the user id from ctx.
			return "u1", nil
		},
		Domain: func(ctx context.Context) (string, string, error) {
			// Replace with your tenant middleware: extract tenant/subtenant.
			return "biz1", "branch1", nil
		},
	})

	// mw is a kratos middleware.Middleware; install it AFTER auth + tenant
	// middleware, e.g.:
	//   http.NewServer(http.Middleware(recovery.Recovery(), authMW, tenantMW, mw))
	_ = mw
	log.NewHelper(log.DefaultLogger).Info("rbac example wired; install mw after auth + tenant middleware")
}
```

Create `examples/kratos-service/README.md`:
```markdown
# kratos-service example

Minimal wiring of the RBAC middleware.

- `enforcer.New(adapter, Config{})` builds the enforcer (nil adapter = in-memory).
- `kratos.New(Config{...})` builds the middleware; inject `Subject` and `Domain`.
- Install the middleware AFTER your auth and tenant-context middleware so the
  subject and tenant are populated in `ctx`.
- Annotate RPCs in your proto with `option (rbac.v1.require) = {resource action}`
  or `option (rbac.v1.skip) = true`. Un-annotated RPCs fail closed.
```

- [ ] **Step 2: Build the example**

Run:
```bash
go build ./examples/...
```
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add examples/
git commit -m "docs(examples): runnable kratos-service wiring example"
```

---

## Task 12: README + whole-suite verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Write the full README**

Replace `README.md` with:
```markdown
# casbin-rbac-kratos

Generic, config-driven Casbin RBAC with proto-annotation authorization for Go.
Transport-agnostic core; first-class Kratos v2 middleware; any Casbin store.

## Quickstart

\`\`\`go
enf, _ := enforcer.New(adapter, enforcer.Config{}) // nil adapter = in-memory
mw := kratos.New(kratos.Config{
    Enforcer:          enf,
    OperationPrefixes: []string{"/myapp.v1."},
    Subject:           func(ctx context.Context) (string, error) { /* user id */ },
    Domain:            func(ctx context.Context) (string, string, error) { /* tenant, subtenant */ },
})
// install mw AFTER auth + tenant middleware
\`\`\`

## Proto annotation

\`\`\`proto
import "rbac/v1/rbac.proto";
rpc GetBusiness(...) returns (...) { option (rbac.v1.require) = { resource: "org" action: "view" }; }
rpc ListPublic(...)  returns (...) { option (rbac.v1.skip) = true; }
\`\`\`

Extension field numbers: `require = 56811`, `skip = 56812`. If you define your own
`MethodOptions` extensions, avoid these numbers.

## Model

Request shape: `r = sub, dom, obj, act`. `dom` is `tenant:subtenant`; `tenant:*`
is tenant-wide (covered via `keyMatch2`); `*` is global. Root subject short-circuits
all checks (configurable via `Config.RootSubject`; disable with `Config.DisableRoot`).

**Custom models:** any matcher/role/effect is supported as long as the request shape
stays `sub, dom, obj, act` — `New` validates this and returns `ErrUnsupportedModel`
otherwise. Arity-different models can still use the raw embedded `*casbin.Enforcer`
and `enforcer.RequirementFor`.

**keyMatch2 trap:** `keyMatch2("*","*")` compiles to invalid regex and is silently
false; the default matcher guards `p.dom == "*"` and `VerifyPolicyCoverage` scans
policies directly. Do not remove these guards.

## Multi-instance staleness

`EnableAutoSave` + one boot-time `LoadPolicy` means policy changes on instance A are
invisible to B until B reloads. Provide `Config.Watcher`:
- `adapter/polling` — store-agnostic, interval reload, no replica set needed.
- `adapter/mongo` — change-stream, near-instant, requires a replica set.

A nil Watcher means no live reload (logged warning).

## Rollout

`Config.Permissive = true` logs would-be denials and forwards the request — use it
to audit before enforcing.

## Version matrix

Kratos v2, casbin/v2, mongo-driver/v2 (mongo adapter only). SemVer; v0.1.0.

## License

Apache-2.0.
\`\`\`
```

> The triple-backtick fences inside the README block above are shown escaped for
> this plan. Write real unescaped code fences in the actual `README.md`.

- [ ] **Step 2: Run the entire hermetic test suite with coverage**

Run:
```bash
go test ./... -cover
```
Expected: PASS for `rbacmodel`, `enforcer`, `middleware/kratos`, `adapter/polling`;
`adapter/mongo` shows `no test files`; total coverage of the core packages >= 80%.

- [ ] **Step 3: Vet + build everything**

Run:
```bash
go vet ./...
go build ./...
```
Expected: both exit 0.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: full README (quickstart, model, watcher, rollout)"
```

---

## Self-review notes (coverage of the spec)

- Spec §2 decisions 1–6 → Tasks 1 (root templating), 2 (domain), 3 (validation/contract),
  4 (layered core + composer + nil adapter), 7 (single-pair annotation), 8 (Kratos layer),
  9/10 (generic watcher + two impls).
- Spec §5 API → Tasks 3, 4, 5. Spec §5.1 root templating → Task 1. §5.3 keyMatch2 trap →
  Tasks 1 (matcher guard) + 5 (slice-scan verify).
- Spec §6 annotation resolver → Task 7.
- Spec §7 custom-model contract + fail-fast → Tasks 3, 4 (`ErrUnsupportedModel`).
- Spec §8 middleware (reasons, lifecycle, deny mapper, permissive) → Task 8.
- Spec §9 error handling → Tasks 4 (`ErrUnauthorized`), 8 (deny mapper).
- Spec §10 proto → Task 6. §11 testing → every task is TDD; mongo gated (Task 10).
- Spec §12 correctness gaps → watcher (9/10), ext-number docs + keyMatch2 + permissive (12/README).
- Spec §13 publishing checklist → Tasks 6 (proto gen), 12 (README), 0 (license).

**Deferred (spec §15, non-blocking):** repeated `Requirement` pairs; final LICENSE wording
(Apache-2.0 assumed); version-matrix pin numbers (filled at publish).
