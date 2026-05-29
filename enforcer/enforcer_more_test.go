package enforcer

import (
	"testing"

	"github.com/casbin/casbin/v2/model"
)

// noopAdapter is a minimal in-memory persist.Adapter for exercising the
// adapter != nil construction path (LoadPolicy + EnableAutoSave).
type noopAdapter struct{}

func (noopAdapter) LoadPolicy(model.Model) error                           { return nil }
func (noopAdapter) SavePolicy(model.Model) error                           { return nil }
func (noopAdapter) AddPolicy(string, string, []string) error              { return nil }
func (noopAdapter) RemovePolicy(string, string, []string) error           { return nil }
func (noopAdapter) RemoveFilteredPolicy(string, string, int, ...string) error { return nil }

func TestNewWithAdapterPath(t *testing.T) {
	e, err := New(noopAdapter{}, Config{})
	if err != nil {
		t.Fatalf("New with adapter: %v", err)
	}
	// root still short-circuits through the adapter-backed enforcer.
	ok, err := e.HasPermission("root", "biz1", "branch1", "x", "y")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !ok {
		t.Fatal("root should be allowed")
	}
}

// fakeWatcher satisfies persist.Watcher to exercise the SetWatcher path.
type fakeWatcher struct {
	callbackSet bool
	closed      bool
}

func (w *fakeWatcher) SetUpdateCallback(func(string)) error { w.callbackSet = true; return nil }
func (w *fakeWatcher) Update() error                        { return nil }
func (w *fakeWatcher) Close()                               { w.closed = true }

func TestNewWiresWatcher(t *testing.T) {
	w := &fakeWatcher{}
	_, err := New(nil, Config{Watcher: w})
	if err != nil {
		t.Fatalf("New with watcher: %v", err)
	}
	if !w.callbackSet {
		t.Fatal("SetWatcher should have registered an update callback")
	}
}

func TestNewAcceptsCustomModelWithRoles(t *testing.T) {
	const m = `[request_definition]
r = sub, dom, obj, act
[policy_definition]
p = sub, dom, obj, act
[role_definition]
g = _, _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act
`
	e, err := New(nil, Config{Model: m})
	if err != nil {
		t.Fatalf("custom model with roles should be accepted: %v", err)
	}
	if _, err := e.AddPolicy("viewer", "biz1:branch1", "financial", "view"); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	if _, err := e.AddGroupingPolicy("u1", "viewer", "biz1:branch1"); err != nil {
		t.Fatalf("add grouping: %v", err)
	}
	// Default composer maps (biz1, branch1) -> "biz1:branch1", matching the
	// stored grant exactly, so the role resolves and access is granted.
	ok, err := e.HasPermission("u1", "biz1", "branch1", "financial", "view")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !ok {
		t.Fatal("role-based grant in custom model should be allowed")
	}
}

// TestNewAcceptsCustomModelWithoutRoles is a regression guard: a tier-2 custom
// model that has the supported sub,dom,obj,act request shape but NO g role
// section must still construct successfully. The domain-matching-func
// registration is conditional on the presence of a g section.
func TestNewAcceptsCustomModelWithoutRoles(t *testing.T) {
	const m = `[request_definition]
r = sub, dom, obj, act
[policy_definition]
p = sub, dom, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`
	e, err := New(nil, Config{Model: m})
	if err != nil {
		t.Fatalf("role-less custom model should be accepted, got: %v", err)
	}
	if _, err := e.AddPolicy("u1", "biz1:branch1", "financial", "view"); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	ok, err := e.HasPermission("u1", "biz1", "branch1", "financial", "view")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !ok {
		t.Fatal("direct policy match should be allowed in role-less model")
	}
}
