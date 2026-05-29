package enforcer

import (
	"errors"
	"testing"
)

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
	ok, err := e.HasPermission("root", "biz1", "branch1", "anything", "delete")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if ok {
		t.Fatal("root must NOT be magic when DisableRoot is set")
	}
}

func TestRoleGrantWithTenantWildcard(t *testing.T) {
	e := newSeeded(t, Config{})
	if _, err := e.AddPolicy("biz1:viewer", "biz1:*", "financial", "view"); err != nil {
		t.Fatalf("add policy: %v", err)
	}
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
	ok, err = e.HasPermission("u1", "biz1", "branch1", "financial", "delete")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
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

func TestTenantWildcardRoleResolution(t *testing.T) {
	e := newSeeded(t, Config{})
	// Policy grants viewer access tenant-wide.
	if _, err := e.AddPolicy("biz1:viewer", "biz1:*", "financial", "view"); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	// CRUCIAL: the role is assigned in the WILDCARD domain biz1:*, not in the
	// specific branch. Resolving it for a request in biz1:branch1 requires the
	// registered keyMatch2 domain matching function on g().
	if _, err := e.AddGroupingPolicy("u1", "biz1:viewer", "biz1:*"); err != nil {
		t.Fatalf("add grouping: %v", err)
	}
	ok, err := e.HasPermission("u1", "biz1", "branch1", "financial", "view")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !ok {
		t.Fatal("role assigned in biz1:* must resolve for request domain biz1:branch1 via keyMatch2 domain func")
	}
}
