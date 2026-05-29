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
	if got := NamespacedRole("biz1", "manager", def); got != "manager" {
		t.Errorf("system role should be un-namespaced, got %q", got)
	}
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
