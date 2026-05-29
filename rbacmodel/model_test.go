package rbacmodel

import (
	"strings"
	"testing"
)

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
