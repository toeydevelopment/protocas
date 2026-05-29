package enforcer

import (
	"testing"

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
