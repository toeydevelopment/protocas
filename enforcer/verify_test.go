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
