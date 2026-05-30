package postgres

import (
	"reflect"
	"testing"
)

func TestValidateIdentifier(t *testing.T) {
	valid := []string{"casbin_rule", "rbac", "_x", "T9", "a_b_c"}
	for _, s := range valid {
		if err := validateIdentifier("table", s); err != nil {
			t.Errorf("%q should be valid: %v", s, err)
		}
	}
	invalid := []string{"", "1bad", "has space", "drop;table", "a-b", "x\"y", "tbl--", "naïve", "x\n", "a\nb", "good\nDROP TABLE x;--"}
	for _, s := range invalid {
		if err := validateIdentifier("table", s); err == nil {
			t.Errorf("%q should be rejected", s)
		}
	}
}

func TestRuleToColumns(t *testing.T) {
	cols, err := ruleToColumns([]string{"alice", "data1", "read"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := [numColumns]string{"alice", "data1", "read", "", "", ""}
	if cols != want {
		t.Fatalf("got %v want %v", cols, want)
	}

	if _, err := ruleToColumns([]string{"1", "2", "3", "4", "5", "6", "7"}); err == nil {
		t.Fatal("expected error for over-wide rule (7 > 6)")
	}

	// exactly 6 is allowed
	if _, err := ruleToColumns([]string{"1", "2", "3", "4", "5", "6"}); err != nil {
		t.Fatalf("6 values should be allowed: %v", err)
	}
}

func TestBuildRuleArray(t *testing.T) {
	cases := []struct {
		ptype string
		cols  []string
		want  []string
	}{
		{"p", []string{"alice", "data1", "read", "", "", ""}, []string{"p", "alice", "data1", "read"}},
		{"g", []string{"u1", "viewer", "biz1:branch1", "", "", ""}, []string{"g", "u1", "viewer", "biz1:branch1"}},
		{"p", []string{"", "", "", "", "", ""}, []string{"p"}},
		// an interior empty value must be preserved; only trailing empties drop
		{"p", []string{"a", "", "c", "", "", ""}, []string{"p", "a", "", "c"}},
	}
	for _, c := range cases {
		got := buildRuleArray(c.ptype, c.cols)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("buildRuleArray(%q,%v) = %v, want %v", c.ptype, c.cols, got, c.want)
		}
	}
}

func TestFilteredDelete(t *testing.T) {
	// fieldIndex 0, skip wildcard at index 1
	q, args, err := filteredDelete("casbin_rule", "g", 0, []string{"u1", "", "biz1:branch1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	wantQ := "DELETE FROM casbin_rule WHERE ptype = $1 AND v0 = $2 AND v2 = $3"
	if q != wantQ {
		t.Errorf("sql = %q, want %q", q, wantQ)
	}
	wantArgs := []any{"g", "u1", "biz1:branch1"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %v, want %v", args, wantArgs)
	}

	// only ptype when all fields are wildcards
	q2, args2, err := filteredDelete("t", "p", 0, []string{"", ""})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if q2 != "DELETE FROM t WHERE ptype = $1" {
		t.Errorf("sql = %q", q2)
	}
	if !reflect.DeepEqual(args2, []any{"p"}) {
		t.Errorf("args = %v", args2)
	}

	// fieldIndex offset maps to the right columns
	q3, _, err := filteredDelete("t", "p", 2, []string{"x"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if q3 != "DELETE FROM t WHERE ptype = $1 AND v2 = $2" {
		t.Errorf("sql = %q", q3)
	}

	// a non-empty value mapping past v5 must error, not widen the DELETE
	if _, _, err := filteredDelete("t", "p", 5, []string{"a", "b"}); err == nil {
		t.Fatal("expected out-of-range error for non-empty value at v6")
	}
}

func TestExactDelete(t *testing.T) {
	q, args, err := exactDelete("casbin_rule", "p", []string{"alice", "data1", "read"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	wantQ := "DELETE FROM casbin_rule WHERE ptype = $1 AND v0 = $2 AND v1 = $3 AND v2 = $4"
	if q != wantQ {
		t.Errorf("sql = %q, want %q", q, wantQ)
	}
	if !reflect.DeepEqual(args, []any{"p", "alice", "data1", "read"}) {
		t.Errorf("args = %v", args)
	}

	if _, _, err := exactDelete("t", "p", []string{"1", "2", "3", "4", "5", "6", "7"}); err == nil {
		t.Fatal("expected error for over-wide rule")
	}
}
