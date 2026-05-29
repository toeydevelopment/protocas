package kratos

import (
	"context"
	"errors"
	"testing"

	"github.com/go-kratos/kratos/v2/transport"

	"github.com/toeydevelopment/protocas/enforcer"
	_ "github.com/toeydevelopment/protocas/internal/testdata/proto/rbactest/v1"
)

type fakeTransport struct{ op string }

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

// TestEmptyTenantFailsClosed guards against global-domain escalation: a Domain
// func returning an empty tenant (even with a non-empty sub-tenant) must be
// denied, not resolved against the global "*" domain.
func TestEmptyTenantFailsClosed(t *testing.T) {
	cfg := baseConfig(t, "u1")
	cfg.Domain = func(context.Context) (string, string, error) { return "", "branch1", nil }
	var reached bool
	mw := New(cfg)
	_, err := mw(okHandler(&reached))(ctxWithOp("/rbactest.v1.Svc/Guarded"), nil)
	if err == nil {
		t.Fatal("empty tenant must fail closed (no global escalation)")
	}
	if reached {
		t.Fatal("handler must NOT be reached when tenant is empty")
	}
}
