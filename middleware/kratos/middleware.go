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
	// Fail closed whenever the tenant is absent. An empty tenant composes to the
	// global "*" domain (see enforcer.ComposeDom), so allowing it here would let
	// a request resolve against global grants; a non-empty sub-tenant with an
	// empty tenant is nonsensical and must not slip through.
	if tenantID == "" {
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
