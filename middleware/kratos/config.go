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
