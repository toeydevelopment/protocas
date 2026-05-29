package enforcer

import (
	"errors"

	"github.com/casbin/casbin/v2/persist"
)

// ErrUnauthorized is returned by MustHasPermission when access is denied.
var ErrUnauthorized = errors.New("rbac: unauthorized")

// ErrUnsupportedModel is returned by New when the model's request definition
// is not the supported `sub, dom, obj, act` shape. Use the raw casbin enforcer
// directly for arity-different models.
var ErrUnsupportedModel = errors.New("rbac: unsupported model request shape (want sub, dom, obj, act)")

// Config configures the enforcer. The zero value is usable: it yields the
// default model, the default domain composer, and root subject "root".
//
// Note on system roles: namespacing of roles (system vs custom) is a caller-side
// concern handled with the exported helpers DefaultSystemRoles, IsSystemRole, and
// NamespacedRole — the enforcer does not namespace roles automatically, so there
// is intentionally no SystemRoles field here.
type Config struct {
	Model          string          // empty -> rbacmodel.DefaultModel
	DomainComposer DomainComposer  // nil -> DefaultDomainComposer
	RootSubject    string          // empty -> "root"
	DisableRoot    bool            // true -> no superuser short-circuit
	Watcher        persist.Watcher // nil -> no live reload
}

func (c Config) rootSubject() string {
	if c.RootSubject == "" {
		return "root"
	}
	return c.RootSubject
}

func (c Config) composer() DomainComposer {
	if c.DomainComposer == nil {
		return DefaultDomainComposer
	}
	return c.DomainComposer
}
