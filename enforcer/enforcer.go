package enforcer

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"

	"github.com/toeydevelopment/protocas/rbacmodel"
)

// Enforcer wraps *casbin.Enforcer and carries the DomainComposer.
type Enforcer struct {
	*casbin.Enforcer
	composer DomainComposer
}

// New builds an Enforcer. A nil adapter yields an in-memory enforcer.
func New(adapter persist.Adapter, cfg Config) (*Enforcer, error) {
	modelText := cfg.Model
	custom := modelText != ""
	if !custom {
		modelText = rbacmodel.Render(rbacmodel.DefaultModel, cfg.rootSubject(), cfg.DisableRoot)
	}

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("rbac: parse model: %w", err)
	}
	if err := validateModel(m); err != nil {
		return nil, err
	}

	var ce *casbin.Enforcer
	if adapter == nil {
		ce, err = casbin.NewEnforcer(m)
	} else {
		ce, err = casbin.NewEnforcer(m, adapter)
	}
	if err != nil {
		return nil, fmt.Errorf("rbac: new enforcer: %w", err)
	}

	// Domain-aware role matching: when the model defines a "g" role section,
	// resolve a subject's roles across domains with keyMatch2 so a tenant-wide
	// grant (biz:*) covers every sub-tenant. AddNamedDomainMatchingFunc returns
	// false if the "g" role manager is absent; since we only call it when the
	// section exists, a false here means the model is internally inconsistent —
	// fail loudly rather than silently skipping domain matching. Custom models
	// without roles (no "g" section) are supported and simply skip this.
	if g, ok := m["g"]; ok && len(g) > 0 {
		if registered := ce.AddNamedDomainMatchingFunc("g", "keyMatch2", util.KeyMatch2); !registered {
			return nil, fmt.Errorf("rbac: model defines a 'g' section but its role manager was not initialized")
		}
	}

	if adapter != nil {
		if err := ce.LoadPolicy(); err != nil {
			return nil, fmt.Errorf("rbac: load policy: %w", err)
		}
		ce.EnableAutoSave(true)
	}
	if cfg.Watcher != nil {
		if err := ce.SetWatcher(cfg.Watcher); err != nil {
			return nil, fmt.Errorf("rbac: set watcher: %w", err)
		}
	}

	return &Enforcer{Enforcer: ce, composer: cfg.composer()}, nil
}

// HasPermission composes the dom and calls Enforce(sub, dom, obj, act).
func (e *Enforcer) HasPermission(subject, tenantID, subTenantID, resource, action string) (bool, error) {
	return e.Enforce(subject, e.composer(tenantID, subTenantID), resource, action)
}

// MustHasPermission returns ErrUnauthorized on deny, or the enforcer error.
func (e *Enforcer) MustHasPermission(subject, tenantID, subTenantID, resource, action string) error {
	ok, err := e.HasPermission(subject, tenantID, subTenantID, resource, action)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUnauthorized
	}
	return nil
}
