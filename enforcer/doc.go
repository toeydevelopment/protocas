// Package enforcer is the transport- and store-agnostic core of a generic,
// config-driven Casbin RBAC library with proto-annotation authorization.
//
// It provides:
//
//   - New: build an [Enforcer] from any Casbin persist.Adapter (nil = in-memory)
//     and a [Config]. The enforcer embeds *casbin.Enforcer and carries a
//     [DomainComposer] so HasPermission composes the tenant domain consistently.
//   - HasPermission / MustHasPermission: enforce (subject, tenant, subtenant,
//     resource, action) against the canonical sub,dom,obj,act model.
//   - RequirementFor: resolve the rbac require/skip annotation for a Kratos-style
//     operation string via proto reflection (cached). Model-independent.
//   - VerifyPolicyCoverage: assert that a set of required grants exists.
//   - Domain/role composition helpers: ComposeDom, NamespacedRole, IsSystemRole.
//
// The supported model request shape is r = sub, dom, obj, act. New validates this
// and returns [ErrUnsupportedModel] for arity-different custom models; such models
// can still use the embedded raw *casbin.Enforcer plus RequirementFor.
//
// See the repository docs/GUIDE.md for the full model, policy/role management,
// custom-model contract, watcher selection, and the keyMatch2("*","*") trap.
package enforcer
