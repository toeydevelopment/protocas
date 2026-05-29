package enforcer

import "strings"

// DomainComposer maps (tenantID, subTenantID) to a Casbin dom string.
type DomainComposer func(tenantID, subTenantID string) string

// ComposeDom is the default tenant:subtenant composition:
//   ("","")        -> "*"        (global / system)
//   ("biz","")     -> "biz:*"    (tenant-wide)
//   ("biz","br")   -> "biz:br"   (specific sub-tenant)
func ComposeDom(tenantID, subTenantID string) string {
	if tenantID == "" {
		return "*"
	}
	if subTenantID == "" {
		return tenantID + ":*"
	}
	return tenantID + ":" + subTenantID
}

// DefaultDomainComposer is ComposeDom as a DomainComposer value.
func DefaultDomainComposer(tenantID, subTenantID string) string {
	return ComposeDom(tenantID, subTenantID)
}

// IsWildcardDom reports whether dom is global ("*") or tenant-wide ("tenant:*").
func IsWildcardDom(dom string) bool {
	return dom == "*" || strings.HasSuffix(dom, ":*")
}

// DefaultSystemRoles is the default set of un-namespaced (global) roles.
func DefaultSystemRoles() map[string]struct{} {
	return map[string]struct{}{
		"root":        {},
		"super_owner": {},
		"manager":     {},
		"operator":    {},
		"viewer":      {},
	}
}

// IsSystemRole reports whether name is in the system-role set.
func IsSystemRole(name string, systemRoles map[string]struct{}) bool {
	_, ok := systemRoles[name]
	return ok
}

// NamespacedRole returns the storage name for a role: system roles stay
// un-namespaced (global), custom roles become "<tenant>:<name>".
func NamespacedRole(tenantID, name string, systemRoles map[string]struct{}) string {
	if IsSystemRole(name, systemRoles) {
		return name
	}
	return tenantID + ":" + name
}
