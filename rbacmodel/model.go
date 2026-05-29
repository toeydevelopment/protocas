// Package rbacmodel holds the default Casbin model text for the RBAC library.
//
// The model uses the request shape `r = sub, dom, obj, act`:
//   - sub: subject (user id, or a role name in g parent links)
//   - dom: tenant domain, e.g. "tenant:subtenant"; "tenant:*" = tenant-wide; "*" = global
//   - obj: resource (e.g. "financial")
//   - act: action (e.g. "view")
//
// TRAP: keyMatch2("*","*") compiles to the invalid regex ^*$ and silently
// returns false. The matcher therefore guards domain "*" explicitly with
// `p.dom == "*"`, and enforcer.VerifyPolicyCoverage scans policies directly
// instead of calling Enforce/HasPolicy. Do NOT remove these guards.
package rbacmodel

import (
	"fmt"
	"strings"
)

// DefaultModel is the Casbin model with a {{ROOT_CLAUSE}} placeholder at the
// head of the matcher. Render substitutes it. The super_owner role and the
// p.dom=="*" guard are intentional; see the package doc.
const DefaultModel = `[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = {{ROOT_CLAUSE}}g(r.sub, "super_owner", r.dom) || (g(r.sub, p.sub, r.dom) && (p.dom == "*" || keyMatch2(r.dom, p.dom)) && keyMatch(r.obj, p.obj) && keyMatch(r.act, p.act))
`

// Render substitutes the {{ROOT_CLAUSE}} placeholder. When disableRoot is true
// the clause is removed; otherwise it becomes `r.sub == "<rootSubject>" || `.
func Render(model, rootSubject string, disableRoot bool) string {
	clause := ""
	if !disableRoot {
		clause = fmt.Sprintf(`r.sub == %q || `, rootSubject)
	}
	return strings.ReplaceAll(model, "{{ROOT_CLAUSE}}", clause)
}
