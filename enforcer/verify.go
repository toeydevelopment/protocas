package enforcer

import "github.com/casbin/casbin/v2"

// PolicyTuple is a required (role, resource, action) grant, domain-agnostic.
type PolicyTuple struct {
	Role     string
	Resource string
	Action   string
}

// VerifyPolicyCoverage returns how many of the required tuples are absent.
//
// It scans GetPolicy() directly rather than calling Enforce/HasPolicy: the
// keyMatch2("*","*") invalid-regex trap (see rbacmodel doc) makes wildcard
// Enforce checks unreliable, so a direct slice scan is the correct approach.
func VerifyPolicyCoverage(e casbin.IEnforcer, required []PolicyTuple) (missing int) {
	policies, _ := e.GetPolicy() // [][]string of {sub, dom, obj, act}
	have := make(map[[3]string]struct{}, len(policies))
	for _, p := range policies {
		if len(p) < 4 {
			continue
		}
		have[[3]string{p[0], p[2], p[3]}] = struct{}{}
	}
	for _, r := range required {
		if _, ok := have[[3]string{r.Role, r.Resource, r.Action}]; !ok {
			missing++
		}
	}
	return missing
}
