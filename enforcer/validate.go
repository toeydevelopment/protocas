package enforcer

import "github.com/casbin/casbin/v2/model"

// wantRequestTokens is the supported request definition. Casbin prefixes each
// token with the section key, so `r = sub, dom, obj, act` becomes these tokens.
var wantRequestTokens = []string{"r_sub", "r_dom", "r_obj", "r_act"}

// validateModel enforces the library's request-shape contract: the request
// definition must be exactly `r = sub, dom, obj, act`.
//
// SCOPE WARNING: this checks the request-token shape ONLY. It does NOT inspect
// the matcher, so it cannot guarantee a custom model actually enforces tenant
// isolation. A custom matcher that omits r.dom (e.g. only compares sub/obj/act)
// will pass validation yet grant cross-tenant access. Authors of custom models
// own correct domain scoping in their matcher; see docs/GUIDE.md §5.
func validateModel(m model.Model) error {
	r, ok := m["r"]
	if !ok {
		return ErrUnsupportedModel
	}
	def, ok := r["r"]
	if !ok {
		return ErrUnsupportedModel
	}
	if len(def.Tokens) != len(wantRequestTokens) {
		return ErrUnsupportedModel
	}
	for i, tok := range wantRequestTokens {
		if def.Tokens[i] != tok {
			return ErrUnsupportedModel
		}
	}
	return nil
}
