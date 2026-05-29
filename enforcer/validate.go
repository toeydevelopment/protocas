package enforcer

import "github.com/casbin/casbin/v2/model"

// wantRequestTokens is the supported request definition. Casbin prefixes each
// token with the section key, so `r = sub, dom, obj, act` becomes these tokens.
var wantRequestTokens = []string{"r_sub", "r_dom", "r_obj", "r_act"}

// validateModel enforces the library's request-shape contract.
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
