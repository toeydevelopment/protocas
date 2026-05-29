package enforcer

import (
	"errors"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/toeydevelopment/protocas/rbacmodel"
)

func TestValidateModelAcceptsDefault(t *testing.T) {
	m, err := model.NewModelFromString(rbacmodel.Render(rbacmodel.DefaultModel, "root", false))
	if err != nil {
		t.Fatalf("model parse: %v", err)
	}
	if err := validateModel(m); err != nil {
		t.Fatalf("default model should validate, got %v", err)
	}
}

func TestValidateModelRejectsWrongArity(t *testing.T) {
	const noDom = `[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(noDom)
	if err != nil {
		t.Fatalf("model parse: %v", err)
	}
	err = validateModel(m)
	if !errors.Is(err, ErrUnsupportedModel) {
		t.Fatalf("expected ErrUnsupportedModel, got %v", err)
	}
}
