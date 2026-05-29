package enforcer

import (
	"fmt"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	rbacv1 "github.com/toeydevelopment/protocas/proto/rbac/v1"
)

// Requirement is the resolved annotation for an RPC. A nil *Requirement means
// the method is un-annotated (caller decides fail-closed).
type Requirement struct {
	Resource string
	Action   string
	Skip     bool
}

var reqCache sync.Map // operation string -> cachedResult

type cachedResult struct {
	req *Requirement
	err error
}

// RequirementFor resolves the rbac annotation for a Kratos-style operation
// string "/pkg.v1.Svc/Method" via proto reflection. Results are cached because
// operation strings are stable for the life of the process.
func RequirementFor(operation string) (*Requirement, error) {
	if v, ok := reqCache.Load(operation); ok {
		c := v.(cachedResult)
		return c.req, c.err
	}
	req, err := resolve(operation)
	reqCache.Store(operation, cachedResult{req: req, err: err})
	return req, err
}

func resolve(operation string) (*Requirement, error) {
	svc, method, ok := splitOperation(operation)
	if !ok {
		return nil, fmt.Errorf("rbac: malformed operation %q", operation)
	}
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(svc))
	if err != nil {
		return nil, fmt.Errorf("rbac: service %q not found: %w", svc, err)
	}
	sd, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("rbac: %q is not a service", svc)
	}
	md := sd.Methods().ByName(protoreflect.Name(method))
	if md == nil {
		return nil, fmt.Errorf("rbac: method %q not found on %q", method, svc)
	}
	opts := md.Options()
	if opts == nil {
		return nil, nil
	}
	if proto.HasExtension(opts, rbacv1.E_Skip) {
		if v, ok := proto.GetExtension(opts, rbacv1.E_Skip).(bool); ok && v {
			return &Requirement{Skip: true}, nil
		}
	}
	if proto.HasExtension(opts, rbacv1.E_Require) {
		r, _ := proto.GetExtension(opts, rbacv1.E_Require).(*rbacv1.Requirement)
		if r != nil {
			return &Requirement{Resource: r.GetResource(), Action: r.GetAction()}, nil
		}
	}
	return nil, nil
}

// splitOperation parses "/pkg.v1.Svc/Method" -> ("pkg.v1.Svc", "Method").
func splitOperation(op string) (svc, method string, ok bool) {
	op = strings.TrimPrefix(op, "/")
	i := strings.LastIndex(op, "/")
	if i <= 0 || i == len(op)-1 {
		return "", "", false
	}
	return op[:i], op[i+1:], true
}
