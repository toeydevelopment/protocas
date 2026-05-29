// Command kratos-service is a minimal example wiring the RBAC middleware.
package main

import (
	"context"
	"os"

	"github.com/go-kratos/kratos/v2/log"

	"github.com/toeydevelopment/protocas/enforcer"
	rbacmw "github.com/toeydevelopment/protocas/middleware/kratos"
)

func main() {
	// In-memory enforcer for the demo (nil adapter). Real services pass a
	// persist.Adapter (e.g. a Mongo adapter) and optionally a Watcher.
	enf, err := enforcer.New(nil, enforcer.Config{})
	if err != nil {
		panic(err)
	}
	// Seed a demo policy + role assignment.
	_, _ = enf.AddPolicy("biz1:viewer", "biz1:*", "financial", "view")
	_, _ = enf.AddGroupingPolicy("u1", "biz1:viewer", "biz1:branch1")

	mw := rbacmw.New(rbacmw.Config{
		Enforcer:          enf,
		OperationPrefixes: []string{"/myapp.v1."},
		Permissive:        os.Getenv("RBAC_PERMISSIVE") == "true",
		Logger:            log.DefaultLogger,
		Subject: func(ctx context.Context) (string, error) {
			// Replace with your auth: extract the user id from ctx.
			return "u1", nil
		},
		Domain: func(ctx context.Context) (string, string, error) {
			// Replace with your tenant middleware: extract tenant/subtenant.
			return "biz1", "branch1", nil
		},
	})

	// mw is a kratos middleware.Middleware; install it AFTER auth + tenant
	// middleware, e.g.:
	//   http.NewServer(http.Middleware(recovery.Recovery(), authMW, tenantMW, mw))
	_ = mw
	log.NewHelper(log.DefaultLogger).Info("rbac example wired; install mw after auth + tenant middleware")
}
