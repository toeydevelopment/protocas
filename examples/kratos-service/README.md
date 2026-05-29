# kratos-service example

Minimal wiring of the RBAC middleware.

- `enforcer.New(adapter, Config{})` builds the enforcer (nil adapter = in-memory).
- `kratos.New(Config{...})` builds the middleware; inject `Subject` and `Domain`.
- Install the middleware AFTER your auth and tenant-context middleware so the
  subject and tenant are populated in `ctx`.
- Annotate RPCs in your proto with `option (rbac.v1.require) = {resource action}`
  or `option (rbac.v1.skip) = true`. Un-annotated RPCs fail closed.

Run it:

    go run ./examples/kratos-service
