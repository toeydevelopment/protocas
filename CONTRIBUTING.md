# Contributing

## Prerequisites

- Go 1.26+
- [`buf`](https://buf.build) (for regenerating proto code) — optional, only needed
  if you change `.proto` files.

## Layout

```
enforcer/            core: enforcer, domain, annotation, verify, config, validate
rbacmodel/           default Casbin model + root-clause rendering
middleware/kratos/   Kratos v2 middleware
adapter/polling/     store-agnostic polling watcher
adapter/mongo/       MongoDB change-stream watcher (integration-gated)
proto/rbac/v1/       require/skip MethodOptions (.proto + committed .pb.go)
internal/testdata/   generated test-fixture service used by enforcer tests
examples/            runnable wiring
docs/                spec, plan, usage guide
```

## Build and test

```bash
go build ./...
go test ./...            # hermetic; no database required
go vet ./...
```

Coverage:

```bash
go test ./... -cover
```

### Integration tests

The Mongo change-stream watcher test is gated behind the `integration` build tag
and needs a MongoDB replica set:

```bash
MONGO_URI="mongodb://localhost:27017/?replicaSet=rs0" \
  go test -tags integration ./adapter/mongo/...
```

It compiles in the default build but only runs with the tag and `MONGO_URI` set.

## Regenerating proto code

Generated `.pb.go` files are committed (consumers need the extension without a
toolchain). Regenerate only when you change a `.proto`:

```bash
buf generate
go mod tidy
go test ./...
```

`buf.gen.yaml` uses `opt: module=github.com/toeydevelopment/protocas` so files land
at paths matching their Go import path (e.g. `proto/rbac/v1/rbac.pb.go`).

The rbac extension field numbers are `require = 56811`, `skip = 56812`. Do not
change them — they are part of the wire contract for every consumer.

## Conventions

- **TDD.** Write a failing test, watch it fail, write minimal code, watch it pass.
- **Conventional commits**: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`.
- Keep the core (`enforcer`, `rbacmodel`) free of transport and store dependencies.
- Carry the `keyMatch2("*","*")` guards (see [docs/GUIDE.md](docs/GUIDE.md) §8) if you
  touch the model or coverage check.

## License

By contributing you agree your contributions are licensed under Apache-2.0.
