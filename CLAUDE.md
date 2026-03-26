# gossl

Go project using Bazel for build and test.

## Build System

- **Bazel** is the build system. Use `bazel build //...` and `bazel test //...`.
- Do not use `go build`, `go test`, `go mod tidy`, or any `go` CLI commands directly — always use Bazel.
- Keep `BUILD.bazel` files up to date when adding/removing Go files.
- Use `gazelle` to regenerate BUILD files: `bazel run //:gazelle`.
- Format code: `bazel run //tools/format:format`. Check formatting: `bazel run //tools/format:format.check`.
- Git hooks managed by [pre-commit](https://pre-commit.com/) — see `.pre-commit-config.yaml`. Never write raw `.git/hooks/` scripts.

## Go Style

Follow Google's official Go guidelines:

- **Effective Go**: https://go.dev/doc/effective_go
- **Code Review Comments**: https://go.dev/wiki/CodeReviewComments

Key rules enforced in this project:

- Run `gofmt` / `goimports` on all code.
- MixedCaps naming, no underscores. Initialisms in consistent case (`URL`, `ID`, not `Url`, `Id`).
- Package names: short, lowercase, single-word. No stutter (`ring.Buffer` not `ring.RingBuffer`).
- Error strings: lowercase, no trailing punctuation.
- Always check errors. Never discard with `_` unless documented why.
- Early returns for error handling — keep happy path at minimal indentation.
- Interfaces: small, defined at consumer, not producer. Don't predefine for mocking.
- `context.Context` as first parameter. Never store in structs.
- Pointer receivers for mutation/large structs/consistency. Never mix receiver types on a type.
- Receiver names: 1-2 letters, consistent, never `this`/`self`.
- Prefer synchronous APIs. Let callers manage concurrency.
- Document goroutine lifetimes. Don't leak goroutines.
- Table-driven tests. Failure messages: `Foo(%q) = %d, want %d`.
- `crypto/rand` for secrets, never `math/rand`.
- `var s []T` for nil slices, not `s := []T{}` (unless JSON requires `[]`).
- All exported names have doc comments — complete sentences starting with the name.

## Testing

- Target **80%+ unit test coverage**. Complete coverage with integration tests.
- Unit tests: table-driven, colocated with source files (`foo_test.go` next to `foo.go`).
- Integration tests: use [testcontainers-go](https://github.com/testcontainers/testcontainers-go) for external dependencies (databases, services, etc.). No mocking infrastructure — test against real containers.
- Run all tests: `bazel test //...`.

## Project Structure

```
gossl/
  cmd/           # main packages
  pkg/           # library packages
  internal/      # private packages
  BUILD.bazel    # root build file
  MODULE.bazel   # bazel module definition
  go.mod         # go module file
```
