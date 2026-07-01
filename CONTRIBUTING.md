# Contributing to spiffecli

Thanks for your interest in contributing! This document explains how to build,
test, and submit changes to `spiffecli`.

By participating in this project you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

This project uses [mise](https://mise.jdx.dev/) to pin the Go and
golangci-lint versions (see `.mise.toml`). After cloning, run:

```bash
mise install
```

This installs the pinned toolchain so the linter and compiler versions match
across environments and you avoid typecheck failures from version mismatches.

### Build

```bash
make build        # builds ./bin/spiffecli
./bin/spiffecli   # run it
```

### Test

```bash
make test                                   # all tests
go test ./internal/jwtinspect -run TestHappyCases   # a single test
```

End-to-end tests compile the binary and drive full CLI workflows (each spins up
a real Workload API server as a subprocess):

```bash
go test ./internal/test/e2e/... -v -timeout 180s
```

## Guardrails

Before opening a pull request, run the full guardrail suite. This mirrors what
CI enforces on every push:

```bash
make check    # lint + test-race + mod-tidy-check + govulncheck
```

You can also run the individual checks:

```bash
make lint            # golangci-lint (staticcheck, errcheck, gosec, gocritic, govet)
make lint-fix        # auto-fix lint issues where possible
make test-race       # go test -race ./... (catches data races)
make mod-tidy-check  # ensure go.mod/go.sum are tidy (no drift)
make govulncheck     # scan dependencies for known CVEs
```

CI runs `lint`, `test` (with the race detector), `mod-tidy`, and `govulncheck`
on every push and pull request. Security scans (gosec, Trivy) run on `main` and
weekly, with results in the GitHub Security tab.

## Making Changes

### Architecture

See [CLAUDE.md](CLAUDE.md) for an overview of the command structure, key
patterns, and package layout. In short:

- Commands live in `cmd/` (Cobra, `spiffecli <command> <subcommand>`).
- Business logic lives in `internal/<package>/`, with a domain struct whose
  exported fields are bound to Cobra flags.

### Adding a new command

1. Create a domain struct in `internal/<package>/` with exported fields for flags.
2. Add a method on the struct that performs the operation and returns `(result, error)`.
3. In `cmd/`, add a `New<Command>Cmd()` that constructs the struct, wires flags
   with `Flags().StringVar(&struct.Field, ...)`, and calls the method in `RunE`.
4. Register it via `init()` with `parentCmd.AddCommand(New<Command>Cmd())`.

### Adding a new output format

1. Write a converter function matching the package's existing signature.
2. Register it in the package's `FormatMap` (format name, chroma lexer, converter).
3. Add golden-file fixtures under `testdata/`.

### Documentation

When you add, remove, or change a command, flag, or behavior, keep the docs in
sync and regenerate the command reference:

```bash
make build && ./bin/spiffecli docs -o ./documentation/docs/
```

## Testing Expectations

- Use table-driven tests (`tests := []struct{...}` with `t.Run(tt.name, ...)`).
- Use `testify/require` for assertions on critical checks.
- Use `testdata/` fixtures and golden-file comparison (`require.JSONEq` /
  `require.YAMLEq`); `jwtinspect` and `bundle` are reference implementations.
- Generate certificate chains with `internal/test/testx509.CertificateAuthority`
  and its functional options; use `testclock` for time-dependent logic.

New code should include tests. Critical paths (SVID operations, verification)
should be covered thoroughly.

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) standard:

```
<type>(<scope>): <short summary>

<body — explain WHY, not WHAT; wrap at 72 chars>
```

- **Types:** `feat` | `fix` | `refactor` | `test` | `docs` | `chore` | `perf`
- **Scope:** the area changed, e.g. `watch`, `cmd`, `wlapi`, `docs`
- **Summary:** imperative mood, lowercase, no trailing period, ≤50 chars
- **Breaking changes:** append `!` after the type/scope and add a
  `BREAKING CHANGE:` trailer.

Example:

```
feat(watch): add x509-svid streaming watcher

Uses workloadapi.WatchX509Context for push-based updates instead of
polling, so consumers see rotations immediately rather than on interval.
```

## Developer Certificate of Origin (DCO)

Contributions to this project require a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off.
This certifies that you wrote the change (or otherwise have the right to submit
it under the project's license). Add a sign-off line to each commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

The easiest way is to pass `-s` when committing:

```bash
git commit -s -m "feat(cmd): add ..."
```

## Pull Requests

1. Fork the repository and create a topic branch from `main`.
2. Make your change, with tests and updated docs.
3. Run `make check` and ensure it passes.
4. Open a pull request describing the change and its motivation. Link any
   related issues.

We review PRs as promptly as we can. Thanks for contributing!

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE), the same license that covers this project.
