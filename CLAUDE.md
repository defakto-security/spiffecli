# SPIFFECLI Development Guide

## Build & Test

This is a Go CLI project (spiffecli) related to SPIFFE/SPIRE. Build with `go build ./...`, test with `go test ./...`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor workflow.

## Toolchain Setup

This project uses [mise](https://mise.jdx.dev/) to pin Go and golangci-lint versions (see `.mise.toml`).
After cloning, run `mise install` once to install the pinned versions. This ensures the linter and compiler
versions match across all environments and avoids typecheck failures from Go version mismatches.

## Build Commands
- Install toolchain: `mise install`
- Build binary: `make build` (outputs to `./bin/spiffecli`)
- Run all tests: `make test`
- Run a single test: `go test ./internal/jwtinspect -run TestHappyCases`
- Run linter: `make lint` (requires `golangci-lint`)
- Fix lint issues: `make lint-fix`
- Generate docs: `./bin/spiffecli docs -o ./documentation/docs/`

## Architecture

### Command Structure (Cobra)
The CLI uses cobra with a two-level command hierarchy: `spiffecli <command> <subcommand>`.

**Command tree:**
- `run` -- starts a local dev Workload API server (reads TOML config from `~/.spirl/dev.toml`)
- `get x509-svid | jwt-svid | bundle` -- requests SVIDs/bundles from a running Workload API
- `verify x509-svid | jwt-svid | x509` -- verifies SVIDs or generic X.509 certificates
- `inspect jwt | jwks | x509` -- inspects JWTs, JWKS bundles, and X.509 certificates offline (no Workload API needed)
  - `inspect x509` supports `--format json|yaml|summary|chain|tree`, plus `--bundle <pem>`, `--shortest-path`, and `--tree-fields <fields>` for PKI visualization
- `watch x509-svid | jwt-svid | bundle` -- streams SVID/bundle updates from Workload API
- `docs` -- hidden command that generates markdown documentation

Commands requiring a Workload API connection (`get *`, `verify x509-svid`, `verify jwt-svid`,
`watch *`) use the `--spiffe-endpoint-socket` / `-s` flag or `SPIFFE_ENDPOINT_SOCKET` env var.
The flag is registered per command group (not globally on the root), so offline commands
(`inspect *`, `verify x509`, `run`, `docs`) do not expose it. Socket paths auto-prepend
`unix://` if no scheme is present (see `cmd/validation.go`).

### Key Architectural Patterns

**1. Struct-as-command-state pattern:**
Each subcommand creates a domain struct (e.g., `jwtinspect.JwtInspector`, `x509verify.Verifier`,
`jwtsvid.JWTSVIDClient`, `bundle.BundleClient`) and binds cobra flags directly to its exported
fields. The struct's method (`.Inspect()`, `.VerifyCertificate()`, `.RequestJWTSVID()`) contains
all business logic. This means: flags -> struct fields -> method call -> output.

**2. FormatMap formatter registry:**
Both `jwtinspect` and `bundle` packages use a `FormatMap` (map of format string to `Formatter`
struct) that maps output format names ("json", "yaml", "summary") to converter functions.
The `Formatter` struct carries a label, chroma lexer name, and a converter function. When
adding a new output format, register it in the package's `FormatMap`.

**3. Dual error wrapping styles:**
The codebase uses BOTH `fmt.Errorf("context: %w", err)` (in `cmd/` and newer packages) and
`errors.Wrap(err, "context")` from `github.com/pkg/errors` (in `internal/wlapi/`). New code
should prefer `fmt.Errorf` with `%w`.

**4. Embedded default config:**
`cmd/run.go` uses `//go:embed dev.toml` to embed the default TOML configuration. The `run`
command writes this to `~/.spirl/dev.toml` on first use if the file doesn't exist.

**5. Config uses custom duration type:**
The TOML config (`internal/wlapi/config.go`) uses `stringtime.Duration` for human-readable
duration strings in config files. This is unmarshaled via `go-toml/v2`.

### Package Dependency Flow
```
cmd/ -> internal/{jwtinspect,bundle,jwtsvid,x509svid,x509verify,wlapi}
                     |                              |
                     v                              v
              internal/style              internal/{x509util,pemutil,cryptoutil}
                                                    |
                                                    v
                                    internal/{x509authority,jwtauthority}
```

### Test Helpers (internal/test/)
Shared test infrastructure lives in `internal/test/`:
- `testx509.CertificateAuthority` -- creates temp CAs, signs intermediate/leaf certs with
  functional options (`WithValidityPeriod`, `WithPublicKey`, `WithSubject`). This is the
  primary way to generate test certificate chains.
- `testkey` -- pre-generated key fixtures (EC256, EC384, Ed25519, RSA2048) in `testdata/`
- `testclock` -- fake clock for deterministic time-dependent tests
- `testhttpd` -- creates `httptest.Server` instances serving files with custom headers
- `testauthority` -- test authority helpers

## Code Style Guidelines

### Imports
- Group: stdlib first, then third-party, then `github.com/defakto-security/spiffecli/internal/...`
- Alias hyphenated packages: `identityexchange "github.com/defakto-security/spiffecli/internal/identity-exchange"`

### Error Handling
- Wrap errors with `fmt.Errorf("context: %w", err)` in new code
- Return early on errors
- Validate options in `PreRunE` or a `validateOptions()` method before main logic

### Testing
- Use table-driven tests with `tests := []struct{...}` and `t.Run(tt.name, ...)`
- Use `testify/require` for assertions (not `assert` for critical checks)
- Use `testdata/` directories for fixtures; golden-file testing compares output against
  `testdata/<input>.<format>` files (e.g., `simple.jwt.json`, `simple.jwt.yaml`)
- Test helpers that create temp files should use `t.TempDir()` and `t.Helper()`
- The `testx509.CertificateAuthority` with functional options is the standard way to
  generate certificate chains for tests
- For HTTP-dependent tests, use `httptest.Server` via `testhttpd` or directly

### Adding a New Command
1. Create domain struct in `internal/<package>/` with exported fields for flags
2. Add a method on the struct that performs the operation and returns `(result, error)`
3. In `cmd/`, create a `New<Command>Cmd()` function that constructs the struct,
   creates a `cobra.Command`, binds flags with `Flags().StringVar(&struct.Field, ...)`,
   and calls the struct method in `RunE`
4. Register via `init()` with `parentCmd.AddCommand(New<Command>Cmd())`

### Adding a New Output Format
1. Create a converter function matching the existing signature in the package
2. Register in the package's `FormatMap` with format name, chroma lexer, and converter
3. Add golden-file test fixtures in `testdata/`

## Testing Guidelines

### Testing Philosophy
spiffecli requires three levels of testing:
1. **Unit tests** - Business logic without external dependencies (use mocks/fakes for gRPC)
2. **Integration tests** - gRPC client-server interaction with test Workload API server
3. **End-to-end tests** - Full CLI workflows from user perspective

Target coverage: 90%+ for business logic, 100% for critical paths (SVID operations, verification).

### Unit Testing Patterns

**Table-driven tests** (existing pattern - keep using):
- Use `tests := []struct{name, input, want}` with `t.Run(tt.name, ...)`
- Group related test cases together
- Name test cases descriptively ("expired certificate", "missing audience")

**Golden file testing** (existing pattern - expand usage):
- Store expected outputs in `testdata/<input>.<format>` files
- Use `require.JSONEq` / `require.YAMLEq` for format-agnostic comparison
- Update golden files when output format intentionally changes
- Pattern: `jwtinspect` and `bundle` packages are reference implementations

**Test helpers** (existing but underutilized):
- `testx509.CertificateAuthority` - ALWAYS use for certificate generation
  - Functional options: `WithPublicKey`, `WithSubject`, `WithValidityPeriod`, `WithSerialNumber`
  - See `x509verify/client_test.go` for certificate chain examples
- `testclock.Clock` - Use for time-dependent logic (expiration, TTLs)
- `testhttpd` - Use for HTTP-dependent tests (bundle fetching from URLs)

**Testing command packages:**
- Create a struct that mirrors the command's business logic
- Test the struct's methods directly (NOT via cobra.Command.Execute())
- For flag validation, test the validation function separately
- Example: Test `jwtinspect.JwtInspector.Inspect()` not `NewInspectJWTCmd().Execute()`

### Integration Testing (gRPC Workload API)

For packages that interact with the Workload API (`bundle.BundleClient`, `jwtsvid.JWTSVIDClient`, `x509svid.X509SVIDClient`):

**Pattern: Test with real gRPC server**
1. Start `wlapi` server in test with `wlapi.Run()` on a test socket
2. Configure client to connect to test socket
3. Invoke client method
4. Verify response against expected values
5. Defer server shutdown

**Example structure:**
```go
func TestBundleClient_Integration(t *testing.T) {
    // Setup test TrustDomain config
    cfg := &config.Config{ /* ... */ }

    // Start test Workload API server
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    socketPath := filepath.Join(t.TempDir(), "workload.sock")
    go wlapi.Run(ctx, cfg, socketPath)

    // Wait for server to be ready (poll or use a ready channel)

    // Test client
    client := &bundle.BundleClient{SocketPath: socketPath}
    result, err := client.GetX509Bundle(ctx)

    require.NoError(t, err)
    require.NotNil(t, result)
    // Additional assertions...
}
```

**Fixture management:**
- Store test configs in `internal/wlapi/testdata/`
- Use `testx509.CertificateAuthority` to generate test certificate chains
- Reuse fixtures across integration tests

**Coverage targets:**
- `wlapi` package: 80%+ (focus on happy paths and common error cases)
- Client packages (`bundle`, `jwtsvid`, `x509svid`): 90%+ (critical path)

### End-to-End Testing (CLI Workflows)

Test the CLI as users interact with it: compile binary, run commands, verify outputs.

**Pattern: Subprocess testing with compiled binary**
```go
// internal/test/e2e/e2e_test.go
func TestE2E_GetX509SVID(t *testing.T) {
    // Build binary
    binaryPath := buildTestBinary(t)

    // Start dev server in background
    serverCtx, stopServer := context.WithCancel(context.Background())
    defer stopServer()

    socketPath := filepath.Join(t.TempDir(), "workload.sock")
    serverCmd := exec.CommandContext(serverCtx, binaryPath, "run", "--socket", socketPath)
    require.NoError(t, serverCmd.Start())

    // Wait for server readiness (poll socket)
    waitForSocket(t, socketPath, 5*time.Second)

    // Run client command
    outputFile := filepath.Join(t.TempDir(), "svid.pem")
    clientCmd := exec.Command(
        binaryPath,
        "get", "x509-svid",
        "--spiffe-endpoint-socket", socketPath,
        "--output", outputFile,
    )

    output, err := clientCmd.CombinedOutput()
    require.NoError(t, err, "command output: %s", output)

    // Verify output file exists and contains valid SVID
    data, err := os.ReadFile(outputFile)
    require.NoError(t, err)
    require.Contains(t, string(data), "BEGIN CERTIFICATE")
}

func buildTestBinary(t *testing.T) string {
    t.Helper()
    binaryPath := filepath.Join(t.TempDir(), "spiffecli")
    cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/spiffecli")
    require.NoError(t, cmd.Run())
    return binaryPath
}
```

**Workflows to test:**
1. `run` server → `get x509-svid` → verify PEM output
2. `run` server → `get jwt-svid` → verify JWT token
3. `run` server → `get bundle` → verify JWKS format
4. `verify x509-svid` → verify against running server
5. `inspect jwt` → verify offline inspection (no server needed)

**Test organization:**
- Create `internal/test/e2e/` package
- One test file per command group (`run_test.go`, `get_test.go`, `verify_test.go`, `inspect_test.go`)
- Use `t.Parallel()` for independent tests

**Run commands:**
```bash
# Run e2e tests
go test ./internal/test/e2e/... -v

# Run all tests including e2e
make test
```

### Test Coverage Requirements

| Package | Current Coverage | Target | Priority |
|---------|-----------------|--------|----------|
| `cmd` | ~13% | 80% | HIGH |
| `wlapi` | 0% | 80% | CRITICAL |
| `bundle` | ~60% (client untested) | 90% | HIGH |
| `jwtsvid` | ~60% (client untested) | 90% | HIGH |
| `x509svid` | ~60% (client untested) | 90% | HIGH |
| `x509verify` | ~90% | 95% | MEDIUM |
| `jwtinspect` | ~95% | 95% | LOW (already good) |
| `style` | 0% | 70% | LOW |
| `identity-exchange` | 0% | 80% | MEDIUM |

### Test Commands

Add these targets to your Makefile for organized test execution:

```makefile
.PHONY: test-unit test-integration test-e2e test-coverage

test-unit:
	go test -short ./... -v

test-integration:
	go test -run Integration ./... -v

test-e2e:
	go test ./internal/test/e2e/... -v

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Existing test target runs all
test: test-unit test-integration test-e2e
```

## Commit Message Convention

Follow the Conventional Commits standard. Format:

```
<type>(<scope>): <short summary>

<body — wrap at 72 chars, explain WHY not WHAT>

<trailers>
```

**Types:** `feat` | `fix` | `refactor` | `test` | `docs` | `chore` | `perf`

**Scope:** the package or area changed, e.g. `watch`, `cmd`, `wlapi`, `inject`, `docs`

**Summary:** imperative mood, lowercase, no period, ≤50 chars — "add x509 watcher" not "Added x509 watcher"

**Body:** required when the change is non-obvious. Explain motivation and contrast with previous behavior. Omit if the summary is self-contained.

**Examples:**
```
feat(watch): add x509-svid streaming watcher

Uses workloadapi.WatchX509Context for push-based updates instead of
polling, so consumers see rotations immediately rather than on interval.
```
```
fix(cmd): set SPIFFE_ENDPOINT_SOCKET for inject-istio target
```
```
test(watch): add periodic re-fetch verification for JWT watcher
```
```
docs(inject): add all five injection scenario examples
```

**Breaking changes:** append `!` after the type/scope and add a `BREAKING CHANGE:` trailer.

Contributions require a Developer Certificate of Origin sign-off — commit with
`git commit -s`. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Workflow Conventions

When asked to create a plan or document, save it to the specified file first. Do NOT start implementing the plan unless explicitly asked to implement.

## Documentation Currency

When adding, removing, or modifying commands, flags, or behavior, update documentation to match:
- **Command `--help` text** — keep `Use`, `Short`, `Long`, and flag descriptions accurate in `cmd/*.go`
- **CLAUDE.md command tree** — add/remove/update entries when commands change
- **`documentation/docs/`** — regenerate with `make build && ./bin/spiffecli docs -o ./documentation/docs/` after any command changes

Never leave documentation describing commands, flags, or behavior that no longer exists or works differently.

## Response Style

Keep responses concise and avoid multi-phase algorithmic frameworks (e.g., 7-phase processes) for straightforward requests. Prefer direct action over elaborate methodology.

## Guardrails (Run After Every Code Change)

After implementing any code change, run all local guardrails before committing:

```bash
make check          # lint + test-race + mod-tidy-check + govulncheck (fast, full suite)
```

Or individually:

```bash
make lint           # golangci-lint (staticcheck, errcheck, gosec, gocritic, govet)
make test-race      # go test -race ./... (catches data races)
make mod-tidy-check # go mod tidy + git diff --exit-code (prevents go.mod drift)
make govulncheck    # scan dependencies for known CVEs
make gosec          # standalone gosec scan (local, no SARIF)
make test-cover     # coverage report (informational)
```

**What CI enforces on every push** (`.github/workflows/ci.yml`):
- `lint` job: golangci-lint
- `test` job: `go test -race ./...` + coverage artifact
- `mod-tidy` job: go.mod/go.sum drift check
- `govulncheck` job: dependency CVE scan

**What runs on main/PR + weekly** (`.github/workflows/security.yml`):
- gosec SARIF → GitHub Security tab
- Trivy image scan of `Dockerfile.debug` → GitHub Security tab

**Branch protection** (configure in GitHub → Settings → Branches → main):
Require status checks: `lint`, `test`, `mod-tidy`, `govulncheck`
Require branches to be up to date before merging.

## Debugging Guidelines

When analyzing code or diagnosing bugs in SPIRE-related components, do not assume current behavior is 'expected' — ask clarifying questions about the intended behavior before concluding.