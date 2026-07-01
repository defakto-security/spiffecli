# SPIFFE CLI

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

SPIFFE CLI is a command line tool to run a [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) locally and request and validate SVIDs. 

## Installation

Download the spiffecli binary for your OS in the [Releases page](https://github.com/defakto-security/spiffecli/releases).

Or build from source by cloning the repo and running:

```bash
make build
./bin/spiffecli
```

## Getting Started
Run a local Workload API: 

```bash
./bin/spiffecli run
Unable to find an existing configuration (see --config flag).

If you continue, a default configuration will be used and saved at ~/.spirl/dev.toml
? Continue? [y/N] y█

Saved $HOME/.spirl/dev.toml

2023/10/17 10:59:58 Trust domain: name="example.com" X509AuthorityTTL="24h0m0s" JWTAuthorityTTL="24h0m0s"
2023/10/17 10:59:58 Trust domain: name="acme-corp" X509AuthorityTTL="24h0m0s" JWTAuthorityTTL="24h0m0s"
2023/10/17 10:59:58 Rotating X.509 authority for trust domain "example.com"
2023/10/17 10:59:58 Rotating X.509 authority for trust domain "acme-corp"
2023/10/17 10:59:58 Rotating JWT authority for trust domain "acme-corp"
2023/10/17 10:59:58 Rotating JWT authority for trust domain "example.com"
2023/10/17 10:59:58 Workload: id="spiffe://acme-corp/pubsub" trustDomain="acme-corp" socket="/var/folders/by/rf9wqg_d5z150k1fb1wh_s180000gn/T/spirl-dev/acme-corp/pubsub.sock"
2023/10/17 10:59:58 Workload: id="spiffe://example.com/frontend" trustDomain="example.com" socket="/var/folders/by/rf9wqg_d5z150k1fb1wh_s180000gn/T/spirl-dev/example.com/frontend.sock"
2023/10/17 10:59:58 Workload: id="spiffe://example.com/backend" trustDomain="example.com" socket="/var/folders/by/rf9wqg_d5z150k1fb1wh_s180000gn/T/spirl-dev/example.com/backend.sock"
```

This will create a new default configuration file at `~/.spirl/dev` with two trust domains `example.com` and `acme.corp`.  

To get an SVID, specify the unix domain socket for the SPIFFE ID and request an SVID:

```bash
$ export SPIFFE_ENDPOINT_SOCKET=unix:///var/folders/by/rf9wqg_d5z150k1fb1wh_s180000gn/T/spirl-dev/example.com/frontend.sock
$ ./bin/spiffecli get x509-svid
```

## Testing & Guardrails

### Quick check — run all guardrails at once

```bash
make check      # lint + test-race + mod-tidy-check + govulncheck
```

This mirrors what CI enforces on every push. Run it after any code change before committing.

### Individual guardrails

```bash
make lint           # golangci-lint (staticcheck, errcheck, gosec, gocritic, govet)
make lint-fix       # auto-fix lint issues
make test-race      # go test -race ./... (catches data races)
make test-cover     # tests with coverage report
make mod-tidy-check # ensure go.mod/go.sum are tidy (no drift)
make govulncheck    # scan dependencies for known CVEs
make gosec          # standalone gosec security scan
```

### Running tests directly

```bash
# All tests
go test ./...

# Single package
go test ./internal/jwtinspect/... -v

# Single test function
go test ./internal/jwtinspect -run TestHappyCases
```

### End-to-end tests

E2E tests compile the `spiffecli` binary and test complete CLI workflows. Each test starts a real Workload API server as a subprocess.

```bash
# Run all E2E tests (~20s)
go test ./internal/test/e2e/... -v -timeout 180s

# Offline tests only (no server, fast)
go test ./internal/test/e2e/... -run "TestE2E_Inspect" -v -timeout 60s
```

### CI

Every push and pull request runs four checks: **lint**, **test** (with race detector), **mod-tidy**, and **govulncheck**. Security scans (gosec SARIF, Trivy image scan) run on pushes to `main` and weekly — results appear in the GitHub Security tab.

## Kubernetes Injection

`spiffecli` can be injected into a running Kubernetes pod as an **ephemeral container** (no pod restart required) using `kubectl debug`. The debug image is based on [nicolaka/netshoot](https://hub.docker.com/r/nicolaka/netshoot) with the `spiffecli` binary added.

### Prerequisites

- Docker (to build the debug image)
- `kubectl` with access to the target cluster
- Kubernetes 1.23+ (ephemeral containers are GA)

### Standard SPIRE-managed pod

Two approaches — choose based on your situation:

**Option 1: Ephemeral container (in-place, recommended)**

Always pass `TARGET`. Without it the ephemeral container is fully isolated and `spiffecli` fails with `context deadline exceeded`.

```bash
make inject POD=<pod-name> TARGET=<container-name> [NAMESPACE=<ns>]
```

Inside the shell, the socket is at `/proc/<pid>/root/<original-path>`. PID is usually 1 — verify with `ps`:

```bash
export SPIFFE_ENDPOINT_SOCKET=unix:///proc/1/root/spirl-agent-socket/agent.sock
spiffecli get x509-svid
```

If `/proc/<pid>/root/` returns `Permission denied`, the target container runs as a non-root UID. Use `kubectl debug --profile=sysadmin` directly (kubectl 1.30+).

**Option 2: Clone pod (simpler socket access)**

Clones the pod with the debug image — all volume mounts are preserved, so the socket is at its original path. Requires deleting the clone when done.

```bash
kubectl debug -it <pod> --namespace=<ns> \
  --image=ghcr.io/defakto-security/spiffecli-debug:latest \
  --copy-to=spiffecli-debug-pod --same-node=true \
  --set-image='*=ghcr.io/defakto-security/spiffecli-debug:latest'

# Inside shell:
export SPIFFE_ENDPOINT_SOCKET=unix:///spirl-agent-socket/agent.sock
spiffecli get x509-svid

# Cleanup:
kubectl delete pod spiffecli-debug-pod --namespace=<ns>
```

### Istio-managed pod

For Istio workloads the socket lives in the sidecar. `make inject-istio` targets the `istio-proxy` container and pre-sets `SPIFFE_ENDPOINT_SOCKET` automatically:

```bash
make inject-istio POD=<pod-name>
# Inside the shell:
spiffecli get x509-svid   # socket already configured
```

### Variables

| Variable | Default | Description |
|---|---|---|
| `POD` | *(required)* | Target pod name |
| `NAMESPACE` | `default` | Pod namespace |
| `TARGET` | *(none)* | Container whose process namespace to share. Required to reach the Workload API socket (`inject` only; `inject-istio` always uses `istio-proxy`) |
| `IMAGE` | `ghcr.io/defakto-security/spiffecli-debug:latest` | Debug image ref |
| `CLUSTER_TYPE` | `registry` | How to distribute the image: `registry`, `kind`, or `k3d` |
| `KIND_CLUSTER` | `kind` | kind cluster name (override if created with `--name`) |

### Local development (kind / k3d)

For local clusters, skip the registry push by loading the image directly:

```bash
# kind (non-default cluster name: add KIND_CLUSTER=<name>)
make inject POD=<pod> TARGET=<container> CLUSTER_TYPE=kind

# k3d
make inject POD=<pod> TARGET=<container> CLUSTER_TYPE=k3d
```

### Build the debug image only

```bash
make inject-build                         # build locally
make inject-build IMAGE=myrepo/debug:v1   # custom image tag
```

## Releasing

We use Github actions to build spiffecli binaries and publish them on Github Container Registry and as a Github Release. To trigger the actions create a release branch and tag it with the next release number. Push the branch and tag and open a Pull Request. Once the Pull Request is merged the Github Actions will trigger and you should see a Github Release with the spiffecli binaries in the Artifacts section.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for
build, test, and pull-request guidelines, and note that contributions require a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off
(`git commit -s`). By participating you agree to our
[Code of Conduct](CODE_OF_CONDUCT.md).

To report a security vulnerability, please follow our [Security Policy](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See the [NOTICE](NOTICE)
file for attribution.