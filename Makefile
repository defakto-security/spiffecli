.PHONY: build test test-race test-cover mod-tidy-check govulncheck gosec \
        check lint lint-fix \
        inject-build inject-load inject inject-istio

# ── Core ──────────────────────────────────────────────────────────────────────

test:
	mise exec -- go test ./...

test-race:
	mise exec -- go test -race ./...

test-cover:
	mise exec -- go test -coverprofile=coverage.out ./...
	mise exec -- go tool cover -func=coverage.out

build:
	mise exec -- go build -o bin/spiffecli .

# ── Guardrails (run these after every code change) ────────────────────────────
#
# check: run all fast local guardrails in sequence.
# Mirrors what CI enforces on every push.

check: lint test-race mod-tidy-check govulncheck

mod-tidy-check:
	mise exec -- go mod tidy
	git diff --exit-code go.mod go.sum

govulncheck:
	mise exec -- go run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./...

gosec:
	mise exec -- go run github.com/securego/gosec/v2/cmd/gosec@v2.24.7 ./...

lint:
	mise exec -- golangci-lint run

lint-fix:
	mise exec -- golangci-lint run --fix

# ── Kubernetes injection (Phase 0) ────────────────────────────────────────────
#
# Injects spiffecli into a running pod as an ephemeral container using
# `kubectl debug`. The debug image is based on nicolaka/netshoot with the
# spiffecli binary added.
#
# Variables (all overridable on the command line):
#   IMAGE        — full image ref  (default: ghcr.io/defakto-security/spiffecli-debug:latest)
#   POD          — target pod name (required for inject / inject-istio)
#   NAMESPACE    — pod namespace   (default: default)
#   TARGET       — container to share process namespace with (inject only;
#                  inject-istio always uses istio-proxy)
#   CLUSTER_TYPE — how to distribute the image:
#                    registry  push to registry (default)
#                    kind      load into kind cluster (local dev)
#                    k3d       import into k3d cluster (local dev)
#   KIND_CLUSTER — kind cluster name (default: kind); override if your cluster
#                  has a non-default name: make inject ... KIND_CLUSTER=my-cluster

IMAGE        ?= ghcr.io/defakto-security/spiffecli-debug:latest
NAMESPACE    ?= default
CLUSTER_TYPE ?= registry
KIND_CLUSTER ?= kind

# For local cluster types the image is already loaded; tell kubelet not to
# pull from the registry. For registry-based deployments leave the default.
_PULL_POLICY = $(if $(filter kind k3d,$(CLUSTER_TYPE)),--image-pull-policy=Never,)

# Build the debug image locally.
inject-build:
	docker build -f Dockerfile.debug -t $(IMAGE) .

# Build then distribute to the cluster according to CLUSTER_TYPE.
inject-load: inject-build
	@case "$(CLUSTER_TYPE)" in \
	  kind)     kind load docker-image $(IMAGE) --name $(KIND_CLUSTER) ;; \
	  k3d)      k3d image import $(IMAGE) ;; \
	  registry) docker push $(IMAGE) ;; \
	  *) echo "Unknown CLUSTER_TYPE=$(CLUSTER_TYPE). Valid values: registry | kind | k3d" && exit 1 ;; \
	esac

# Inject into a standard SPIRE-managed pod.
# Usage: make inject POD=<pod> [NAMESPACE=<ns>] [TARGET=<container>] [CLUSTER_TYPE=kind|k3d|registry]
inject: inject-load
	@test -n "$(POD)" || (echo "ERROR: POD is required. Usage: make inject POD=<pod>"; exit 1)
	kubectl debug -it $(POD) \
	  --namespace=$(NAMESPACE) \
	  --image=$(IMAGE) \
	  --profile=general \
	  $(_PULL_POLICY) \
	  $(if $(TARGET),--target=$(TARGET),)

# Inject into an Istio-managed pod, targeting the istio-proxy sidecar.
# Pre-sets SPIFFE_ENDPOINT_SOCKET to the standard Istio socket path so all
# spiffecli commands work without extra flags.
# Usage: make inject-istio POD=<pod> [NAMESPACE=<ns>] [CLUSTER_TYPE=kind|k3d|registry]
inject-istio: inject-load
	@test -n "$(POD)" || (echo "ERROR: POD is required. Usage: make inject-istio POD=<pod>"; exit 1)
	kubectl debug -it $(POD) \
	  --namespace=$(NAMESPACE) \
	  --image=$(IMAGE) \
	  --profile=general \
	  $(_PULL_POLICY) \
	  --target=istio-proxy \
	  --env="SPIFFE_ENDPOINT_SOCKET=unix:///var/run/secrets/workload-spiffe-uds/socket"

