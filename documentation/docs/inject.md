---
title: Kubernetes Injection
sidebar_position: 15
---

# Injecting spiffecli into a Kubernetes Pod

`spiffecli` can be injected into any running Kubernetes pod as an **ephemeral container** — no pod restart, no image rebuild, no change to workload manifests. This makes it ideal for live debugging of SPIFFE/SPIRE or Istio workloads in any environment.

The debug image is based on [nicolaka/netshoot](https://hub.docker.com/r/nicolaka/netshoot) (a comprehensive network-debugging toolkit) with the `spiffecli` binary added at `/usr/local/bin/spiffecli`.

## How it works

Ephemeral containers are GA since Kubernetes 1.23.

### Process namespace vs. mount namespace

When you pass `--target=<container>`, the ephemeral container shares the **process namespace** of the target container — not its mount namespace. The Workload API socket volume is mounted into the target container's mount namespace, and the ephemeral container cannot directly see it.

To reach a volume that lives in another container's mount namespace, you have two options:

**Option A — `--profile=general` (recommended, kubectl 1.23+)**

This profile gives the ephemeral container enough privileges to access `/proc/<pid>/root/` when both the debug container and the target container run as the same UID (typically both root). All `make inject` commands use this profile by default.

The path to the socket is `/proc/<pid>/root/<original-path>`, where `<pid>` is the main process of the target container. It is often PID 1, but run `ps` inside the shell to confirm.

**Option B — `--profile=sysadmin` (kubectl 1.30+)**

Grants `SYS_PTRACE` + `NET_ADMIN` regardless of UID. Use this if `--profile=general` still results in `Permission denied` (e.g. the target container runs as a non-root UID while the debug container runs as root).

**Option C — `shareProcessNamespace: true` in the pod spec**

When set at pod creation, all containers share a process namespace with the correct permissions — no extra capabilities required. This enables the `/proc/<pid>/root/` path without any profile flags.

**Option D — `--copy-to` (no /proc traversal needed)**

Creates a clone of the pod where the debug image replaces the workload image, but all volume mounts are preserved. The socket is accessible at its original path. See [Option 2: Clone approach](#option-2-starting-an-ephemeral-container-in-a-clone-of-the-target-pod) below.

## Prerequisites

- Docker (to build the debug image)
- `kubectl` configured for the target cluster
- Kubernetes 1.23+

## Quickstart

```bash
git clone https://github.com/defakto-security/spiffecli
cd spiffecli
make inject POD=<your-pod-name> TARGET=<container-name>
```

## Injection Scenarios

### Option 1: Ephemeral container in the target pod

Injects a debug container that shares the target container's **process namespace**. The socket is accessible via `/proc/<pid>/root/`. Use `make inject` with `TARGET` set to the container that has the socket mounted.

```bash
make inject POD=<pod-name> TARGET=<container-name> [NAMESPACE=<ns>]
```

Inside the shell, find the main process PID and set the socket path:

```bash
# Find the PID of the target container's main process
ps aux

# Use the proc-rooted socket path (PID is often 1, but verify with ps)
export SPIFFE_ENDPOINT_SOCKET=unix:///proc/1/root/spirl-agent-socket/agent.sock

spiffecli get x509-svid
spiffecli get bundle jwt --trust-domain example.com
spiffecli watch x509-svid
```

Check `kubectl describe pod <pod>` → `Mounts` for the container you targeted to find the socket path. Common paths:

| Distribution | Socket path (inside target container) | proc-rooted path |
|---|---|---|
| SPIRL CSI driver | `/spirl-agent-socket/agent.sock` | `/proc/1/root/spirl-agent-socket/agent.sock` |
| SPIRE agent default | `/tmp/spire-agent/public/api.sock` | `/proc/1/root/tmp/spire-agent/public/api.sock` |
| Istio | `/var/run/secrets/workload-spiffe-uds/socket` | `/proc/1/root/var/run/secrets/workload-spiffe-uds/socket` |

**If `/proc/<pid>/root/` returns `Permission denied`:** The UID mismatch between the debug container (root) and target container (non-root) is blocking access. Try `--profile=sysadmin` or see Option C/D in [How it works](#how-it-works).

**If you omit `TARGET`:** The ephemeral container runs in a fully isolated mount namespace. No socket is visible and `spiffecli` will fail with `context deadline exceeded`.

### Option 2: Clone the target pod

Creates a copy of the pod with the debug image replacing the workload image. All volume mounts are preserved — **the socket is accessible at its original path** with no `/proc/` traversal needed. Requires deleting the clone pod when done.

```bash
kubectl debug -it <pod-name> \
  --namespace=<ns> \
  --image=ghcr.io/defakto-security/spiffecli-debug:latest \
  --copy-to=spiffecli-debug-pod \
  --same-node=true \
  --set-image='*=ghcr.io/defakto-security/spiffecli-debug:latest'

# When done:
kubectl delete pod spiffecli-debug-pod --namespace=<ns>
```

Inside the shell, the socket is at its normal path:

```bash
export SPIFFE_ENDPOINT_SOCKET=unix:///spirl-agent-socket/agent.sock
spiffecli get x509-svid
```

This approach works regardless of capabilities or UID, but creates a new pod and does not run inside the original workload.

### Istio-managed pod

Istio delivers SVIDs via its `istio-proxy` sidecar. `make inject-istio` automatically targets the sidecar and sets `SPIFFE_ENDPOINT_SOCKET` to the standard Istio socket path — no extra flags needed inside the shell:

```bash
make inject-istio POD=<pod-name> [NAMESPACE=<ns>]
```

Inside the shell, `SPIFFE_ENDPOINT_SOCKET` is already set:

```bash
spiffecli get x509-svid
spiffecli get jwt-svid --audiences my-service
spiffecli watch bundle x509
```

The Istio socket path used is:
```
unix:///var/run/secrets/workload-spiffe-uds/socket
```

### Local development with kind

For kind clusters, the image is loaded directly into the cluster — no registry required:

```bash
make inject POD=<pod-name> TARGET=<container-name> CLUSTER_TYPE=kind
# or
make inject-istio POD=<pod-name> CLUSTER_TYPE=kind
```

If your cluster was created with a custom name (`kind create cluster --name my-cluster`), pass `KIND_CLUSTER`:

```bash
make inject POD=<pod-name> TARGET=<container-name> CLUSTER_TYPE=kind KIND_CLUSTER=my-cluster
```

### Local development with k3d

For k3d clusters:

```bash
make inject POD=<pod-name> TARGET=<container-name> CLUSTER_TYPE=k3d
make inject-istio POD=<pod-name> CLUSTER_TYPE=k3d
```

## Variables

All variables can be overridden on the command line.

| Variable | Default | Description |
|---|---|---|
| `POD` | *(required)* | Name of the target pod |
| `NAMESPACE` | `default` | Kubernetes namespace containing the pod |
| `TARGET` | *(none)* | Container whose **process namespace** to share. Required to reach the Workload API socket. (`inject-istio` always uses `istio-proxy`) |
| `IMAGE` | `ghcr.io/defakto-security/spiffecli-debug:latest` | Full image reference for the debug container |
| `CLUSTER_TYPE` | `registry` | Image distribution method: `registry` (push), `kind` (load), or `k3d` (import) |
| `KIND_CLUSTER` | `kind` | kind cluster name; override if your cluster was created with a non-default name (e.g. `kind create cluster --name my-cluster`) |

## Build targets

| Target | Description |
|---|---|
| `make inject-build` | Build the debug image locally |
| `make inject-load` | Build then distribute according to `CLUSTER_TYPE` |
| `make inject` | Full flow: build → distribute → inject into pod |
| `make inject-istio` | Full flow targeting the Istio proxy sidecar |

### Build with a custom image tag

```bash
make inject-build IMAGE=myregistry.io/spiffecli-debug:v1.2.3
make inject POD=my-pod IMAGE=myregistry.io/spiffecli-debug:v1.2.3
```

## Manual injection (without make)

If you have a pre-built image and just need the `kubectl debug` command:

```bash
# Option 1: Ephemeral container — shares process namespace of target container
kubectl debug -it <pod> \
  --namespace=<ns> \
  --image=ghcr.io/defakto-security/spiffecli-debug:latest \
  --profile=general \
  --target=<container>
# Inside shell: export SPIFFE_ENDPOINT_SOCKET=unix:///proc/<pid>/root/<socket-path>

# Istio pod — target istio-proxy and pre-set the socket env var
kubectl debug -it <pod> \
  --namespace=<ns> \
  --image=ghcr.io/defakto-security/spiffecli-debug:latest \
  --profile=general \
  --target=istio-proxy \
  --env="SPIFFE_ENDPOINT_SOCKET=unix:///var/run/secrets/workload-spiffe-uds/socket"

# Option 2: Clone pod — socket accessible at its original path, no /proc needed
kubectl debug -it <pod> \
  --namespace=<ns> \
  --image=ghcr.io/defakto-security/spiffecli-debug:latest \
  --copy-to=spiffecli-debug-pod \
  --same-node=true \
  --set-image='*=ghcr.io/defakto-security/spiffecli-debug:latest'
# Inside shell: export SPIFFE_ENDPOINT_SOCKET=unix:///<original-socket-path>
# When done: kubectl delete pod spiffecli-debug-pod --namespace=<ns>
```
