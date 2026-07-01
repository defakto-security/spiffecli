---
slug: /
sidebar_position: 1
---

# SPIFFE CLI Docs

SPIFFE CLI is a command line tool that allows the following:

1. Requesting and validation of SVIDs, as well as retrieval of x.509 or JWT bundles, from workload endpoints.
2. `spiffecli run` starts a [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) locally.
3. Validation of JWT-SVIDs against local bundles, or those served from a remote endpoint.
4. Verification of X.509 certificates against local CA bundles, the system store, or the most recent version of a root program (only mozilla is supported at the moment).
5. Real-time monitoring of SVID and bundle rotation via `spiffecli watch`.
6. Live debugging of Kubernetes workloads by [injecting spiffecli as an ephemeral container](inject.md) — no pod restart required.

## Installation

Download the spiffecli binary for your OS in the [Releases page](https://github.com/defakto-security/spiffecli/releases).

Or build from source by cloning the repo and running:

```bash
make build
./bin/spiffecli
```

## Run a local Workload API

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


## Verification
As well as SVID verification, `spiffecli` includes methods to verify arbitrary JWTs or X.509 certificates.

### Verify a JWT
Here's a demonstration of JWT verification:

![Verify JWT](/img/verify-demo.gif)


### Verify an X.509 certificate

Here's an example of verifying an endpoint certificate against the system bundle, showing the verification path:

```bash
$ ./bin/spiffecli verify x509 --certificate https://aws.amazon.com/ --system --show-path
Found single validation path:
── CN=aws.amazon.com
   └─ CN=Amazon RSA 2048 M01,O=Amazon,C=US
      └─ CN=Amazon Root CA 1,O=Amazon,C=US
```

