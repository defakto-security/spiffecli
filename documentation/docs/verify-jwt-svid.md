---
title: verify jwt-svid
sidebar_position: 7
---
## spiffecli verify jwt-svid

Verify a JWT SVID

```
spiffecli verify jwt-svid [flags]
```

### Options

```
      --audiences strings               Comma-separated list of audiences for JWT SVID
      --bundle string                   URL or filename of bundle to use for verification instead of the workload API
      --filename string                 Name of file to read the JWT SVID from
  -h, --help                            help for jwt-svid
  -s, --spiffe-endpoint-socket string   Path to Workload API socket (env: SPIFFE_ENDPOINT_SOCKET)
      --token string                    The JWT SVID token to verify
      --trust-domain string             Trust domain to use for verification
```

