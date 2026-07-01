---
title: watch jwt-svid
sidebar_position: 13
---
## spiffecli watch jwt-svid

Periodically fetch and stream JWT SVID events from the Workload API

```
spiffecli watch jwt-svid [flags]
```

Connects to the Workload API and fetches a JWT SVID immediately, then re-fetches at each interval until interrupted (Ctrl+C). The SPIFFE Workload API does not stream JWT SVIDs natively, so this command uses a polling loop.

### Options

```
      --audiences strings   Comma-separated list of audiences for JWT SVID
      --format string       Output format (json-stream, summary-stream, event-log) (default "summary-stream")
  -h, --help                help for jwt-svid
      --interval duration   Interval between JWT SVID fetches (default 1m0s)
```

### Options inherited from parent commands

```
  -s, --spiffe-endpoint-socket string   Path to Workload API socket
```

### Output Formats

| Format | Description |
|--------|-------------|
| `summary-stream` | Human-readable timestamped lines, e.g. `[2026-03-05T12:00:00Z] JWT SVID fetched: spiffe://example.com/frontend (expires ...)` |
| `json-stream` | One JSON object per line (JSONL), suitable for piping to `jq` |
| `event-log` | Key=value structured log lines |

### Examples

```bash
# Watch JWT SVIDs, re-fetching every 30 seconds
spiffecli watch jwt-svid \
  --spiffe-endpoint-socket unix:///tmp/spire-agent/public/api.sock \
  --audiences myservice \
  --interval 30s

# Watch with JSON output
spiffecli watch jwt-svid \
  --spiffe-endpoint-socket unix:///tmp/spire-agent/public/api.sock \
  --audiences myservice,otherservice \
  --format json-stream | jq .
```

