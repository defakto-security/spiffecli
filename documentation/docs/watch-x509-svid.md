---
title: watch x509-svid
sidebar_position: 12
---
## spiffecli watch x509-svid

Stream X.509 SVID updates from the Workload API

```
spiffecli watch x509-svid [flags]
```

Connects to the Workload API and continuously streams X.509 SVID update events until interrupted (Ctrl+C). Emits an event immediately on connect, then again each time the SVID rotates.

### Options

```
      --format string   Output format (json-stream, summary-stream, event-log) (default "summary-stream")
  -h, --help            help for x509-svid
```

### Options inherited from parent commands

```
  -s, --spiffe-endpoint-socket string   Path to Workload API socket
```

### Output Formats

| Format | Description |
|--------|-------------|
| `summary-stream` | Human-readable timestamped lines, e.g. `[2026-03-05T12:00:00Z] X.509 SVID updated: spiffe://example.com/frontend (expires ...)` |
| `json-stream` | One JSON object per line (JSONL), suitable for piping to `jq` |
| `event-log` | Key=value structured log lines |

### Examples

```bash
# Watch with default summary output
spiffecli watch x509-svid --spiffe-endpoint-socket unix:///tmp/spire-agent/public/api.sock

# Watch and pipe to jq
spiffecli watch x509-svid \
  --spiffe-endpoint-socket unix:///tmp/spire-agent/public/api.sock \
  --format json-stream | jq .
```

