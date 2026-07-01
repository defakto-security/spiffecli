---
title: watch bundle
sidebar_position: 14
---
## spiffecli watch bundle

Stream bundle updates from the Workload API

```
spiffecli watch bundle TYPE [flags]
```

Connects to the Workload API and continuously streams trust bundle update events until interrupted (Ctrl+C). `TYPE` must be `x509` or `jwt`. Emits an event immediately on connect with the current bundle state, then again each time the bundle rotates.

### Options

```
      --format string   Output format (json-stream, summary-stream, event-log) (default "summary-stream")
  -h, --help            help for bundle
```

### Options inherited from parent commands

```
  -s, --spiffe-endpoint-socket string   Path to Workload API socket
```

### Output Formats

| Format | Description |
|--------|-------------|
| `summary-stream` | Human-readable timestamped lines, e.g. `[2026-03-05T12:00:00Z] Bundle updated: example.com (1 key)` |
| `json-stream` | One JSON object per line (JSONL), suitable for piping to `jq` |
| `event-log` | Key=value structured log lines |

### Examples

```bash
# Watch X.509 bundle updates
spiffecli watch bundle x509 \
  --spiffe-endpoint-socket unix:///tmp/spire-agent/public/api.sock

# Watch JWT bundle updates with JSON output
spiffecli watch bundle jwt \
  --spiffe-endpoint-socket unix:///tmp/spire-agent/public/api.sock \
  --format json-stream | jq .
```

