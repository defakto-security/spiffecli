---
title: inspect x509
sidebar_position: 11
---
## spiffecli inspect x509

Inspect an X.509-SVID (or any X.509 certificate)

### Synopsis

Inspect an X.509-SVID or any X.509 certificate and display its fields in structured form.

Output includes all Subject Alternative Name (SAN) fields and the certificate Subject
(X.500 Distinguished Name), which may contain email addresses (PII), personal names,
and internal hostnames. Operators who pipe this command's output to external systems —
log aggregators, SIEMs, audit trails — should apply appropriate data-handling controls
before routing output to such systems.

```
spiffecli inspect x509 [flags]
```

### Options

```
      --bundle string        Path to a PEM file with additional CA certificates (for --format chain/tree).
      --color                Enable colorized output for json/yaml/summary. Has no effect for chain or tree formats.
      --filename string      Name of input file containing the X.509-SVID (PEM)
      --format string        Output format is one of "json", "yaml", "summary", "chain", or "tree". (default "json")
  -h, --help                 help for x509
      --indent               Indent JSON output. Has no effect for other output formats
      --isSvid               Return 0 if input is a well-formed X.509-SVID, 1 otherwise. Disables other output.
      --shortest-path        Filter chain output to the shortest valid path from leaf to a root. Requires --format chain. Roots come from --bundle or self-signed certs in --filename.
      --timezone string      Timezone to use for "summary" format. Defaults to local timezone
      --tree-fields string   Comma-separated per-node attributes for --format tree; if omitted, 'subject' is used. Allowed: subject, issuer, spiffe-id, serial, not-after, key-algorithm, sha256-fp.
```

