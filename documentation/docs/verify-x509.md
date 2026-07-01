---
title: verify x509
sidebar_position: 8
---
## spiffecli verify x509

Verify an x509 certificate against a variety of CA bundles (trust stores)

```
spiffecli verify x509 [flags]
```

### Options

```
      --ca-bundle string      Filename or URL containing list of CAs to trust. Requires --ca-format
      --ca-format string      CA bundle format. Available options are 'pem', 'jks', 'p12' (default "pem")
      --ca-password string    Password ("integrity check") for CA bundle, if required. Usually only necessary for Java keystores
      --certificate string    File or URL endpoint for certificate and chain
      --format string         Certificate file format. Available options are 'pem' or 'der', defaults to pem (default "pem")
  -h, --help                  help for x509
      --password string       Certificate password, for password-protected DER files containing a single certificate
      --root-program string   Only 'mozilla' is supported
      --show-path             Show verification path(s)
      --system                Use the system trust store
```

