# Security Policy

## Reporting a Vulnerability

We take the security of `spiffecli` seriously. If you believe you have found a
security vulnerability, please report it to us privately. **Do not open a public
GitHub issue for security vulnerabilities.**

Please use one of the following channels:

- **GitHub Security Advisories** (preferred): open a private report via the
  ["Report a vulnerability"](https://github.com/defakto-security/spiffecli/security/advisories/new)
  button under the repository's **Security** tab.
- **Email**: security@defakto.security. If you would like to encrypt your report,
  ask us for a PGP key in your first message.

Please include as much of the following as you can:

- A description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept, affected commands/flags, sample inputs)
- The version or commit of `spiffecli` you tested against
- Any suggested remediation, if you have one

## What to Expect

- We will acknowledge your report within **3 business days**.
- We will provide an initial assessment and expected timeline within **10 business days**.
- We will keep you informed of progress toward a fix and coordinate a disclosure
  date with you.
- We are happy to credit reporters in the release notes and advisory unless you
  prefer to remain anonymous.

## Scope

This policy covers the `spiffecli` codebase in this repository. Vulnerabilities
in upstream dependencies should be reported to the respective projects; if a
dependency issue affects `spiffecli`, we still want to hear about it so we can
update or mitigate.

## Supported Versions

`spiffecli` is under active development. Security fixes are applied to the
`main` branch and included in the next release. We recommend always running the
latest released version.
