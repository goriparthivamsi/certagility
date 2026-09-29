# Security Policy

Please report vulnerabilities privately through GitHub Security Advisories ("Report a vulnerability" on this repository). Do not open a public issue.

## Design notes

- certagility parses only certificate material (`tls.crt`, `ca.crt`, PEM/DER files, ACM certificate bodies). It never parses or outputs private keys.
- Endpoint scanning uses `InsecureSkipVerify` only so it can capture the presented chain for inventory. Trust is evaluated separately against the system trust store and reported as a finding.
- Reports can contain internal hostnames and certificate subjects. Treat them as internal data.
