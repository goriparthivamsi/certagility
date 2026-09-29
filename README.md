# certagility

**Cryptographic inventory and certificate-lifecycle readiness scanner for cloud-native infrastructure.**

`certagility` finds X.509 certificates across **TLS endpoints, certificate files, Kubernetes `kubernetes.io/tls` Secrets and AWS Certificate Manager**. It reports three things:

- **Lifecycle risk:** certificates that are expired, expiring, or not yet valid.
- **47-day readiness:** which certificates will break under the CA/Browser Forum's shrinking maximum lifetimes (200 → 100 → **47 days by March 2029**), and which renewals therefore have to be automated.
- **Post-quantum readiness:** which keys and signatures are vulnerable to a cryptographically relevant quantum computer (RSA, ECDSA, Ed25519, DSA). It also recognizes NIST PQC algorithms (ML-DSA / SLH-DSA, FIPS 204/205).

The inventory can be exported as a **CycloneDX 1.6 CBOM** (Cryptography Bill of Materials) or as **Prometheus metrics**, so it plugs into existing security and SRE tooling.

> Why this matters: see [docs/why.md](docs/why.md). In short, certificate expiry is still a leading cause of avoidable outages, public certificate lifetimes are shrinking to 47 days, and U.S. federal policy (EO 14412, OMB M-26-15) now calls for automated, continuously updated cryptographic inventories to drive the migration to post-quantum cryptography.

## Install

```bash
go install github.com/goriparthivamsi/certagility/cmd/certagility@latest
# or download a release binary / container: ghcr.io/goriparthivamsi/certagility
```

## Usage

```bash
# TLS endpoints (default port 443)
certagility scan -e example.com -e api.internal:8443
certagility scan --endpoints-file examples/endpoints.txt

# Files and directories (.pem .crt .cer .cert .der; bundles supported)
certagility scan -p /etc/ssl/private-ca/

# Kubernetes (current kubeconfig context, all namespaces)
certagility scan --kubernetes
certagility scan --kubernetes --kube-context prod -n payments

# AWS Certificate Manager (read-only: acm:ListCertificates, acm:GetCertificate)
certagility scan --acm --aws-region us-east-1 --aws-region us-west-2

# Mix sources; emit a CycloneDX CBOM; fail CI on any high/critical finding
certagility scan --kubernetes --acm -o cbom --out-file cbom.json --fail-on high
```

Example output:

```
SEVERITY  DAYS  SOURCE      LOCATION                  SUBJECT CN        KEY        VALIDITY  PQ-SAFE  FINDINGS
CRITICAL  3     kubernetes  payments/api-tls[tls.crt] api.bank.test     RSA-2048   90d       no       EXPIRING_SOON,QUANTUM_VULNERABLE,LIFETIME_47D_READINESS
HIGH      21    endpoint    portal.example.com:443    portal.example..  ECDSA-256  397d      no       EXPIRING,QUANTUM_VULNERABLE,CABF_VALIDITY_EXCEEDED,...

2 certificates | 0 expired | 2 expiring <30d | 2 quantum-vulnerable | 2 exceed 47-day lifetime | 0 scan errors
```

### Output formats (`-o`)

| Format | Use |
|---|---|
| `table` | Human-readable summary (default) |
| `json` | Full inventory with every finding |
| `cbom` | CycloneDX 1.6 Cryptography Bill of Materials (certificate, key and signature-algorithm assets) |
| `prometheus` | Prometheus text exposition for node-exporter textfile collectors |

### Exporter mode

```bash
certagility serve --kubernetes --endpoints-file endpoints.txt --interval 15m --listen :9115
# GET /metrics  (Prometheus)   GET /cbom  (CycloneDX)   GET /healthz
```

For in-cluster deployment, see [deploy/kubernetes/exporter.yaml](deploy/kubernetes/exporter.yaml). Example alert rules are in [examples/prometheus-alerts.yaml](examples/prometheus-alerts.yaml).

## Findings

| Code | Severity | Meaning |
|---|---|---|
| `EXPIRED` / `EXPIRING_SOON` / `EXPIRING` | critical / critical / high | Certificate is expired, or inside `--crit-days` (7) / `--warn-days` (30) |
| `NOT_YET_VALID` | high | `notBefore` is in the future |
| `WEAK_KEY` | high | RSA key under 2048 bits, or a DSA key |
| `WEAK_SIGNATURE` | high | SHA-1 / MD5 signature |
| `CABF_VALIDITY_EXCEEDED` | high | Publicly trusted leaf certificate exceeds the SC-081v3 maximum for its issuance date |
| `LIFETIME_47D_READINESS` | info | Leaf certificate lifetime is over 47 days, so renewal automation must be proven before 2029 |
| `QUANTUM_VULNERABLE` | low / medium | RSA/ECC/EdDSA key. Medium if the certificate is still valid after 2030 |
| `WEAK_TLS_VERSION` / `TLS13_NOT_NEGOTIATED` | high / info | Endpoint negotiated TLS below 1.2, or TLS 1.2 instead of 1.3 |
| `UNTRUSTED_CHAIN` | info | Chain does not verify against system roots (expected for private PKI) |

## Security

- Only certificates are parsed; private keys are never read into reports.
- Kubernetes: listing Secrets is sensitive. Scope RBAC to the namespaces you need.
- AWS: only read-only ACM calls are made.

See [SECURITY.md](SECURITY.md).

## Roadmap

- Detection of hybrid post-quantum TLS key exchange (X25519MLKEM768) on endpoints
- cert-manager `Certificate` / `Issuer` awareness (renewal configuration vs. 47-day target)
- HashiCorp Vault PKI, Azure Key Vault and Google Certificate Manager sources
- Helm chart and Grafana dashboard
- Policy-as-code profiles (internal PKI lifetime limits, algorithm allow-lists)

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0
