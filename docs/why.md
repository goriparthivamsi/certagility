# Why certificate lifecycle and crypto-agility need automation now

1. **Shrinking certificate lifetimes.** CA/Browser Forum Ballot SC-081v3 (adopted April 2025) reduces the maximum validity of publicly trusted TLS certificates:

   | Issued on or after | Maximum validity |
   |---|---|
   | 2026-03-15 | 200 days |
   | 2027-03-15 | 100 days |
   | 2029-03-15 | 47 days |

   Domain-validation reuse drops to 10 days. At 47 days, manual renewal stops being workable: every certificate needs automated issuance, deployment and monitoring.

2. **Expired certificates still cause major outages.** NIST SP 1800-16 (*Securing Web Transactions: TLS Server Certificate Management*) names outages caused by expired certificates as a core risk, and recommends automation and a full certificate inventory.

3. **Post-quantum migration starts with inventory.**
   - NIST published FIPS 203/204/205 (ML-KEM, ML-DSA, SLH-DSA) in August 2024.
   - The draft NIST IR 8547 deprecates 112-bit RSA/ECC after 2030 and disallows it after 2035.
   - Executive Order 14412 (June 2026) and OMB M-26-15 set federal PQC migration deadlines. They call for an *automated cryptographic inventory, dynamic and continuously updated*, and for crypto-agility.
   - Sector risk management agencies are directed to help critical-infrastructure operators, including in financial services and healthcare, plan their migrations.

4. **Cloud-native sprawl.** Certificates now live in Kubernetes Secrets, service meshes, cloud certificate managers and load balancers, often owned by different teams. `certagility` puts them in one inventory in standard formats: CycloneDX CBOM for security and compliance, and Prometheus for SRE alerting.

Verify policy citations against the primary sources before relying on them for compliance decisions.
