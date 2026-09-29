// Package analyze derives lifecycle, policy and quantum-readiness findings for certificates.
package analyze

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/goriparthivamsi/certagility/internal/model"
)

// Options tune the analysis thresholds.
type Options struct {
	WarnDays int // days before expiry that raise a warning
	CritDays int // days before expiry that raise a critical finding
}

// DefaultOptions returns sensible defaults (30/7 days).
func DefaultOptions() Options { return Options{WarnDays: 30, CritDays: 7} }

// cabfStep is one step of the CA/Browser Forum Ballot SC-081v3 validity schedule.
type cabfStep struct {
	From    time.Time
	MaxDays int
}

// CABFSchedule is the maximum TLS subscriber certificate validity by issuance date
// (CA/Browser Forum Ballot SC-081v3, adopted April 2025).
var CABFSchedule = []cabfStep{
	{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), 200},
	{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), 100},
	{time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), 47},
}

// MaxPublicValidityDays returns the SC-081 maximum validity for a certificate issued at t.
func MaxPublicValidityDays(issued time.Time) int {
	max := 398
	for _, s := range CABFSchedule {
		if !issued.Before(s.From) {
			max = s.MaxDays
		}
	}
	return max
}

// QuantumVulnerable reports whether the public-key algorithm is breakable by a
// cryptographically relevant quantum computer (Shor's algorithm).
func QuantumVulnerable(keyAlg string) bool {
	switch keyAlg {
	case "RSA", "ECDSA", "Ed25519", "DSA":
		return true
	}
	return false
}

func days(d time.Duration) int { return int(math.Ceil(d.Hours() / 24)) }

// Record populates derived fields and findings on r, evaluated at now.
func Record(r *model.CertRecord, now time.Time, o Options) {
	r.Findings = nil
	r.DaysRemaining = int(math.Floor(r.NotAfter.Sub(now).Hours() / 24))
	r.ValidityDays = days(r.NotAfter.Sub(r.NotBefore) + time.Second)
	r.QuantumVulnerable = QuantumVulnerable(r.KeyAlgorithm)
	add := func(sev, code, msg string, a ...any) {
		r.Findings = append(r.Findings, model.Finding{Severity: sev, Code: code, Message: fmt.Sprintf(msg, a...)})
	}

	// Lifecycle
	switch {
	case now.After(r.NotAfter):
		add(model.SevCritical, "EXPIRED", "certificate expired on %s", r.NotAfter.Format("2006-01-02"))
	case r.DaysRemaining < o.CritDays:
		add(model.SevCritical, "EXPIRING_SOON", "certificate expires in %d days (%s)", r.DaysRemaining, r.NotAfter.Format("2006-01-02"))
	case r.DaysRemaining < o.WarnDays:
		add(model.SevHigh, "EXPIRING", "certificate expires in %d days (%s)", r.DaysRemaining, r.NotAfter.Format("2006-01-02"))
	}
	if now.Before(r.NotBefore) {
		add(model.SevHigh, "NOT_YET_VALID", "certificate is not valid until %s", r.NotBefore.Format("2006-01-02"))
	}

	// Classical cryptographic strength
	if r.KeyAlgorithm == "RSA" && r.KeySize < 2048 {
		add(model.SevHigh, "WEAK_KEY", "RSA key size %d bits is below the 2048-bit minimum", r.KeySize)
	}
	if r.KeyAlgorithm == "DSA" {
		add(model.SevHigh, "WEAK_KEY", "DSA keys are no longer approved for signature generation (FIPS 186-5)")
	}
	sig := strings.ToUpper(r.SignatureAlgorithm)
	if strings.Contains(sig, "SHA1") || strings.Contains(sig, "MD5") || strings.Contains(sig, "MD2") {
		add(model.SevHigh, "WEAK_SIGNATURE", "signature algorithm %s is deprecated", r.SignatureAlgorithm)
	}

	// Quantum readiness
	if r.QuantumVulnerable {
		sev := model.SevLow
		if r.NotAfter.After(time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)) {
			sev = model.SevMedium
		}
		add(sev, "QUANTUM_VULNERABLE",
			"%s key is vulnerable to a cryptographically relevant quantum computer; plan migration to ML-DSA/SLH-DSA (FIPS 204/205). NIST IR 8547 (draft) deprecates 112-bit RSA/ECC after 2030 and disallows it after 2035",
			r.KeyAlgorithm)
	}

	// Lifetime policy (leaf certificates only)
	if !r.IsCA && r.ChainPos == 0 {
		max := MaxPublicValidityDays(r.NotBefore)
		if r.PubliclyTrusted && r.ValidityDays > max {
			add(model.SevHigh, "CABF_VALIDITY_EXCEEDED",
				"validity of %d days exceeds the %d-day maximum for publicly trusted TLS certificates issued on %s (CA/B Forum SC-081v3)",
				r.ValidityDays, max, r.NotBefore.Format("2006-01-02"))
		}
		if r.ValidityDays > 47 {
			add(model.SevInfo, "LIFETIME_47D_READINESS",
				"validity is %d days; from 2029-03-15 public TLS certificates are limited to 47 days, so renewal must be fully automated", r.ValidityDays)
		}
	}

	// Transport
	switch r.TLSVersion {
	case "TLS 1.0", "TLS 1.1", "SSL 3.0":
		add(model.SevHigh, "WEAK_TLS_VERSION", "endpoint negotiated %s", r.TLSVersion)
	case "TLS 1.2":
		add(model.SevInfo, "TLS13_NOT_NEGOTIATED", "endpoint negotiated TLS 1.2; TLS 1.3 is required for federal systems by 2030-01-02 (EO 14306)")
	}
	if r.Source == "endpoint" && r.ChainPos == 0 && !r.PubliclyTrusted {
		add(model.SevInfo, "UNTRUSTED_CHAIN", "chain does not verify against the system trust store (expected for private PKI)")
	}
}

// Inventory analyzes every record in inv.
func Inventory(inv *model.Inventory, now time.Time, o Options) {
	for i := range inv.Certificates {
		Record(&inv.Certificates[i], now, o)
	}
}
