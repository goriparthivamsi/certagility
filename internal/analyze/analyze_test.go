package analyze

import (
	"testing"
	"time"

	"github.com/goriparthivamsi/certagility/internal/model"
)

func has(r model.CertRecord, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestMaxPublicValidityDays(t *testing.T) {
	cases := []struct {
		d    time.Time
		want int
	}{
		{time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), 398},
		{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), 200},
		{time.Date(2027, 3, 14, 0, 0, 0, 0, time.UTC), 200},
		{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), 100},
		{time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), 47},
	}
	for _, c := range cases {
		if got := MaxPublicValidityDays(c.d); got != c.want {
			t.Errorf("MaxPublicValidityDays(%s)=%d want %d", c.d.Format("2006-01-02"), got, c.want)
		}
	}
}

func TestRecordFindings(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	r := model.CertRecord{
		KeyAlgorithm: "RSA", KeySize: 1024, SignatureAlgorithm: "SHA1-RSA",
		NotBefore: now.AddDate(0, -1, 0), NotAfter: now.AddDate(0, 0, 5),
		PubliclyTrusted: true, TLSVersion: "TLS 1.2", Source: "endpoint",
	}
	Record(&r, now, DefaultOptions())
	for _, code := range []string{"EXPIRING_SOON", "WEAK_KEY", "WEAK_SIGNATURE", "QUANTUM_VULNERABLE", "TLS13_NOT_NEGOTIATED"} {
		if !has(r, code) {
			t.Errorf("expected finding %s, got %+v", code, r.Findings)
		}
	}
	if r.MaxSeverity() != model.SevCritical {
		t.Errorf("max severity = %s", r.MaxSeverity())
	}
}

func TestCABFValidityExceeded(t *testing.T) {
	issued := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	r := model.CertRecord{KeyAlgorithm: "ECDSA", KeySize: 256, SignatureAlgorithm: "ECDSA-SHA256",
		NotBefore: issued, NotAfter: issued.AddDate(0, 0, 397), PubliclyTrusted: true}
	Record(&r, issued.AddDate(0, 0, 10), DefaultOptions())
	if !has(r, "CABF_VALIDITY_EXCEEDED") {
		t.Fatalf("expected CABF_VALIDITY_EXCEEDED, got %+v", r.Findings)
	}
	r.PubliclyTrusted = false
	Record(&r, issued.AddDate(0, 0, 10), DefaultOptions())
	if has(r, "CABF_VALIDITY_EXCEEDED") {
		t.Fatal("private certificates must not be held to the CA/B schedule")
	}
	if !has(r, "LIFETIME_47D_READINESS") {
		t.Fatal("expected 47-day readiness notice")
	}
}

func TestPQCNotQuantumVulnerable(t *testing.T) {
	if QuantumVulnerable("ML-DSA-65") {
		t.Fatal("ML-DSA must not be flagged as quantum vulnerable")
	}
}
