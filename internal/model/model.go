// Package model defines the normalized certificate inventory record shared by
// all sources, analyzers and reporters.
package model

import "time"

// Severity levels, ordered from least to most severe.
const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

var sevRank = map[string]int{SevInfo: 1, SevLow: 2, SevMedium: 3, SevHigh: 4, SevCritical: 5}

// SeverityRank returns a comparable rank for a severity string (0 if unknown).
func SeverityRank(s string) int { return sevRank[s] }

// Finding is a single observation about a certificate.
type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// CertRecord is one X.509 certificate discovered in one location.
type CertRecord struct {
	Source   string `json:"source"`   // endpoint | file | kubernetes | acm
	Location string `json:"location"` // host:port, file path, namespace/secret, ACM ARN
	ChainPos int    `json:"chainPosition"`

	Subject            string    `json:"subject"`
	CommonName         string    `json:"commonName"`
	Issuer             string    `json:"issuer"`
	DNSNames           []string  `json:"dnsNames,omitempty"`
	Serial             string    `json:"serial"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	SHA256Fingerprint  string    `json:"sha256Fingerprint"`
	KeyAlgorithm       string    `json:"keyAlgorithm"`
	KeySize            int       `json:"keySize"`
	Curve              string    `json:"curve,omitempty"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	SignatureOID       string    `json:"signatureOID,omitempty"`
	IsCA               bool      `json:"isCA"`
	SelfSigned         bool      `json:"selfSigned"`
	PubliclyTrusted    bool      `json:"publiclyTrusted"`

	// Endpoint-only connection details.
	TLSVersion  string `json:"tlsVersion,omitempty"`
	CipherSuite string `json:"cipherSuite,omitempty"`

	// Derived by the analyzer.
	DaysRemaining     int       `json:"daysRemaining"`
	ValidityDays      int       `json:"validityDays"`
	QuantumVulnerable bool      `json:"quantumVulnerable"`
	Findings          []Finding `json:"findings"`
}

// MaxSeverity returns the most severe finding level on the record ("" if none).
func (r *CertRecord) MaxSeverity() string {
	max := ""
	for _, f := range r.Findings {
		if SeverityRank(f.Severity) > SeverityRank(max) {
			max = f.Severity
		}
	}
	return max
}

// ScanError records a location that could not be scanned.
type ScanError struct {
	Source   string `json:"source"`
	Location string `json:"location"`
	Error    string `json:"error"`
}

// Inventory is the full result of a scan.
type Inventory struct {
	GeneratedAt  time.Time    `json:"generatedAt"`
	ToolVersion  string       `json:"toolVersion"`
	Certificates []CertRecord `json:"certificates"`
	Errors       []ScanError  `json:"errors,omitempty"`
}
