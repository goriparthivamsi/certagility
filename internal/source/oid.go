package source

import (
	"crypto/x509"
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Post-quantum and hybrid OIDs (NIST FIPS 204 / FIPS 205 as registered by NIST CSOR).
var pqcSigOIDs = map[string]string{
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
	"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
	"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
	"2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
	"2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
	"2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
	"2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
	"2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
	"2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
	"2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
	"2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
	"2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
	"2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
	"2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
	"2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
}

// IsPQCAlgorithm reports whether a signature algorithm name is a NIST PQC algorithm.
func IsPQCAlgorithm(name string) bool {
	for _, v := range pqcSigOIDs {
		if v == name {
			return true
		}
	}
	return false
}

// signatureOID extracts the signatureAlgorithm OID from the raw TBS-wrapping certificate.
func signatureOID(c *x509.Certificate) string {
	input := cryptobyte.String(c.Raw)
	var cert, tbs, sigAlg cryptobyte.String
	if !input.ReadASN1(&cert, cbasn1.SEQUENCE) ||
		!cert.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!cert.ReadASN1(&sigAlg, cbasn1.SEQUENCE) {
		return ""
	}
	var oid asn1.ObjectIdentifier
	if !sigAlg.ReadASN1ObjectIdentifier(&oid) {
		return ""
	}
	return oid.String()
}

// spkiOID extracts the SubjectPublicKeyInfo algorithm OID.
func spkiOID(c *x509.Certificate) string {
	input := cryptobyte.String(c.RawSubjectPublicKeyInfo)
	var spki, alg cryptobyte.String
	if !input.ReadASN1(&spki, cbasn1.SEQUENCE) || !spki.ReadASN1(&alg, cbasn1.SEQUENCE) {
		return ""
	}
	var oid asn1.ObjectIdentifier
	if !alg.ReadASN1ObjectIdentifier(&oid) {
		return ""
	}
	return oid.String()
}

func sigNameFromOID(oid string) string {
	if n, ok := pqcSigOIDs[oid]; ok {
		return n
	}
	if oid == "" {
		return "unknown"
	}
	return "OID " + oid
}

func classifyUnknownKey(c *x509.Certificate) string {
	oid := spkiOID(c)
	if n, ok := pqcSigOIDs[oid]; ok {
		return n
	}
	if oid == "1.2.840.10040.4.1" {
		return "DSA"
	}
	if oid == "" {
		return "unknown"
	}
	return "OID " + oid
}
