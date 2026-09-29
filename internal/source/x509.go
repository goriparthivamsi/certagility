// Package source discovers certificates from endpoints, files, Kubernetes and AWS ACM.
package source

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/goriparthivamsi/certagility/internal/model"
)

// FromX509 converts a parsed certificate into a CertRecord (analysis is done later).
func FromX509(c *x509.Certificate, source, location string, pos int) model.CertRecord {
	sum := sha256.Sum256(c.Raw)
	r := model.CertRecord{
		Source:             source,
		Location:           location,
		ChainPos:           pos,
		Subject:            c.Subject.String(),
		CommonName:         c.Subject.CommonName,
		Issuer:             c.Issuer.String(),
		DNSNames:           c.DNSNames,
		Serial:             strings.ToUpper(c.SerialNumber.Text(16)),
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
		SHA256Fingerprint:  strings.ToUpper(hex.EncodeToString(sum[:])),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:               c.IsCA,
		SelfSigned:         bytes.Equal(c.RawIssuer, c.RawSubject),
	}
	r.SignatureOID = signatureOID(c)
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		r.KeyAlgorithm, r.KeySize = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		r.KeyAlgorithm, r.KeySize, r.Curve = "ECDSA", k.Curve.Params().BitSize, k.Curve.Params().Name
	case ed25519.PublicKey:
		r.KeyAlgorithm, r.KeySize, r.Curve = "Ed25519", 256, "Ed25519"
	default:
		r.KeyAlgorithm = classifyUnknownKey(c)
	}
	if r.SignatureAlgorithm == "0" || r.SignatureAlgorithm == "" {
		r.SignatureAlgorithm = sigNameFromOID(r.SignatureOID)
	}
	return r
}

// ParsePEMBundle parses all CERTIFICATE blocks in data. It also accepts a single DER cert.
func ParsePEMBundle(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return out, fmt.Errorf("parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		if c, err := x509.ParseCertificate(data); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}
