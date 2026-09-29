// Package testutil generates throwaway certificates for tests.
package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Cert is a generated certificate with its key.
type Cert struct {
	X509 *x509.Certificate
	Key  crypto.Signer
	PEM  []byte
}

// Options control certificate generation.
type Options struct {
	CN        string
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	RSABits   int // 0 = ECDSA P-256
	IsCA      bool
	Parent    *Cert // nil = self-signed
}

// New creates a certificate for tests.
func New(t testing.TB, o Options) *Cert {
	t.Helper()
	var key crypto.Signer
	var err error
	if o.RSABits > 0 {
		key, err = rsa.GenerateKey(rand.Reader, o.RSABits)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = o.NotBefore.AddDate(0, 0, 90)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: o.CN, Organization: []string{"certagility test"}},
		DNSNames:              o.DNSNames,
		NotBefore:             o.NotBefore,
		NotAfter:              o.NotAfter,
		IsCA:                  o.IsCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signer := tmpl, key
	if o.Parent != nil {
		parent, signer = o.Parent.X509, o.Parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &Cert{X509: c, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}
