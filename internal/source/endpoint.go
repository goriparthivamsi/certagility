package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/goriparthivamsi/certagility/internal/model"
)

// EndpointOptions controls TLS endpoint scanning.
type EndpointOptions struct {
	Timeout time.Duration
	Roots   *x509.CertPool // nil = system roots
}

// NormalizeTarget adds the default port 443 when missing.
func NormalizeTarget(t string) string {
	t = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "tls://"))
	t = strings.TrimSuffix(t, "/")
	if _, _, err := net.SplitHostPort(t); err != nil {
		return net.JoinHostPort(t, "443")
	}
	return t
}

// ScanEndpoint connects to target (host:port), captures the presented chain and
// connection parameters, and reports whether the chain verifies against Roots.
func ScanEndpoint(ctx context.Context, target string, o EndpointOptions) ([]model.CertRecord, error) {
	target = NormalizeTarget(target)
	host, _, _ := net.SplitHostPort(target)
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: o.Timeout},
		Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // we inventory every chain, then verify separately below
			MinVersion:         tls.VersionTLS10,
		},
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, fmt.Errorf("%s presented no certificates", target)
	}

	trusted := false
	leaf := st.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if net.ParseIP(host) == nil {
		_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter, Roots: o.Roots})
		trusted = verr == nil
	} else {
		_, verr := leaf.Verify(x509.VerifyOptions{Intermediates: inter, Roots: o.Roots})
		trusted = verr == nil
	}

	out := make([]model.CertRecord, 0, len(st.PeerCertificates))
	for i, c := range st.PeerCertificates {
		r := FromX509(c, "endpoint", target, i)
		r.PubliclyTrusted = trusted
		if i == 0 {
			r.TLSVersion = tls.VersionName(st.Version)
			r.CipherSuite = tls.CipherSuiteName(st.CipherSuite)
		}
		out = append(out, r)
	}
	return out, nil
}
