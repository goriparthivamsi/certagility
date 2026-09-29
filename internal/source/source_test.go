package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goriparthivamsi/certagility/internal/testutil"
)

func TestScanPathBundle(t *testing.T) {
	ca := testutil.New(t, testutil.Options{CN: "Test Root", IsCA: true, RSABits: 2048})
	leaf := testutil.New(t, testutil.Options{CN: "svc.example.test", Parent: ca})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bundle.pem"), append(leaf.PEM, ca.PEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o600)
	recs, errs := ScanPath(dir)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 certs, got %d", len(recs))
	}
	if recs[0].CommonName != "svc.example.test" || recs[0].KeyAlgorithm != "ECDSA" || recs[0].Curve != "P-256" {
		t.Errorf("leaf parsed wrong: %+v", recs[0])
	}
	if recs[1].KeyAlgorithm != "RSA" || recs[1].KeySize != 2048 || !recs[1].IsCA || !recs[1].SelfSigned {
		t.Errorf("ca parsed wrong: %+v", recs[1])
	}
	if recs[0].SignatureOID != "1.2.840.113549.1.1.11" {
		t.Errorf("signature OID = %s", recs[0].SignatureOID)
	}
}

func TestScanEndpoint(t *testing.T) {
	ca := testutil.New(t, testutil.Options{CN: "Test Root", IsCA: true})
	leaf := testutil.New(t, testutil.Options{CN: "localhost", DNSNames: []string{"localhost"}, Parent: ca})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.X509.Raw, ca.X509.Raw}, PrivateKey: leaf.Key}},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(ca.X509)

	recs, err := ScanEndpoint(context.Background(), "localhost:"+port, EndpointOptions{Timeout: 5 * time.Second, Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 certs in chain, got %d", len(recs))
	}
	if !recs[0].PubliclyTrusted || recs[0].TLSVersion != "TLS 1.2" || recs[0].CipherSuite == "" {
		t.Errorf("leaf connection details wrong: %+v", recs[0])
	}
	recs, err = ScanEndpoint(context.Background(), "localhost:"+port, EndpointOptions{Timeout: 5 * time.Second, Roots: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].PubliclyTrusted {
		t.Error("chain must not verify against an empty root pool")
	}
}

func TestNormalizeTarget(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":          "example.com:443",
		"https://example.com/": "example.com:443",
		"10.0.0.1:8443":        "10.0.0.1:8443",
		"[::1]:9443":           "[::1]:9443",
	} {
		if got := NormalizeTarget(in); got != want {
			t.Errorf("NormalizeTarget(%q)=%q want %q", in, got, want)
		}
	}
}
