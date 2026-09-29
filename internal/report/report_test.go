package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/goriparthivamsi/certagility/internal/analyze"
	"github.com/goriparthivamsi/certagility/internal/model"
)

func sample() *model.Inventory {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	inv := &model.Inventory{GeneratedAt: now, ToolVersion: "test", Certificates: []model.CertRecord{{
		Source: "file", Location: "a.pem", CommonName: "svc", Subject: "CN=svc", Issuer: "CN=ca",
		KeyAlgorithm: "RSA", KeySize: 2048, SignatureAlgorithm: "SHA256-RSA", SignatureOID: "1.2.840.113549.1.1.11",
		NotBefore: now.AddDate(0, 0, -10), NotAfter: now.AddDate(0, 0, 80), SHA256Fingerprint: "AB", Serial: "01",
	}}}
	analyze.Inventory(inv, now, analyze.DefaultOptions())
	return inv
}

func TestCBOMShape(t *testing.T) {
	var buf bytes.Buffer
	if err := CBOM(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.6" {
		t.Fatalf("bad header: %v", doc)
	}
	comps := doc["components"].([]any)
	if len(comps) != 3 { // key algorithm, signature algorithm, certificate
		t.Fatalf("want 3 components, got %d", len(comps))
	}
	if !strings.Contains(buf.String(), `"assetType": "certificate"`) {
		t.Error("certificate asset missing")
	}
}

func TestPrometheus(t *testing.T) {
	var buf bytes.Buffer
	if err := Prometheus(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"certagility_cert_not_after_timestamp_seconds{",
		`certagility_cert_quantum_vulnerable{source="file"`,
		`certagility_findings{severity="low",code="QUANTUM_VULNERABLE"} 1`,
		"certagility_scan_errors 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "1 certificates") {
		t.Error(buf.String())
	}
}
