package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/goriparthivamsi/certagility/internal/model"
)

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

// Prometheus writes the inventory in the Prometheus text exposition format.
func Prometheus(w io.Writer, inv *model.Inventory) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("# HELP certagility_cert_not_after_timestamp_seconds Certificate expiry time (Unix seconds).\n")
	p("# TYPE certagility_cert_not_after_timestamp_seconds gauge\n")
	for _, c := range inv.Certificates {
		p("certagility_cert_not_after_timestamp_seconds{%s} %d\n", labels(c), c.NotAfter.Unix())
	}
	p("# HELP certagility_cert_validity_days Total certificate lifetime in days.\n")
	p("# TYPE certagility_cert_validity_days gauge\n")
	for _, c := range inv.Certificates {
		p("certagility_cert_validity_days{%s} %d\n", labels(c), c.ValidityDays)
	}
	p("# HELP certagility_cert_quantum_vulnerable 1 if the certificate key is vulnerable to a quantum computer.\n")
	p("# TYPE certagility_cert_quantum_vulnerable gauge\n")
	for _, c := range inv.Certificates {
		v := 0
		if c.QuantumVulnerable {
			v = 1
		}
		p("certagility_cert_quantum_vulnerable{%s,key_algorithm=\"%s\"} %d\n", labels(c), esc(c.KeyAlgorithm), v)
	}
	counts := map[string]int{}
	for _, c := range inv.Certificates {
		for _, f := range c.Findings {
			counts[f.Severity+"|"+f.Code]++
		}
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	p("# HELP certagility_findings Number of findings by severity and code.\n")
	p("# TYPE certagility_findings gauge\n")
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 2)
		p("certagility_findings{severity=\"%s\",code=\"%s\"} %d\n", parts[0], parts[1], counts[k])
	}
	p("# HELP certagility_scan_errors Number of locations that could not be scanned.\n")
	p("# TYPE certagility_scan_errors gauge\n")
	p("certagility_scan_errors %d\n", len(inv.Errors))
	return nil
}

func labels(c model.CertRecord) string {
	return fmt.Sprintf(`source="%s",location="%s",chain_position="%d",common_name="%s",serial="%s"`,
		esc(c.Source), esc(c.Location), c.ChainPos, esc(c.CommonName), esc(c.Serial))
}
