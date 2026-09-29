// Package report renders an inventory as a table, JSON, CycloneDX CBOM or Prometheus metrics.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/goriparthivamsi/certagility/internal/model"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json", "cbom", "prometheus"}

// Write renders inv in the named format.
func Write(w io.Writer, inv *model.Inventory, format string) error {
	switch format {
	case "table", "":
		return Table(w, inv)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(inv)
	case "cbom":
		return CBOM(w, inv)
	case "prometheus":
		return Prometheus(w, inv)
	}
	return fmt.Errorf("unknown format %q (supported: %s)", format, strings.Join(Formats, ", "))
}

// Table writes a human-readable summary, sorted by days remaining.
func Table(w io.Writer, inv *model.Inventory) error {
	certs := append([]model.CertRecord(nil), inv.Certificates...)
	sort.SliceStable(certs, func(i, j int) bool { return certs[i].DaysRemaining < certs[j].DaysRemaining })
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tDAYS\tSOURCE\tLOCATION\tSUBJECT CN\tKEY\tVALIDITY\tPQ-SAFE\tFINDINGS")
	for _, c := range certs {
		key := c.KeyAlgorithm
		if c.KeySize > 0 {
			key = fmt.Sprintf("%s-%d", c.KeyAlgorithm, c.KeySize)
		}
		pq := "yes"
		if c.QuantumVulnerable {
			pq = "no"
		}
		var codes []string
		for _, f := range c.Findings {
			codes = append(codes, f.Code)
		}
		cn := c.CommonName
		if cn == "" {
			cn = "-"
		}
		sev := c.MaxSeverity()
		if sev == "" {
			sev = "ok"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%dd\t%s\t%s\n",
			strings.ToUpper(sev), c.DaysRemaining, c.Source, c.Location, truncate(cn, 40), key, c.ValidityDays, pq, strings.Join(codes, ","))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	s := Summarize(inv)
	fmt.Fprintf(w, "\n%d certificates | %d expired | %d expiring <30d | %d quantum-vulnerable | %d exceed 47-day lifetime | %d scan errors\n",
		s.Total, s.Expired, s.Expiring30, s.QuantumVulnerable, s.Over47Days, len(inv.Errors))
	for _, e := range inv.Errors {
		fmt.Fprintf(w, "error: %s %s: %s\n", e.Source, e.Location, e.Error)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Summary aggregates key readiness indicators.
type Summary struct {
	Total, Expired, Expiring30, QuantumVulnerable, Over47Days int
}

// Summarize computes the readiness summary for inv.
func Summarize(inv *model.Inventory) Summary {
	var s Summary
	for _, c := range inv.Certificates {
		s.Total++
		if c.DaysRemaining < 0 {
			s.Expired++
		} else if c.DaysRemaining < 30 {
			s.Expiring30++
		}
		if c.QuantumVulnerable {
			s.QuantumVulnerable++
		}
		if !c.IsCA && c.ChainPos == 0 && c.ValidityDays > 47 {
			s.Over47Days++
		}
	}
	return s
}
