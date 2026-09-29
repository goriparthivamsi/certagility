// Package scan orchestrates all configured sources into a single analyzed inventory.
package scan

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/goriparthivamsi/certagility/internal/analyze"
	"github.com/goriparthivamsi/certagility/internal/model"
	"github.com/goriparthivamsi/certagility/internal/source"
)

// Config describes what to scan.
type Config struct {
	Endpoints     []string
	EndpointsFile string
	Paths         []string
	Kubernetes    bool
	K8s           source.KubernetesOptions
	ACM           bool
	AWS           source.ACMOptions
	Timeout       time.Duration
	Concurrency   int
	Analyze       analyze.Options
	Version       string
}

// Run executes the scan and returns an analyzed inventory.
func Run(ctx context.Context, c Config) (*model.Inventory, error) {
	inv := &model.Inventory{GeneratedAt: time.Now().UTC(), ToolVersion: c.Version}
	var mu sync.Mutex
	add := func(recs []model.CertRecord, errs []model.ScanError) {
		mu.Lock()
		defer mu.Unlock()
		inv.Certificates = append(inv.Certificates, recs...)
		inv.Errors = append(inv.Errors, errs...)
	}

	targets := append([]string(nil), c.Endpoints...)
	if c.EndpointsFile != "" {
		lines, err := readLines(c.EndpointsFile)
		if err != nil {
			return nil, err
		}
		targets = append(targets, lines...)
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 16
	}
	sem := make(chan struct{}, c.Concurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			recs, err := source.ScanEndpoint(ctx, t, source.EndpointOptions{Timeout: c.Timeout})
			if err != nil {
				add(nil, []model.ScanError{{Source: "endpoint", Location: source.NormalizeTarget(t), Error: err.Error()}})
				return
			}
			add(recs, nil)
		}(t)
	}
	wg.Wait()

	for _, p := range c.Paths {
		add(source.ScanPath(p))
	}
	if c.Kubernetes {
		recs, errs, err := source.ScanKubernetes(ctx, c.K8s)
		if err != nil {
			errs = append(errs, model.ScanError{Source: "kubernetes", Location: c.K8s.Context, Error: err.Error()})
		}
		add(recs, errs)
	}
	if c.ACM {
		recs, errs, err := source.ScanACM(ctx, c.AWS)
		if err != nil {
			errs = append(errs, model.ScanError{Source: "acm", Location: strings.Join(c.AWS.Regions, ","), Error: err.Error()})
		}
		add(recs, errs)
	}
	analyze.Inventory(inv, time.Now().UTC(), c.Analyze)
	return inv, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, s.Err()
}
