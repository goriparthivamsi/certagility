// Command certagility builds a cryptographic inventory of X.509 certificates across
// TLS endpoints, files, Kubernetes and AWS ACM, and reports lifecycle, 47-day
// readiness and post-quantum readiness findings.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/goriparthivamsi/certagility/internal/analyze"
	"github.com/goriparthivamsi/certagility/internal/model"
	"github.com/goriparthivamsi/certagility/internal/report"
	"github.com/goriparthivamsi/certagility/internal/scan"
)

var version = "dev" // set by -ldflags at release time

type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRoot().ExecuteContext(ctx); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "certagility",
		Short:         "Cryptographic inventory and certificate-lifecycle readiness scanner",
		Long:          "certagility discovers X.509 certificates across TLS endpoints, files, Kubernetes and AWS ACM,\nand reports expiry, 47-day lifetime readiness (CA/B Forum SC-081) and post-quantum readiness.\nOutputs: table, JSON, CycloneDX 1.6 CBOM, Prometheus.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScan(), newServe(), &cobra.Command{
		Use: "version", Short: "Print the version",
		Run: func(*cobra.Command, []string) { fmt.Println(version) },
	})
	return root
}

func bindSources(cmd *cobra.Command, c *scan.Config) {
	f := cmd.Flags()
	f.StringSliceVarP(&c.Endpoints, "endpoint", "e", nil, "TLS endpoint host[:port] (repeatable, default port 443)")
	f.StringVar(&c.EndpointsFile, "endpoints-file", "", "file with one host[:port] per line")
	f.StringSliceVarP(&c.Paths, "path", "p", nil, "file or directory of PEM/DER certificates (repeatable)")
	f.BoolVar(&c.Kubernetes, "kubernetes", false, "scan kubernetes.io/tls Secrets")
	f.StringVar(&c.K8s.Kubeconfig, "kubeconfig", "", "path to kubeconfig (default: standard loading rules)")
	f.StringVar(&c.K8s.Context, "kube-context", "", "kubeconfig context")
	f.StringVarP(&c.K8s.Namespace, "namespace", "n", "", "namespace (default: all)")
	f.BoolVar(&c.ACM, "acm", false, "scan AWS Certificate Manager (read-only)")
	f.StringVar(&c.AWS.Profile, "aws-profile", "", "AWS shared config profile")
	f.StringSliceVar(&c.AWS.Regions, "aws-region", nil, "AWS region (repeatable, default: configured region)")
	f.DurationVar(&c.Timeout, "timeout", 10*time.Second, "per-endpoint timeout")
	f.IntVar(&c.Concurrency, "concurrency", 16, "parallel endpoint connections")
	f.IntVar(&c.Analyze.WarnDays, "warn-days", 30, "days before expiry to raise a high finding")
	f.IntVar(&c.Analyze.CritDays, "crit-days", 7, "days before expiry to raise a critical finding")
}

func hasSource(c scan.Config) bool {
	return len(c.Endpoints) > 0 || c.EndpointsFile != "" || len(c.Paths) > 0 || c.Kubernetes || c.ACM
}

func newScan() *cobra.Command {
	c := scan.Config{Analyze: analyze.DefaultOptions()}
	var format, outFile, failOn string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan sources once and print a report",
		Example: `  certagility scan -e example.com -e api.internal:8443
  certagility scan --kubernetes --output cbom --out-file cbom.json
  certagility scan --acm --aws-region us-east-1 --aws-region us-west-2 --fail-on high`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !hasSource(c) {
				return errors.New("no sources given: use --endpoint, --endpoints-file, --path, --kubernetes or --acm")
			}
			c.Version = version
			inv, err := scan.Run(cmd.Context(), c)
			if err != nil {
				return err
			}
			var w io.Writer = os.Stdout
			if outFile != "" {
				f, err := os.Create(outFile)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			if err := report.Write(w, inv, format); err != nil {
				return err
			}
			if failOn != "" && failOn != "none" {
				if model.SeverityRank(failOn) == 0 {
					return fmt.Errorf("invalid --fail-on %q", failOn)
				}
				for _, r := range inv.Certificates {
					if model.SeverityRank(r.MaxSeverity()) >= model.SeverityRank(failOn) {
						return exitError{code: 2}
					}
				}
			}
			return nil
		},
	}
	bindSources(cmd, &c)
	cmd.Flags().StringVarP(&format, "output", "o", "table", "output format: "+strings.Join(report.Formats, "|"))
	cmd.Flags().StringVar(&outFile, "out-file", "", "write the report to a file instead of stdout")
	cmd.Flags().StringVar(&failOn, "fail-on", "none", "exit with code 2 if any finding is at or above: info|low|medium|high|critical")
	return cmd
}

func newServe() *cobra.Command {
	c := scan.Config{Analyze: analyze.DefaultOptions()}
	var listen string
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run as a Prometheus exporter, rescanning on an interval",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !hasSource(c) {
				return errors.New("no sources given")
			}
			c.Version = version
			var mu sync.RWMutex
			var latest *model.Inventory
			rescan := func() {
				inv, err := scan.Run(cmd.Context(), c)
				if err != nil {
					log.Printf("scan failed: %v", err)
					return
				}
				mu.Lock()
				latest = inv
				mu.Unlock()
				log.Printf("scan complete: %d certificates, %d errors", len(inv.Certificates), len(inv.Errors))
			}
			rescan()
			go func() {
				t := time.NewTicker(interval)
				defer t.Stop()
				for {
					select {
					case <-cmd.Context().Done():
						return
					case <-t.C:
						rescan()
					}
				}
			}()
			mux := http.NewServeMux()
			mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
				mu.RLock()
				defer mu.RUnlock()
				w.Header().Set("Content-Type", "text/plain; version=0.0.4")
				if latest != nil {
					_ = report.Prometheus(w, latest)
				}
			})
			mux.HandleFunc("/cbom", func(w http.ResponseWriter, _ *http.Request) {
				mu.RLock()
				defer mu.RUnlock()
				w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
				if latest != nil {
					_ = report.CBOM(w, latest)
				}
			})
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
			srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			go func() {
				<-cmd.Context().Done()
				sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(sctx)
			}()
			log.Printf("listening on %s (/metrics, /cbom, /healthz)", listen)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}
	bindSources(cmd, &c)
	cmd.Flags().StringVar(&listen, "listen", ":9115", "listen address")
	cmd.Flags().DurationVar(&interval, "interval", 15*time.Minute, "rescan interval")
	return cmd
}
