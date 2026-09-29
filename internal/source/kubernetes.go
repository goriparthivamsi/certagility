package source

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/goriparthivamsi/certagility/internal/model"
)

// KubernetesOptions selects the cluster and namespace to scan.
type KubernetesOptions struct {
	Kubeconfig string // empty = default loading rules / in-cluster
	Context    string
	Namespace  string // empty = all namespaces
}

// ScanKubernetes inventories certificates stored in kubernetes.io/tls Secrets
// (tls.crt and, when present, ca.crt). Private keys are never read into the report.
func ScanKubernetes(ctx context.Context, o KubernetesOptions) ([]model.CertRecord, []model.ScanError, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if o.Kubeconfig != "" {
		rules.ExplicitPath = o.Kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: o.Context}).ClientConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	var recs []model.CertRecord
	var errs []model.ScanError
	cont := ""
	for {
		list, err := cs.CoreV1().Secrets(o.Namespace).List(ctx, metav1.ListOptions{
			FieldSelector: "type=kubernetes.io/tls", Limit: 500, Continue: cont,
		})
		if err != nil {
			return recs, errs, fmt.Errorf("list secrets: %w", err)
		}
		for _, s := range list.Items {
			for _, key := range []string{"tls.crt", "ca.crt"} {
				data, ok := s.Data[key]
				if !ok || len(data) == 0 {
					continue
				}
				loc := fmt.Sprintf("%s/%s[%s]", s.Namespace, s.Name, key)
				certs, err := ParsePEMBundle(data)
				if err != nil {
					errs = append(errs, model.ScanError{Source: "kubernetes", Location: loc, Error: err.Error()})
				}
				for i, c := range certs {
					pos := i
					if key == "ca.crt" {
						pos = i + 1 // CA material is never the leaf
					}
					recs = append(recs, FromX509(c, "kubernetes", loc, pos))
				}
			}
		}
		if list.Continue == "" {
			break
		}
		cont = list.Continue
	}
	return recs, errs, nil
}
