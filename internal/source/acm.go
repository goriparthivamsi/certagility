package source

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/goriparthivamsi/certagility/internal/model"
)

// ACMOptions selects the AWS profile and regions to scan.
type ACMOptions struct {
	Profile string
	Regions []string // empty = region from the default config
}

// ScanACM inventories issued certificates in AWS Certificate Manager. It uses
// read-only calls: acm:ListCertificates and acm:GetCertificate.
func ScanACM(ctx context.Context, o ACMOptions) ([]model.CertRecord, []model.ScanError, error) {
	var loadOpts []func(*config.LoadOptions) error
	if o.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(o.Profile))
	}
	base, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("aws config: %w", err)
	}
	regions := o.Regions
	if len(regions) == 0 {
		regions = []string{base.Region}
	}
	allKeyTypes := []acmtypes.KeyAlgorithm{}
	for _, k := range acmtypes.KeyAlgorithm("").Values() {
		allKeyTypes = append(allKeyTypes, k)
	}
	var recs []model.CertRecord
	var errs []model.ScanError
	for _, region := range regions {
		cfg := base.Copy()
		cfg.Region = region
		cli := acm.NewFromConfig(cfg)
		p := acm.NewListCertificatesPaginator(cli, &acm.ListCertificatesInput{
			CertificateStatuses: []acmtypes.CertificateStatus{acmtypes.CertificateStatusIssued},
			Includes:            &acmtypes.Filters{KeyTypes: allKeyTypes},
		})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				errs = append(errs, model.ScanError{Source: "acm", Location: region, Error: err.Error()})
				break
			}
			for _, s := range page.CertificateSummaryList {
				arn := aws.ToString(s.CertificateArn)
				out, err := cli.GetCertificate(ctx, &acm.GetCertificateInput{CertificateArn: s.CertificateArn})
				if err != nil {
					errs = append(errs, model.ScanError{Source: "acm", Location: arn, Error: err.Error()})
					continue
				}
				certs, err := ParsePEMBundle([]byte(aws.ToString(out.Certificate) + "\n" + aws.ToString(out.CertificateChain)))
				if err != nil {
					errs = append(errs, model.ScanError{Source: "acm", Location: arn, Error: err.Error()})
				}
				for i, c := range certs {
					r := FromX509(c, "acm", arn, i)
					// Amazon-issued ACM certificates are publicly trusted; imported/private ones may not be.
					r.PubliclyTrusted = s.Type == acmtypes.CertificateTypeAmazonIssued
					recs = append(recs, r)
				}
			}
		}
	}
	return recs, errs, nil
}
