package source

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/goriparthivamsi/certagility/internal/model"
)

var certExts = map[string]bool{".pem": true, ".crt": true, ".cer": true, ".cert": true, ".der": true}

// ScanPath walks a file or directory and inventories every certificate found in
// files with a certificate extension (.pem .crt .cer .cert .der).
func ScanPath(root string) ([]model.CertRecord, []model.ScanError) {
	var recs []model.CertRecord
	var errs []model.ScanError
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, model.ScanError{Source: "file", Location: p, Error: err.Error()})
			return nil
		}
		if d.IsDir() || !certExts[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, model.ScanError{Source: "file", Location: p, Error: err.Error()})
			return nil
		}
		certs, err := ParsePEMBundle(data)
		if err != nil {
			errs = append(errs, model.ScanError{Source: "file", Location: p, Error: err.Error()})
		}
		for i, c := range certs {
			recs = append(recs, FromX509(c, "file", p, i))
		}
		return nil
	})
	return recs, errs
}
