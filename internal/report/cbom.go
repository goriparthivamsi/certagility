package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/goriparthivamsi/certagility/internal/model"
)

// CycloneDX 1.6 CBOM (Cryptography Bill of Materials) structures — only the subset we emit.
type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber,omitempty"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     cdxTools  `json:"tools"`
	Props     []cdxProp `json:"properties,omitempty"`
}

type cdxTools struct {
	Components []cdxToolComponent `json:"components"`
}

type cdxToolComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	Type             string         `json:"type"`
	BOMRef           string         `json:"bom-ref"`
	Name             string         `json:"name"`
	CryptoProperties *cdxCryptoProp `json:"cryptoProperties,omitempty"`
	Properties       []cdxProp      `json:"properties,omitempty"`
}

type cdxCryptoProp struct {
	AssetType             string            `json:"assetType"`
	AlgorithmProperties   *cdxAlgProps      `json:"algorithmProperties,omitempty"`
	CertificateProperties *cdxCertProps     `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterial *cdxRelatedCrypto `json:"relatedCryptoMaterialProperties,omitempty"`
	OID                   string            `json:"oid,omitempty"`
}

type cdxAlgProps struct {
	Primitive                string   `json:"primitive,omitempty"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Curve                    string   `json:"curve,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   int      `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel int      `json:"nistQuantumSecurityLevel"`
}

type cdxCertProps struct {
	SubjectName           string `json:"subjectName"`
	IssuerName            string `json:"issuerName"`
	NotValidBefore        string `json:"notValidBefore"`
	NotValidAfter         string `json:"notValidAfter"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat"`
}

type cdxRelatedCrypto struct {
	Type         string `json:"type"`
	AlgorithmRef string `json:"algorithmRef,omitempty"`
	Size         int    `json:"size,omitempty"`
}

// quantumLevel maps an algorithm to its NIST PQC security category (0 = broken by CRQC).
func quantumLevel(alg string) int {
	switch {
	case strings.HasPrefix(alg, "ML-DSA-44"), strings.Contains(alg, "128"):
		return 2
	case strings.HasPrefix(alg, "ML-DSA-65"), strings.Contains(alg, "192"):
		return 3
	case strings.HasPrefix(alg, "ML-DSA-87"), strings.Contains(alg, "256"):
		return 5
	}
	return 0
}

func classicalLevel(alg string, size int) int {
	switch alg {
	case "RSA":
		switch {
		case size >= 15360:
			return 256
		case size >= 7680:
			return 192
		case size >= 3072:
			return 128
		case size >= 2048:
			return 112
		default:
			return 80
		}
	case "ECDSA":
		return size / 2
	case "Ed25519":
		return 128
	}
	return 0
}

// CBOM writes a CycloneDX 1.6 Cryptography Bill of Materials for inv.
func CBOM(w io.Writer, inv *model.Inventory) error {
	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: inv.GeneratedAt.UTC().Format(time.RFC3339),
			Tools:     cdxTools{Components: []cdxToolComponent{{Type: "application", Name: "certagility", Version: inv.ToolVersion}}},
		},
	}
	seenAlg := map[string]bool{}
	seenCert := map[string]bool{}
	addAlg := func(ref string, c cdxComponent) {
		if !seenAlg[ref] {
			seenAlg[ref] = true
			bom.Components = append(bom.Components, c)
		}
	}
	for _, c := range inv.Certificates {
		keyRef := "crypto/algorithm/" + strings.ToLower(fmt.Sprintf("%s-%d", c.KeyAlgorithm, c.KeySize))
		addAlg(keyRef, cdxComponent{
			Type: "cryptographic-asset", BOMRef: keyRef, Name: fmt.Sprintf("%s-%d", c.KeyAlgorithm, c.KeySize),
			CryptoProperties: &cdxCryptoProp{AssetType: "algorithm", AlgorithmProperties: &cdxAlgProps{
				Primitive: "signature", ParameterSetIdentifier: fmt.Sprint(c.KeySize), Curve: c.Curve,
				CryptoFunctions:          []string{"sign", "verify"},
				ClassicalSecurityLevel:   classicalLevel(c.KeyAlgorithm, c.KeySize),
				NISTQuantumSecurityLevel: quantumLevel(c.KeyAlgorithm),
			}},
		})
		sigRef := "crypto/algorithm/sig/" + strings.ToLower(c.SignatureAlgorithm)
		addAlg(sigRef, cdxComponent{
			Type: "cryptographic-asset", BOMRef: sigRef, Name: c.SignatureAlgorithm,
			CryptoProperties: &cdxCryptoProp{AssetType: "algorithm", OID: c.SignatureOID, AlgorithmProperties: &cdxAlgProps{
				Primitive: "signature", CryptoFunctions: []string{"sign", "verify"},
				NISTQuantumSecurityLevel: quantumLevel(c.SignatureAlgorithm),
			}},
		})
		certRef := "crypto/certificate/" + strings.ToLower(c.SHA256Fingerprint)
		if seenCert[certRef] {
			continue
		}
		seenCert[certRef] = true
		props := []cdxProp{
			{Name: "certagility:source", Value: c.Source},
			{Name: "certagility:location", Value: c.Location},
			{Name: "certagility:daysRemaining", Value: fmt.Sprint(c.DaysRemaining)},
			{Name: "certagility:validityDays", Value: fmt.Sprint(c.ValidityDays)},
			{Name: "certagility:quantumVulnerable", Value: fmt.Sprint(c.QuantumVulnerable)},
			{Name: "certagility:serial", Value: c.Serial},
		}
		for _, f := range c.Findings {
			props = append(props, cdxProp{Name: "certagility:finding", Value: f.Severity + ":" + f.Code})
		}
		name := c.CommonName
		if name == "" {
			name = c.Subject
		}
		bom.Components = append(bom.Components, cdxComponent{
			Type: "cryptographic-asset", BOMRef: certRef, Name: name,
			CryptoProperties: &cdxCryptoProp{AssetType: "certificate", CertificateProperties: &cdxCertProps{
				SubjectName: c.Subject, IssuerName: c.Issuer,
				NotValidBefore: c.NotBefore.Format(time.RFC3339), NotValidAfter: c.NotAfter.Format(time.RFC3339),
				SignatureAlgorithmRef: sigRef, SubjectPublicKeyRef: keyRef, CertificateFormat: "X.509",
			}},
			Properties: props,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}
