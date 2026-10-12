package checks

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

// certificateNow can be replaced by tests
var certificateNow = time.Now

// CheckCertificate monitors X.509 certificates from files or the Windows certificate store
type CheckCertificate struct {
	definitions []*config.CertificateDefinition
}

// Name will be used in the response as check name
func (c *CheckCertificate) Name() string {
	return "certificates"
}

type resultCertificateInfo struct {
	Subject            string   `json:"subject"`              // e.g.: CN=example.com
	Issuer             string   `json:"issuer"`               // e.g.: CN=R11,O=Let's Encrypt,C=US
	SerialNumber       string   `json:"serial_number"`        // Hex encoded
	Thumbprint         string   `json:"thumbprint"`           // SHA-1 fingerprint as shown by Windows
	DNSNames           []string `json:"dns_names"`            // Subject alternative names
	NotBefore          int64    `json:"not_before"`           // Unix timestamp
	NotAfter           int64    `json:"not_after"`            // Unix timestamp
	ExpiresIn          int64    `json:"expires_in"`           // Seconds until the certificate expires (negative if expired)
	SignatureAlgorithm string   `json:"signature_algorithm"`  // e.g.: SHA256-RSA, SHA1-RSA, ECDSA-SHA384
	PublicKeyAlgorithm string   `json:"public_key_algorithm"` // e.g.: RSA, ECDSA, Ed25519, DSA
	PublicKeyBits      int      `json:"public_key_bits"`      // e.g.: 2048 for RSA or 256 for ECDSA P-256
	IsCA               bool     `json:"is_ca"`
	SelfSigned         bool     `json:"self_signed"`
}

type resultCertificate struct {
	resultCertificateInfo
	Source        string                   `json:"source"`         // File path or certificate store
	Chain         []*resultCertificateInfo `json:"chain"`          // Intermediate and root certificates (without the certificate itself)
	Verified      bool                     `json:"verified"`       // Chain is valid and trusted
	VerifySkipped bool                     `json:"verify_skipped"` // skip_verify is enabled
	VerifyError   string                   `json:"verify_error"`
	Hostname      string                   `json:"hostname"`
	HostnameMatch *bool                    `json:"hostname_match"` // null if no hostname is configured
}

type resultCertificates struct {
	Type         string               `json:"type"` // file or windows_store
	Certificates []*resultCertificate `json:"certificates"`
	Warnings     []string             `json:"warnings"` // Non fatal problems, e.g. a file without certificate
}

// certificateCandidate is a certificate which gets monitored together with the certificates of its chain from the same source
type certificateCandidate struct {
	certificate   *x509.Certificate
	intermediates []*x509.Certificate
	source        string
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckCertificate) Run(ctx context.Context) (interface{}, error) {
	result := make(map[string]interface{}, len(c.definitions))
	for _, definition := range c.definitions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if definition.ConfigError != "" {
			result[definition.Name] = map[string]string{"error": definition.ConfigError}
			continue
		}

		res, err := checkCertificateDefinition(ctx, definition)
		if err != nil {
			result[definition.Name] = map[string]string{"error": err.Error()}
			continue
		}
		result[definition.Name] = res
	}
	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckCertificate) Configure(cfg *config.Configuration) (bool, error) {
	c.definitions = cfg.CertificateConfiguration
	return len(c.definitions) > 0, nil
}

func checkCertificateDefinition(ctx context.Context, d *config.CertificateDefinition) (*resultCertificates, error) {
	var candidates []*certificateCandidate
	var warnings []string
	var err error

	switch d.Type {
	case config.CertificateTypeFile:
		candidates, warnings, err = loadCertificateFiles(d.Path, d.SplitBundle)
	case config.CertificateTypeWindowsStore:
		var certificates []*x509.Certificate
		certificates, warnings, err = readWindowsCertificateStore(d.Store)
		for _, certificate := range certificates {
			candidates = append(candidates, &certificateCandidate{certificate: certificate, source: d.Store})
		}
	default:
		err = fmt.Errorf("unknown certificate type: %s", d.Type)
	}
	if err != nil {
		return nil, err
	}

	candidates = filterCertificatesBySubject(candidates, d)
	if d.Type == config.CertificateTypeWindowsStore && !d.IncludeAll {
		candidates = newestCertificatePerSubject(candidates)
	}

	var roots *x509.CertPool
	if d.CAFile != "" && !d.SkipVerify {
		if roots, err = loadRootCertificates(d.CAFile); err != nil {
			return nil, err
		}
	}

	now := certificateNow()
	res := &resultCertificates{
		Type:         d.Type,
		Certificates: make([]*resultCertificate, 0, len(candidates)),
		Warnings:     warnings,
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res.Certificates = append(res.Certificates, analyzeCertificate(candidate, d, roots, now))
	}
	return res, nil
}

func analyzeCertificate(candidate *certificateCandidate, d *config.CertificateDefinition, roots *x509.CertPool, now time.Time) *resultCertificate {
	res := &resultCertificate{
		resultCertificateInfo: *certificateInfo(candidate.certificate, now),
		Source:                candidate.source,
		Hostname:              d.Hostname,
	}

	chain := candidate.intermediates
	if d.SkipVerify {
		res.VerifySkipped = true
	} else {
		intermediates := x509.NewCertPool()
		for _, intermediate := range candidate.intermediates {
			intermediates.AddCert(intermediate)
		}
		chains, err := candidate.certificate.Verify(x509.VerifyOptions{
			Intermediates: intermediates,
			Roots:         roots, // nil = trusted root certificates of the operating system
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			res.VerifyError = err.Error()
		} else {
			res.Verified = true
			if len(chains) > 0 && len(chains[0]) > 0 {
				// The verified chain also contains the root certificate
				chain = chains[0][1:]
			}
		}
	}

	res.Chain = make([]*resultCertificateInfo, 0, len(chain))
	for _, certificate := range chain {
		res.Chain = append(res.Chain, certificateInfo(certificate, now))
	}

	if d.Hostname != "" {
		match := candidate.certificate.VerifyHostname(d.Hostname) == nil
		res.HostnameMatch = &match
	}

	return res
}

func certificateInfo(certificate *x509.Certificate, now time.Time) *resultCertificateInfo {
	thumbprint := sha1.Sum(certificate.Raw)
	info := &resultCertificateInfo{
		Subject:            certificate.Subject.String(),
		Issuer:             certificate.Issuer.String(),
		SerialNumber:       strings.ToUpper(certificate.SerialNumber.Text(16)),
		Thumbprint:         strings.ToUpper(hex.EncodeToString(thumbprint[:])),
		DNSNames:           certificate.DNSNames,
		NotBefore:          certificate.NotBefore.Unix(),
		NotAfter:           certificate.NotAfter.Unix(),
		ExpiresIn:          int64(certificate.NotAfter.Sub(now).Seconds()),
		SignatureAlgorithm: certificate.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: certificate.PublicKeyAlgorithm.String(),
		IsCA:               certificate.IsCA,
		SelfSigned:         isSelfSigned(certificate),
	}
	if info.DNSNames == nil {
		info.DNSNames = []string{}
	}

	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyBits = key.Curve.Params().BitSize
	case ed25519.PublicKey:
		info.PublicKeyBits = 256
	}

	return info
}

func isSelfSigned(certificate *x509.Certificate) bool {
	if certificate.Subject.String() != certificate.Issuer.String() {
		return false
	}
	if len(certificate.AuthorityKeyId) > 0 && !bytes.Equal(certificate.AuthorityKeyId, certificate.SubjectKeyId) {
		return false
	}

	// CheckSignatureFrom can not be used, as it requires the CA flag
	err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature)
	var insecure x509.InsecureAlgorithmError
	// Signatures like SHA1-RSA can not be checked anymore, so we trust subject and key ids
	return err == nil || errors.As(err, &insecure)
}

// loadCertificateFiles reads all certificates from the files matching the glob pattern
func loadCertificateFiles(pattern string, splitBundle bool) ([]*certificateCandidate, []string, error) {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid path %s: %s", pattern, err)
	}
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf("no file matches %s", pattern)
	}

	var candidates []*certificateCandidate
	var warnings []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %s", path, err))
			continue
		}
		if info.IsDir() {
			continue
		}

		certificates, err := parseCertificateFile(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %s", path, err))
			continue
		}

		if splitBundle {
			for _, certificate := range certificates {
				candidates = append(candidates, &certificateCandidate{certificate: certificate, source: path})
			}
			continue
		}
		candidates = append(candidates, &certificateCandidate{
			certificate:   certificates[0],
			intermediates: certificates[1:],
			source:        path,
		})
	}

	if len(candidates) == 0 {
		if len(warnings) > 0 {
			return nil, nil, errors.New(strings.Join(warnings, "; "))
		}
		return nil, nil, fmt.Errorf("no certificate found in %s", pattern)
	}
	return candidates, warnings, nil
}

// parseCertificateFile parses PEM files (also with private keys) and DER encoded files
func parseCertificateFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certificates []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// e.g. a private key in a combined PEM file
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}

	if len(certificates) == 0 && !strings.Contains(string(data), "-----BEGIN") {
		// Not a PEM file, try DER encoding
		if certificates, err = x509.ParseCertificates(data); err != nil {
			return nil, fmt.Errorf("no certificate found")
		}
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	return certificates, nil
}

func loadRootCertificates(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read ca_file: %s", err)
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificate found in ca_file %s", path)
	}
	return roots, nil
}

func filterCertificatesBySubject(candidates []*certificateCandidate, d *config.CertificateDefinition) []*certificateCandidate {
	if d.SubjectRegexp == nil {
		return candidates
	}

	filtered := make([]*certificateCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		certificate := candidate.certificate
		if d.SubjectRegexp.MatchString(certificate.Subject.String()) {
			filtered = append(filtered, candidate)
			continue
		}
		for _, name := range certificate.DNSNames {
			if d.SubjectRegexp.MatchString(name) {
				filtered = append(filtered, candidate)
				break
			}
		}
	}
	return filtered
}

// newestCertificatePerSubject drops certificates which got replaced by a newer certificate with the same subject
func newestCertificatePerSubject(candidates []*certificateCandidate) []*certificateCandidate {
	newest := map[string]*certificateCandidate{}
	order := []string{}
	for _, candidate := range candidates {
		subject := candidate.certificate.Subject.String()
		current, ok := newest[subject]
		if !ok {
			order = append(order, subject)
		}
		if !ok || candidate.certificate.NotAfter.After(current.certificate.NotAfter) {
			newest[subject] = candidate
		}
	}

	result := make([]*certificateCandidate, 0, len(order))
	for _, subject := range order {
		result = append(result, newest[subject])
	}
	return result
}

// parseWindowsCertificateStore splits a store like LocalMachine\My into location and name
func parseWindowsCertificateStore(store string) (location string, name string, err error) {
	parts := strings.FieldsFunc(store, func(r rune) bool {
		return r == '\\' || r == '/'
	})
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid certificate store '%s', expected e.g. LocalMachine\\My", store)
	}

	switch strings.ToLower(parts[0]) {
	case "localmachine":
		location = "LocalMachine"
	case "currentuser":
		location = "CurrentUser"
	default:
		return "", "", fmt.Errorf("invalid certificate store location '%s', expected LocalMachine or CurrentUser", parts[0])
	}
	return location, parts[1], nil
}
