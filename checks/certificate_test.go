package checks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

type testCertificate struct {
	certificate *x509.Certificate
	key         crypto.Signer
}

func createTestCertificate(t *testing.T, template *x509.Certificate, parent *testCertificate, key crypto.Signer) *testCertificate {
	t.Helper()
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(time.Now().UnixNano())
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}

	parentCertificate, parentKey := template, key
	if parent != nil {
		parentCertificate, parentKey = parent.certificate, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parentCertificate, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCertificate{certificate: certificate, key: key}
}

func caTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
	}
}

func writePEM(t *testing.T, path string, blocks ...*pem.Block) {
	t.Helper()
	var data []byte
	for _, block := range blocks {
		data = append(data, pem.EncodeToMemory(block)...)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func certBlock(c *testCertificate) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE", Bytes: c.certificate.Raw}
}

// testPKI creates a root CA, an intermediate CA and a leaf certificate for www.example.com
type testPKI struct {
	dir          string
	root         *testCertificate
	intermediate *testCertificate
	leaf         *testCertificate
	fullchain    string
	caFile       string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{dir: t.TempDir()}
	p.root = createTestCertificate(t, caTemplate("Test Root CA"), nil, nil)
	p.intermediate = createTestCertificate(t, caTemplate("Test Intermediate CA"), p.root, nil)
	p.leaf = createTestCertificate(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "www.example.com"},
		DNSNames:    []string{"www.example.com", "example.com"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotAfter:    time.Now().Add(20 * 24 * time.Hour),
	}, p.intermediate, nil)

	p.fullchain = filepath.Join(p.dir, "fullchain.pem")
	writePEM(t, p.fullchain, certBlock(p.leaf), certBlock(p.intermediate))
	p.caFile = filepath.Join(p.dir, "ca.pem")
	writePEM(t, p.caFile, certBlock(p.root))
	return p
}

func runCertificateCheck(t *testing.T, definition *config.CertificateDefinition) interface{} {
	t.Helper()
	if definition.Name == "" {
		definition.Name = "test"
	}
	c := &CheckCertificate{}
	if enabled, _ := c.Configure(&config.Configuration{CertificateConfiguration: []*config.CertificateDefinition{definition}}); !enabled {
		t.Fatal("check should be enabled")
	}
	r, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	return r.(map[string]interface{})[definition.Name]
}

func runCertificateCheckOK(t *testing.T, definition *config.CertificateDefinition) *resultCertificates {
	t.Helper()
	res, ok := runCertificateCheck(t, definition).(*resultCertificates)
	if !ok {
		t.Fatalf("unexpected result: %+v", runCertificateCheck(t, definition))
	}
	return res
}

func TestCheckCertificateChainAndHostname(t *testing.T) {
	p := newTestPKI(t)

	res := runCertificateCheckOK(t, &config.CertificateDefinition{
		Type:     config.CertificateTypeFile,
		Path:     p.fullchain,
		CAFile:   p.caFile,
		Hostname: "example.com",
	})
	if len(res.Certificates) != 1 {
		t.Fatalf("expected 1 certificate: %+v", res)
	}
	certificate := res.Certificates[0]
	if !certificate.Verified || certificate.VerifyError != "" {
		t.Errorf("certificate should be verified: %s", certificate.VerifyError)
	}
	if certificate.HostnameMatch == nil || !*certificate.HostnameMatch {
		t.Error("hostname should match")
	}
	if certificate.Subject != "CN=www.example.com" || certificate.Source != p.fullchain || certificate.IsCA || certificate.SelfSigned {
		t.Errorf("unexpected certificate: %+v", certificate)
	}
	if certificate.PublicKeyAlgorithm != "ECDSA" || certificate.PublicKeyBits != 256 || certificate.SignatureAlgorithm != "ECDSA-SHA256" {
		t.Errorf("unexpected key information: %+v", certificate.resultCertificateInfo)
	}
	days := certificate.ExpiresIn / 86400
	if days < 19 || days > 20 {
		t.Errorf("unexpected expires_in: %d", certificate.ExpiresIn)
	}
	if len(certificate.Thumbprint) != 40 {
		t.Errorf("unexpected thumbprint: %s", certificate.Thumbprint)
	}

	// Verified chain contains the intermediate and the root certificate
	if len(certificate.Chain) != 2 || certificate.Chain[0].Subject != "CN=Test Intermediate CA" || certificate.Chain[1].Subject != "CN=Test Root CA" {
		t.Fatalf("unexpected chain: %+v", certificate.Chain)
	}
	if !certificate.Chain[1].SelfSigned || !certificate.Chain[1].IsCA {
		t.Errorf("root should be a self signed CA: %+v", certificate.Chain[1])
	}

	// Wrong hostname
	res = runCertificateCheckOK(t, &config.CertificateDefinition{
		Type: config.CertificateTypeFile, Path: p.fullchain, CAFile: p.caFile, Hostname: "mail.example.com",
	})
	if match := res.Certificates[0].HostnameMatch; match == nil || *match {
		t.Error("hostname should not match")
	}
}

func TestCheckCertificateVerifyErrors(t *testing.T) {
	p := newTestPKI(t)

	// Root CA is not trusted by the operating system
	res := runCertificateCheckOK(t, &config.CertificateDefinition{Type: config.CertificateTypeFile, Path: p.fullchain})
	certificate := res.Certificates[0]
	if certificate.Verified || !strings.Contains(certificate.VerifyError, "unknown authority") {
		t.Errorf("expected unknown authority error: %+v", certificate)
	}
	if certificate.HostnameMatch != nil {
		t.Error("hostname_match must be null without hostname")
	}
	// Without verification, the chain contains the certificates of the file
	if len(certificate.Chain) != 1 || certificate.Chain[0].Subject != "CN=Test Intermediate CA" {
		t.Errorf("unexpected chain: %+v", certificate.Chain)
	}

	// Missing intermediate certificate
	leafOnly := filepath.Join(p.dir, "cert.pem")
	writePEM(t, leafOnly, certBlock(p.leaf))
	res = runCertificateCheckOK(t, &config.CertificateDefinition{Type: config.CertificateTypeFile, Path: leafOnly, CAFile: p.caFile})
	if res.Certificates[0].Verified {
		t.Error("certificate without intermediate must not be verified")
	}

	// skip_verify
	res = runCertificateCheckOK(t, &config.CertificateDefinition{Type: config.CertificateTypeFile, Path: p.fullchain, SkipVerify: true})
	if certificate = res.Certificates[0]; !certificate.VerifySkipped || certificate.Verified || certificate.VerifyError != "" {
		t.Errorf("unexpected verification result: %+v", certificate)
	}
}

func TestCheckCertificateExpiredAndWeak(t *testing.T) {
	dir := t.TempDir()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	expired := createTestCertificate(t, &x509.Certificate{
		Subject:            pkix.Name{CommonName: "expired.example.com"},
		NotBefore:          time.Now().Add(-48 * time.Hour),
		NotAfter:           time.Now().Add(-24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, nil, rsaKey)
	path := filepath.Join(dir, "expired.crt")
	// DER encoded file
	if err := os.WriteFile(path, expired.certificate.Raw, 0600); err != nil {
		t.Fatal(err)
	}

	res := runCertificateCheckOK(t, &config.CertificateDefinition{Type: config.CertificateTypeFile, Path: path})
	certificate := res.Certificates[0]
	if certificate.ExpiresIn > -86000 {
		t.Errorf("certificate should be expired: %d", certificate.ExpiresIn)
	}
	if certificate.PublicKeyAlgorithm != "RSA" || certificate.PublicKeyBits != 1024 || !certificate.SelfSigned {
		t.Errorf("unexpected key information: %+v", certificate.resultCertificateInfo)
	}
	if certificate.Verified {
		t.Error("expired self signed certificate must not be verified")
	}
}

func TestCheckCertificateGlobBundleAndSubject(t *testing.T) {
	p := newTestPKI(t)

	// Combined PEM file with private key and certificate (e.g. HAProxy)
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.leaf.key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(p.dir, "combined.pem"), &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}, certBlock(p.leaf))
	// Private key only
	writePEM(t, filepath.Join(p.dir, "privkey.pem"), &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	res := runCertificateCheckOK(t, &config.CertificateDefinition{Type: config.CertificateTypeFile, Path: filepath.Join(p.dir, "*.pem"), SkipVerify: true})
	// ca.pem, combined.pem, fullchain.pem
	if len(res.Certificates) != 3 {
		t.Fatalf("expected 3 certificates: %+v", res.Certificates)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "privkey.pem: no certificate found") {
		t.Errorf("expected warning for privkey.pem: %+v", res.Warnings)
	}

	// Every certificate of a bundle on its own
	res = runCertificateCheckOK(t, &config.CertificateDefinition{Type: config.CertificateTypeFile, Path: p.fullchain, SplitBundle: true, SkipVerify: true})
	if len(res.Certificates) != 2 || len(res.Certificates[0].Chain) != 0 {
		t.Errorf("expected 2 certificates without chain: %+v", res.Certificates)
	}

	// Filter by DNS name
	res = runCertificateCheckOK(t, &config.CertificateDefinition{
		Type: config.CertificateTypeFile, Path: filepath.Join(p.dir, "*.pem"), SkipVerify: true,
		SubjectRegexp: regexp.MustCompile(`^example\.com$`),
	})
	if len(res.Certificates) != 2 {
		t.Errorf("expected 2 certificates for example.com: %+v", res.Certificates)
	}
}

func TestCheckCertificateErrors(t *testing.T) {
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "privkey.pem"), &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")})

	for name, definition := range map[string]*config.CertificateDefinition{
		"no file":        {Type: config.CertificateTypeFile, Path: filepath.Join(dir, "missing.pem")},
		"no certificate": {Type: config.CertificateTypeFile, Path: filepath.Join(dir, "*.pem")},
		"invalid ca":     {Type: config.CertificateTypeFile, Path: filepath.Join(dir, "*.pem"), CAFile: filepath.Join(dir, "missing.pem")},
		"config error":   {Type: config.CertificateTypeFile, ConfigError: "missing path"},
	} {
		res, ok := runCertificateCheck(t, definition).(map[string]string)
		if !ok || res["error"] == "" {
			t.Errorf("%s: expected error, got %+v", name, res)
		}
	}
}

func TestNewestCertificatePerSubject(t *testing.T) {
	old := createTestCertificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: "iis"}, NotAfter: time.Now().Add(-time.Hour), NotBefore: time.Now().Add(-48 * time.Hour)}, nil, nil)
	renewed := createTestCertificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: "iis"}, NotAfter: time.Now().Add(90 * 24 * time.Hour)}, nil, nil)
	other := createTestCertificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: "rdp"}}, nil, nil)

	result := newestCertificatePerSubject([]*certificateCandidate{
		{certificate: old.certificate}, {certificate: other.certificate}, {certificate: renewed.certificate},
	})
	if len(result) != 2 || result[0].certificate != renewed.certificate || result[1].certificate != other.certificate {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestParseWindowsCertificateStore(t *testing.T) {
	for store, expected := range map[string]string{
		`LocalMachine\My`:             "LocalMachine|My",
		`currentuser/My`:              "CurrentUser|My",
		`LocalMachine\Remote Desktop`: "LocalMachine|Remote Desktop",
		`My`:                          "error",
		`Somewhere\My`:                "error",
	} {
		location, name, err := parseWindowsCertificateStore(store)
		got := location + "|" + name
		if err != nil {
			got = "error"
		}
		if got != expected {
			t.Errorf("%s: expected %s, got %s", store, expected, got)
		}
	}
}

func TestCheckCertificateSHA1(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := caTemplate("Old SHA1 Root")
	template.SignatureAlgorithm = x509.SHA1WithRSA
	der, err := x509.CreateCertificate(rand.Reader, template, template, rsaKey.Public(), rsaKey)
	if err != nil {
		t.Skip("creating SHA1 certificates is not supported: ", err)
	}
	path := filepath.Join(t.TempDir(), "sha1.pem")
	writePEM(t, path, &pem.Block{Type: "CERTIFICATE", Bytes: der})

	res := runCertificateCheckOK(t, &config.CertificateDefinition{Type: config.CertificateTypeFile, Path: path, CAFile: path})
	certificate := res.Certificates[0]
	if certificate.SignatureAlgorithm != "SHA1-RSA" || !certificate.SelfSigned {
		t.Errorf("unexpected certificate: %+v", certificate.resultCertificateInfo)
	}
}
