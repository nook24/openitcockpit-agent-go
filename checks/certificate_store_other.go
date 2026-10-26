//go:build !windows
// +build !windows

package checks

import (
	"crypto/x509"
	"fmt"
	"runtime"
)

func readWindowsCertificateStore(store string) ([]*x509.Certificate, []string, error) {
	return nil, nil, fmt.Errorf("windows certificate store is not supported on %s", runtime.GOOS)
}
