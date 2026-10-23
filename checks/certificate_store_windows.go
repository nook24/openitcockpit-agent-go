package checks

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readWindowsCertificateStore returns all certificates of a Windows certificate store like LocalMachine\My
func readWindowsCertificateStore(store string) ([]*x509.Certificate, []string, error) {
	location, name, err := parseWindowsCertificateStore(store)
	if err != nil {
		return nil, nil, err
	}

	flags := uint32(windows.CERT_STORE_READONLY_FLAG | windows.CERT_STORE_OPEN_EXISTING_FLAG)
	if location == "LocalMachine" {
		flags |= windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	} else {
		flags |= windows.CERT_SYSTEM_STORE_CURRENT_USER
	}

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, nil, err
	}

	handle, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(namePtr)))
	if err != nil {
		return nil, nil, fmt.Errorf("could not open certificate store %s: %s", store, err)
	}
	defer windows.CertCloseStore(handle, 0)

	var certificates []*x509.Certificate
	var warnings []string
	var certContext *windows.CertContext
	for {
		// The previous context gets freed by CertEnumCertificatesInStore
		certContext, err = windows.CertEnumCertificatesInStore(handle, certContext)
		if err != nil {
			if errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
				break
			}
			return nil, nil, fmt.Errorf("could not read certificate store %s: %s", store, err)
		}
		if certContext == nil {
			break
		}

		// Copy the data, as the memory is owned by Windows
		der := bytes.Clone(unsafe.Slice(certContext.EncodedCert, certContext.Length))
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("could not parse certificate of %s: %s", store, err))
			continue
		}
		certificates = append(certificates, certificate)
	}

	return certificates, warnings, nil
}
