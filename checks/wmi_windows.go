package checks

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-ole/go-ole"
)

// WMI error codes, see https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-error-constants
const (
	wbemErrorInvalidNamespace = 0x8004100E
	wbemErrorInvalidClass     = 0x80041010
)

// isWMINotFound returns true if a WMI namespace or class does not exist
func isWMINotFound(err error) bool {
	// The error message is localized (e.g. "Ungültiger Namespace" on German systems), so the WMI error code is checked
	var oleError *ole.OleError
	if errors.As(err, &oleError) {
		code := uint32(oleError.Code())
		// The scripting API reports WMI errors as DISP_E_EXCEPTION with the WMI error code in the EXCEPINFO
		if info, ok := oleError.SubError().(ole.EXCEPINFO); ok && info.SCODE() != 0 {
			code = info.SCODE()
		}
		if code == wbemErrorInvalidNamespace || code == wbemErrorInvalidClass {
			return true
		}
	}

	message := strings.ToLower(err.Error())
	for _, text := range []string{"8004100e", "80041010", "invalid namespace", "invalid class"} {
		if strings.Contains(message, text) {
			return true
		}
	}
	return false
}

// wmiPerfClassError adds a hint to the error of a query of the WMI performance classes (Win32_PerfFormattedData_* and
// Win32_PerfRawData_*). Windows creates these classes from the registered performance counters. They are missing
// ("Invalid class") if the performance counters and WMI got out of sync, e.g. after an update or the installation of
// software with performance counters, until the WMI service resynchronizes them on its next start.
func wmiPerfClassError(err error) error {
	if err != nil && isWMINotFound(err) {
		return fmt.Errorf("%w (the WMI performance classes are missing, run 'winmgmt /resyncperf' as administrator or restart the system)", err)
	}
	return err
}
