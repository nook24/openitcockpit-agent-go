package checks

import (
	"errors"
	"strings"
	"testing"

	"github.com/yusufpapurcu/wmi"
)

func TestIsWMINotFound(t *testing.T) {
	// The error messages are localized, e.g. "Ungültiger Namespace" on German systems
	var dst []antiVirusProduct
	err := wmi.QueryNamespace("SELECT displayName FROM AntiVirusProduct", &dst, `root\OitcDoesNotExist`)
	if err == nil || !isWMINotFound(err) {
		t.Errorf("missing namespace not detected: %v", err)
	}
	err = wmi.Query("SELECT DisplayName FROM Oitc_DoesNotExist", &dst)
	if err == nil || !isWMINotFound(err) {
		t.Errorf("missing class not detected: %v", err)
	}
	if isWMINotFound(errors.New("access denied")) {
		t.Error("other errors must not be detected as missing namespace or class")
	}
}

func TestWmiPerfClassError(t *testing.T) {
	var dst []struct{ Name string }
	err := wmiPerfClassError(wmi.Query("SELECT Name FROM Win32_PerfFormattedData_OitcDoesNotExist", &dst))
	if err == nil || !strings.Contains(err.Error(), "winmgmt /resyncperf") || !isWMINotFound(err) {
		t.Errorf("missing hint or wrapped error: %v", err)
	}
	if err := wmiPerfClassError(errors.New("access denied")); err.Error() != "access denied" {
		t.Errorf("other errors must not be changed: %v", err)
	}
	if err := wmiPerfClassError(nil); err != nil {
		t.Errorf("expected nil: %v", err)
	}
}
