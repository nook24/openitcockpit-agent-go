package checks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/yusufpapurcu/wmi"
)

type resultWindowsFirewallProfile struct {
	Enabled bool `json:"enabled"`
	Active  bool `json:"active"` // The profile is used by at least one network connection
}

type resultWindowsFirewall struct {
	Profiles map[string]*resultWindowsFirewallProfile `json:"profiles"` // domain, private and public
}

type resultWindowsDefender struct {
	Available                 bool   `json:"available"` // false if Microsoft Defender is not installed or replaced by another antivirus
	AMServiceEnabled          bool   `json:"am_service_enabled"`
	AntivirusEnabled          bool   `json:"antivirus_enabled"`
	AntispywareEnabled        bool   `json:"antispyware_enabled"`
	RealTimeProtectionEnabled bool   `json:"real_time_protection_enabled"`
	BehaviorMonitorEnabled    bool   `json:"behavior_monitor_enabled"`
	IsTamperProtected         bool   `json:"is_tamper_protected"`
	AMRunningMode             string `json:"am_running_mode"`        // e.g.: Normal, Passive Mode, EDR Block Mode
	SignatureVersion          string `json:"signature_version"`      // e.g.: 1.403.123.0
	SignatureLastUpdated      int64  `json:"signature_last_updated"` // Unix timestamp
	SignatureAge              int64  `json:"signature_age"`          // Days, -1 = never updated
	QuickScanAge              int64  `json:"quick_scan_age"`         // Days since the last quick scan, -1 = never
	FullScanAge               int64  `json:"full_scan_age"`          // Days since the last full scan, -1 = never
	ProductVersion            string `json:"product_version"`        // e.g.: 4.18.25010.11
}

type resultAntivirusProduct struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UpToDate bool   `json:"up_to_date"`
}

// MSFT_MpComputerStatus of root\Microsoft\Windows\Defender
type mpComputerStatus struct {
	AMServiceEnabled              bool
	AntivirusEnabled              bool
	AntispywareEnabled            bool
	RealTimeProtectionEnabled     bool
	BehaviorMonitorEnabled        bool
	IsTamperProtected             bool
	AMRunningMode                 string
	AntivirusSignatureVersion     string
	AntivirusSignatureLastUpdated time.Time
	AntivirusSignatureAge         uint32
	QuickScanAge                  uint32
	FullScanAge                   uint32
	AMProductVersion              string
}

// AntiVirusProduct of root\SecurityCenter2 (only available on client versions of Windows)
type antiVirusProduct struct {
	DisplayName  string
	ProductState uint32
}

var windowsFirewallProfiles = []struct {
	name string
	id   int32 // NET_FW_PROFILE_TYPE2
}{
	{"domain", 1},
	{"private", 2},
	{"public", 4},
}

func securityParts() []securityPart {
	return []securityPart{
		{"firewall", func(ctx context.Context) (interface{}, error) { return getWindowsFirewall() }},
		{"defender", func(ctx context.Context) (interface{}, error) { return getWindowsDefender() }},
		{"antivirus", func(ctx context.Context) (interface{}, error) { return getAntivirusProducts() }},
		{"bitlocker", func(ctx context.Context) (interface{}, error) { return getBitLocker() }},
	}
}

// getWindowsFirewall returns the effective state of the firewall profiles including group policies
func getWindowsFirewall() (*resultWindowsFirewall, error) {
	// COM has to be initialized for the current OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		var oleError *ole.OleError
		// S_FALSE = COM is already initialized for this thread
		if !errors.As(err, &oleError) || oleError.Code() != 1 {
			return nil, err
		}
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		return nil, fmt.Errorf("could not create HNetCfg.FwPolicy2: %s", err)
	}
	defer unknown.Release()
	policy, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, err
	}
	defer policy.Release()

	current, err := oleutil.GetProperty(policy, "CurrentProfileTypes")
	if err != nil {
		return nil, fmt.Errorf("could not query active firewall profiles: %s", err)
	}
	activeProfiles := current.Value().(int32)

	res := &resultWindowsFirewall{Profiles: map[string]*resultWindowsFirewallProfile{}}
	for _, profile := range windowsFirewallProfiles {
		enabled, err := oleutil.GetProperty(policy, "FirewallEnabled", profile.id)
		if err != nil {
			return nil, fmt.Errorf("could not query firewall profile %s: %s", profile.name, err)
		}
		res.Profiles[profile.name] = &resultWindowsFirewallProfile{
			Enabled: enabled.Value().(bool),
			Active:  activeProfiles&profile.id != 0,
		}
	}
	return res, nil
}

func getWindowsDefender() (*resultWindowsDefender, error) {
	var dst []mpComputerStatus
	err := wmi.QueryNamespace("SELECT * FROM MSFT_MpComputerStatus", &dst, `root\Microsoft\Windows\Defender`)
	if err != nil {
		var fieldMismatch *wmi.ErrFieldMismatch
		if !errors.As(err, &fieldMismatch) {
			// Namespace or class does not exist, if Defender is not installed (e.g. Windows Server Core without Defender)
			if isWMINotFound(err) {
				return &resultWindowsDefender{Available: false}, nil
			}
			return nil, err
		}
		// Older versions of Defender do not know all properties (e.g. IsTamperProtected)
	}
	if len(dst) == 0 {
		return &resultWindowsDefender{Available: false}, nil
	}

	status := dst[0]
	res := &resultWindowsDefender{
		Available:                 true,
		AMServiceEnabled:          status.AMServiceEnabled,
		AntivirusEnabled:          status.AntivirusEnabled,
		AntispywareEnabled:        status.AntispywareEnabled,
		RealTimeProtectionEnabled: status.RealTimeProtectionEnabled,
		BehaviorMonitorEnabled:    status.BehaviorMonitorEnabled,
		IsTamperProtected:         status.IsTamperProtected,
		AMRunningMode:             status.AMRunningMode,
		SignatureVersion:          status.AntivirusSignatureVersion,
		SignatureAge:              defenderAge(status.AntivirusSignatureAge),
		QuickScanAge:              defenderAge(status.QuickScanAge),
		FullScanAge:               defenderAge(status.FullScanAge),
		ProductVersion:            status.AMProductVersion,
	}
	if !status.AntivirusSignatureLastUpdated.IsZero() {
		res.SignatureLastUpdated = status.AntivirusSignatureLastUpdated.Unix()
	}
	return res, nil
}

// defenderAge converts the age in days. Defender uses 4294967295 for "never"
func defenderAge(days uint32) int64 {
	if days == math.MaxUint32 {
		return -1
	}
	return int64(days)
}

// getAntivirusProducts returns all antivirus products registered in the Windows Security Center.
// The Security Center is not available on Windows Server, so an empty list is returned there.
func getAntivirusProducts() ([]*resultAntivirusProduct, error) {
	res := []*resultAntivirusProduct{}

	var dst []antiVirusProduct
	err := wmi.QueryNamespace("SELECT displayName, productState FROM AntiVirusProduct", &dst, `root\SecurityCenter2`)
	if err != nil {
		if isWMINotFound(err) {
			return res, nil
		}
		return nil, err
	}

	for _, product := range dst {
		res = append(res, &resultAntivirusProduct{
			Name:     product.DisplayName,
			Enabled:  (product.ProductState>>12)&0xF == 1,
			UpToDate: (product.ProductState>>4)&0xF == 0,
		})
	}
	return res, nil
}
