package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

const (
	// SMART values change slowly, so the disks are only queried every 5 minutes
	smartCacheDuration  = 5 * time.Minute
	smartCommandTimeout = 30 * time.Second
)

// Default locations of smartctl, which are often not part of the PATH of the agent service
var smartctlLocations = []string{
	"/usr/sbin/smartctl",
	"/usr/local/sbin/smartctl",
	"/opt/homebrew/bin/smartctl",
	"/usr/local/bin/smartctl",
	`C:\Program Files\smartmontools\bin\smartctl.exe`,
}

var (
	smartCacheMutex sync.Mutex
	smartCache      []*resultSmartDevice
	smartCacheTime  time.Time
)

// CheckSmart gathers the SMART health of all disks with smartctl (smartmontools 7.0 or newer)
type CheckSmart struct {
	smartctl string
}

// Name will be used in the response as check name
func (c *CheckSmart) Name() string {
	return "smart"
}

type resultSmartDevice struct {
	Device        string `json:"device"`   // e.g.: /dev/sda or /dev/nvme0
	Type          string `json:"type"`     // smartctl device type, e.g.: sat, nvme, scsi
	Protocol      string `json:"protocol"` // ATA, NVMe or SCSI
	Model         string `json:"model"`
	Serial        string `json:"serial"`
	Firmware      string `json:"firmware"`
	CapacityBytes int64  `json:"capacity_bytes"`

	SmartAvailable bool  `json:"smart_available"`
	SmartEnabled   bool  `json:"smart_enabled"`
	Passed         *bool `json:"passed"`  // SMART overall-health self-assessment, null if unknown (e.g. standby)
	Standby        bool  `json:"standby"` // The disk was sleeping and was not woken up
	Temperature    int64 `json:"temperature"`
	PowerOnHours   int64 `json:"power_on_hours"`
	PowerCycles    int64 `json:"power_cycles"`

	// ATA, -1 if not available
	ReallocatedSectors   int64    `json:"reallocated_sectors"`   // 5 Reallocated_Sector_Ct
	PendingSectors       int64    `json:"pending_sectors"`       // 197 Current_Pending_Sector
	OfflineUncorrectable int64    `json:"offline_uncorrectable"` // 198 Offline_Uncorrectable
	ReportedUncorrect    int64    `json:"reported_uncorrect"`    // 187 Reported_Uncorrect
	CRCErrors            int64    `json:"crc_errors"`            // 199 UDMA_CRC_Error_Count, usually a cable problem
	FailedAttributes     []string `json:"failed_attributes"`     // Attributes below their threshold, e.g.: Reallocated_Sector_Ct (now)

	// SSD wear in percent (NVMe percentage_used, ATA wear leveling attributes, SCSI endurance), -1 if not available
	PercentageUsed int64 `json:"percentage_used"`

	// NVMe, -1 if not available
	CriticalWarning         int64 `json:"critical_warning"` // Bit field, 0 = no warning
	AvailableSpare          int64 `json:"available_spare"`  // Percent
	AvailableSpareThreshold int64 `json:"available_spare_threshold"`
	MediaErrors             int64 `json:"media_errors"`

	ErrorLogCount int64    `json:"error_log_count"` // Errors in the error log of the disk
	ExitStatus    int      `json:"exit_status"`     // Exit status of smartctl (bit mask)
	Messages      []string `json:"messages"`        // Messages of smartctl, e.g. why the disk could not be read
}

// Subset of "smartctl --scan-open --json"
type smartScanJSON struct {
	Devices []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"devices"`
}

// Subset of "smartctl --json --all"
type smartDeviceJSON struct {
	Smartctl struct {
		ExitStatus int `json:"exit_status"`
		Messages   []struct {
			String   string `json:"string"`
			Severity string `json:"severity"`
		} `json:"messages"`
	} `json:"smartctl"`
	Device struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelName       string `json:"model_name"`
	ScsiModelName   string `json:"scsi_model_name"`
	SerialNumber    string `json:"serial_number"`
	FirmwareVersion string `json:"firmware_version"`
	UserCapacity    struct {
		Bytes int64 `json:"bytes"`
	} `json:"user_capacity"`
	SmartSupport *struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current int64 `json:"current"`
	} `json:"temperature"`
	PowerOnTime struct {
		Hours int64 `json:"hours"`
	} `json:"power_on_time"`
	PowerCycleCount    int64 `json:"power_cycle_count"`
	AtaSmartAttributes *struct {
		Table []struct {
			ID         int64  `json:"id"`
			Name       string `json:"name"`
			Value      int64  `json:"value"`
			WhenFailed string `json:"when_failed"`
			Raw        struct {
				Value int64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	AtaSmartErrorLog *struct {
		Summary *struct {
			Count int64 `json:"count"`
		} `json:"summary"`
		Extended *struct {
			Count int64 `json:"count"`
		} `json:"extended"`
	} `json:"ata_smart_error_log"`
	NvmeHealth *struct {
		CriticalWarning         int64 `json:"critical_warning"`
		AvailableSpare          int64 `json:"available_spare"`
		AvailableSpareThreshold int64 `json:"available_spare_threshold"`
		PercentageUsed          int64 `json:"percentage_used"`
		MediaErrors             int64 `json:"media_errors"`
		NumErrLogEntries        int64 `json:"num_err_log_entries"`
	} `json:"nvme_smart_health_information_log"`
	ScsiPercentageUsed *int64 `json:"scsi_percentage_used_endurance_indicator"`
	ScsiGrownDefects   *int64 `json:"scsi_grown_defect_list"`
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckSmart) Run(ctx context.Context) (interface{}, error) {
	smartCacheMutex.Lock()
	defer smartCacheMutex.Unlock()

	if smartCache != nil && time.Since(smartCacheTime) < smartCacheDuration {
		return smartCache, nil
	}

	smartctl := c.smartctl
	if smartctl == "" {
		smartctl = findSmartctl()
	}
	if smartctl == "" {
		return nil, fmt.Errorf("smartctl: %w, please install smartmontools 7.0 or newer", exec.ErrNotFound)
	}

	scanOutput, err := runSmartctl(ctx, smartctl, "--scan-open", "--json")
	if err != nil {
		return nil, err
	}
	var scan smartScanJSON
	if err := json.Unmarshal(scanOutput, &scan); err != nil {
		return nil, fmt.Errorf("could not parse output of smartctl --scan-open: %s", err)
	}

	devices := make([]*resultSmartDevice, 0, len(scan.Devices))
	for _, device := range scan.Devices {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		args := []string{"--json", "--all", "-n", "standby"}
		if device.Type != "" {
			args = append(args, "-d", device.Type)
		}
		args = append(args, device.Name)

		output, err := runSmartctl(ctx, smartctl, args...)
		if err != nil && len(output) == 0 {
			devices = append(devices, &resultSmartDevice{Device: device.Name, Type: device.Type, Protocol: device.Protocol, Messages: []string{err.Error()}})
			continue
		}
		result, err := parseSmartDevice(output)
		if err != nil {
			devices = append(devices, &resultSmartDevice{Device: device.Name, Type: device.Type, Protocol: device.Protocol, Messages: []string{err.Error()}})
			continue
		}
		if result.Device == "" {
			result.Device = device.Name
		}
		devices = append(devices, result)
	}

	smartCache, smartCacheTime = devices, time.Now()
	return devices, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckSmart) Configure(config *config.Configuration) (bool, error) {
	if !config.Smart {
		return false, nil
	}
	// Only enable the check if smartmontools is installed
	c.smartctl = findSmartctl()
	return c.smartctl != "", nil
}

func findSmartctl() string {
	if path, err := exec.LookPath("smartctl"); err == nil {
		return path
	}
	for _, path := range smartctlLocations {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// runSmartctl returns the output of smartctl. The exit status of smartctl is a bit mask which also contains
// the health of the disk (e.g. bit 3 = SMART status failing), so the output is returned for every exit status
func runSmartctl(ctx context.Context, smartctl string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, smartCommandTimeout)
	defer cancel()

	output, err := exec.CommandContext(ctx, smartctl, args...).Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok && len(output) > 0 {
			return output, nil
		}
		return output, fmt.Errorf("smartctl %s failed: %s", strings.Join(args, " "), err)
	}
	return output, nil
}

// ATA attributes which describe the remaining life of an SSD in percent (normalized value)
var smartWearAttributes = map[int64]bool{
	177: true, // Wear_Leveling_Count (Samsung)
	202: true, // Percent_Lifetime_Remain (Crucial/Micron)
	231: true, // SSD_Life_Left
	233: true, // Media_Wearout_Indicator (Intel)
}

func parseSmartDevice(output []byte) (*resultSmartDevice, error) {
	var data smartDeviceJSON
	if err := json.Unmarshal(output, &data); err != nil {
		return nil, fmt.Errorf("could not parse output of smartctl: %s", err)
	}

	device := &resultSmartDevice{
		Device:                  data.Device.Name,
		Type:                    data.Device.Type,
		Protocol:                data.Device.Protocol,
		Model:                   data.ModelName,
		Serial:                  data.SerialNumber,
		Firmware:                data.FirmwareVersion,
		CapacityBytes:           data.UserCapacity.Bytes,
		Temperature:             data.Temperature.Current,
		PowerOnHours:            data.PowerOnTime.Hours,
		PowerCycles:             data.PowerCycleCount,
		ReallocatedSectors:      -1,
		PendingSectors:          -1,
		OfflineUncorrectable:    -1,
		ReportedUncorrect:       -1,
		CRCErrors:               -1,
		FailedAttributes:        []string{},
		PercentageUsed:          -1,
		CriticalWarning:         -1,
		AvailableSpare:          -1,
		AvailableSpareThreshold: -1,
		MediaErrors:             -1,
		ExitStatus:              data.Smartctl.ExitStatus,
		Messages:                []string{},
	}
	if device.Model == "" {
		device.Model = data.ScsiModelName
	}

	for _, message := range data.Smartctl.Messages {
		device.Messages = append(device.Messages, message.String)
		upper := strings.ToUpper(message.String)
		if strings.Contains(upper, "STANDBY") || strings.Contains(upper, "SLEEP") {
			device.Standby = true
		}
	}

	if data.SmartSupport != nil {
		device.SmartAvailable = data.SmartSupport.Available
		device.SmartEnabled = data.SmartSupport.Enabled
	} else if data.NvmeHealth != nil || data.SmartStatus != nil {
		// NVMe devices do not report smart_support
		device.SmartAvailable, device.SmartEnabled = true, true
	}
	if data.SmartStatus != nil {
		passed := data.SmartStatus.Passed
		device.Passed = &passed
	}

	if data.AtaSmartAttributes != nil {
		for _, attribute := range data.AtaSmartAttributes.Table {
			switch attribute.ID {
			case 5:
				device.ReallocatedSectors = attribute.Raw.Value
			case 187:
				device.ReportedUncorrect = attribute.Raw.Value
			case 197:
				device.PendingSectors = attribute.Raw.Value
			case 198:
				device.OfflineUncorrectable = attribute.Raw.Value
			case 199:
				device.CRCErrors = attribute.Raw.Value
			}
			if smartWearAttributes[attribute.ID] && device.PercentageUsed < 0 && attribute.Value <= 100 {
				device.PercentageUsed = 100 - attribute.Value
			}
			// when_failed is "now" or "past" if the normalized value reached the threshold
			if attribute.WhenFailed != "" && attribute.WhenFailed != "-" {
				device.FailedAttributes = append(device.FailedAttributes, fmt.Sprintf("%s (%s)", attribute.Name, attribute.WhenFailed))
			}
		}
	}
	if data.AtaSmartErrorLog != nil {
		if data.AtaSmartErrorLog.Extended != nil {
			device.ErrorLogCount = data.AtaSmartErrorLog.Extended.Count
		} else if data.AtaSmartErrorLog.Summary != nil {
			device.ErrorLogCount = data.AtaSmartErrorLog.Summary.Count
		}
	}

	if nvme := data.NvmeHealth; nvme != nil {
		device.CriticalWarning = nvme.CriticalWarning
		device.AvailableSpare = nvme.AvailableSpare
		device.AvailableSpareThreshold = nvme.AvailableSpareThreshold
		device.PercentageUsed = nvme.PercentageUsed
		device.MediaErrors = nvme.MediaErrors
		device.ErrorLogCount = nvme.NumErrLogEntries
	}

	if data.ScsiPercentageUsed != nil {
		device.PercentageUsed = *data.ScsiPercentageUsed
	}
	if data.ScsiGrownDefects != nil {
		// Grown defects are the reallocated sectors of SCSI/SAS disks
		device.ReallocatedSectors = *data.ScsiGrownDefects
	}

	return device, nil
}
