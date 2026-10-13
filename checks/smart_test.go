package checks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testSmartHDD = `{
  "json_format_version": [1, 0],
  "smartctl": {"version": [7, 3], "exit_status": 0},
  "device": {"name": "/dev/sda", "info_name": "/dev/sda [SAT]", "type": "sat", "protocol": "ATA"},
  "model_family": "Western Digital Red",
  "model_name": "WDC WD40EFRX-68N32N0",
  "serial_number": "WD-WCC7K1234567",
  "firmware_version": "82.00A82",
  "user_capacity": {"blocks": 7814037168, "bytes": 4000787030016},
  "smart_support": {"available": true, "enabled": true},
  "smart_status": {"passed": true},
  "ata_smart_attributes": {"revision": 16, "table": [
    {"id": 1, "name": "Raw_Read_Error_Rate", "value": 200, "worst": 200, "thresh": 51, "when_failed": "", "raw": {"value": 0, "string": "0"}},
    {"id": 5, "name": "Reallocated_Sector_Ct", "value": 200, "worst": 200, "thresh": 140, "when_failed": "", "raw": {"value": 0, "string": "0"}},
    {"id": 9, "name": "Power_On_Hours", "value": 52, "worst": 52, "thresh": 0, "when_failed": "", "raw": {"value": 35123, "string": "35123"}},
    {"id": 194, "name": "Temperature_Celsius", "value": 116, "worst": 104, "thresh": 0, "when_failed": "", "raw": {"value": 34, "string": "34"}},
    {"id": 197, "name": "Current_Pending_Sector", "value": 200, "worst": 200, "thresh": 0, "when_failed": "", "raw": {"value": 0, "string": "0"}},
    {"id": 198, "name": "Offline_Uncorrectable", "value": 100, "worst": 253, "thresh": 0, "when_failed": "", "raw": {"value": 0, "string": "0"}},
    {"id": 199, "name": "UDMA_CRC_Error_Count", "value": 200, "worst": 200, "thresh": 0, "when_failed": "", "raw": {"value": 2, "string": "2"}}
  ]},
  "power_on_time": {"hours": 35123},
  "power_cycle_count": 87,
  "temperature": {"current": 34},
  "ata_smart_error_log": {"summary": {"revision": 1, "count": 0}}
}`

const testSmartSSD = `{
  "smartctl": {"version": [7, 4], "exit_status": 64},
  "device": {"name": "/dev/sdb", "info_name": "/dev/sdb [SAT]", "type": "sat", "protocol": "ATA"},
  "model_name": "Samsung SSD 870 EVO 1TB",
  "serial_number": "S6PTNX0R123456A",
  "firmware_version": "SVT02B6Q",
  "user_capacity": {"bytes": 1000204886016},
  "smart_support": {"available": true, "enabled": true},
  "smart_status": {"passed": true},
  "ata_smart_attributes": {"revision": 1, "table": [
    {"id": 5, "name": "Reallocated_Sector_Ct", "value": 99, "worst": 99, "thresh": 10, "when_failed": "", "raw": {"value": 12, "string": "12"}},
    {"id": 177, "name": "Wear_Leveling_Count", "value": 85, "worst": 85, "thresh": 0, "when_failed": "", "raw": {"value": 213, "string": "213"}},
    {"id": 187, "name": "Uncorrectable_Error_Cnt", "value": 99, "worst": 99, "thresh": 0, "when_failed": "", "raw": {"value": 3, "string": "3"}},
    {"id": 190, "name": "Airflow_Temperature_Cel", "value": 62, "worst": 48, "thresh": 0, "when_failed": "", "raw": {"value": 38, "string": "38"}}
  ]},
  "power_on_time": {"hours": 12034},
  "power_cycle_count": 312,
  "temperature": {"current": 38},
  "ata_smart_error_log": {"extended": {"revision": 1, "sectors": 1, "count": 3}}
}`

const testSmartNVMe = `{
  "smartctl": {"version": [7, 3], "exit_status": 0},
  "device": {"name": "/dev/nvme0", "info_name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe"},
  "model_name": "Samsung SSD 980 PRO 2TB",
  "serial_number": "S69ENF0R123456",
  "firmware_version": "5B2QGXA7",
  "nvme_total_capacity": 2000398934016,
  "user_capacity": {"blocks": 3907029168, "bytes": 2000398934016},
  "smart_status": {"passed": true, "nvme": {"value": 0}},
  "nvme_smart_health_information_log": {
    "critical_warning": 0, "temperature": 42, "available_spare": 100, "available_spare_threshold": 10, "percentage_used": 3,
    "data_units_read": 123456789, "data_units_written": 98765432, "power_cycles": 120, "power_on_hours": 8760,
    "unsafe_shutdowns": 12, "media_errors": 0, "num_err_log_entries": 0
  },
  "temperature": {"current": 42},
  "power_cycle_count": 120,
  "power_on_time": {"hours": 8760}
}`

// Failing disk: exit status 24 = bit 3 (SMART status failing) + bit 4 (prefail attribute below threshold)
const testSmartFailing = `{
  "smartctl": {"version": [7, 3], "exit_status": 24},
  "device": {"name": "/dev/sdc", "info_name": "/dev/sdc [SAT]", "type": "sat", "protocol": "ATA"},
  "model_name": "ST4000DM004-2CV104",
  "serial_number": "ZFN1ABCD",
  "smart_support": {"available": true, "enabled": true},
  "smart_status": {"passed": false},
  "ata_smart_attributes": {"revision": 10, "table": [
    {"id": 5, "name": "Reallocated_Sector_Ct", "value": 8, "worst": 8, "thresh": 10, "when_failed": "now", "raw": {"value": 3912, "string": "3912"}},
    {"id": 197, "name": "Current_Pending_Sector", "value": 100, "worst": 100, "thresh": 0, "when_failed": "", "raw": {"value": 8, "string": "8"}},
    {"id": 198, "name": "Offline_Uncorrectable", "value": 100, "worst": 100, "thresh": 0, "when_failed": "", "raw": {"value": 8, "string": "8"}},
    {"id": 189, "name": "High_Fly_Writes", "value": 1, "worst": 1, "thresh": 0, "when_failed": "past", "raw": {"value": 150, "string": "150"}}
  ]},
  "temperature": {"current": 41},
  "ata_smart_error_log": {"summary": {"revision": 1, "count": 112}}
}`

// The disk is sleeping and not woken up because of "-n standby"
const testSmartStandby = `{
  "smartctl": {"version": [7, 3], "exit_status": 2, "messages": [{"string": "Device is in STANDBY mode, exit(2)", "severity": "information"}]},
  "device": {"name": "/dev/sdd", "info_name": "/dev/sdd [SAT]", "type": "sat", "protocol": "ATA"}
}`

// Virtual disk of a VM
const testSmartVirtual = `{
  "smartctl": {"version": [7, 3], "exit_status": 4, "messages": [{"string": "SMART support is: Unavailable - device lacks SMART capability.", "severity": "information"}]},
  "device": {"name": "/dev/sda", "info_name": "/dev/sda", "type": "scsi", "protocol": "SCSI"},
  "scsi_vendor": "QEMU", "scsi_product": "QEMU HARDDISK", "scsi_model_name": "QEMU QEMU HARDDISK",
  "user_capacity": {"bytes": 34359738368},
  "smart_support": {"available": false}
}`

const testSmartSAS = `{
  "smartctl": {"version": [7, 3], "exit_status": 0},
  "device": {"name": "/dev/sde", "info_name": "/dev/sde", "type": "scsi", "protocol": "SCSI"},
  "scsi_model_name": "SEAGATE ST1200MM0099",
  "serial_number": "WFK1ABCD0000",
  "smart_support": {"available": true, "enabled": true},
  "smart_status": {"passed": true},
  "temperature": {"current": 31},
  "scsi_grown_defect_list": 3,
  "scsi_percentage_used_endurance_indicator": 5,
  "power_on_time": {"hours": 40112}
}`

func TestParseSmartDevice(t *testing.T) {
	hdd, err := parseSmartDevice([]byte(testSmartHDD))
	if err != nil {
		t.Fatal(err)
	}
	if hdd.Device != "/dev/sda" || hdd.Protocol != "ATA" || hdd.Model != "WDC WD40EFRX-68N32N0" || hdd.CapacityBytes != 4000787030016 ||
		hdd.Passed == nil || !*hdd.Passed || !hdd.SmartAvailable || hdd.Temperature != 34 || hdd.PowerOnHours != 35123 || hdd.PowerCycles != 87 {
		t.Errorf("unexpected HDD: %+v", hdd)
	}
	if hdd.ReallocatedSectors != 0 || hdd.PendingSectors != 0 || hdd.OfflineUncorrectable != 0 || hdd.CRCErrors != 2 ||
		hdd.ReportedUncorrect != -1 || hdd.PercentageUsed != -1 || hdd.MediaErrors != -1 || len(hdd.FailedAttributes) != 0 {
		t.Errorf("unexpected HDD attributes: %+v", hdd)
	}

	ssd, _ := parseSmartDevice([]byte(testSmartSSD))
	if ssd.ReallocatedSectors != 12 || ssd.ReportedUncorrect != 3 || ssd.PercentageUsed != 15 || ssd.ErrorLogCount != 3 || ssd.ExitStatus != 64 {
		t.Errorf("unexpected SSD: %+v", ssd)
	}

	nvme, _ := parseSmartDevice([]byte(testSmartNVMe))
	if nvme.Protocol != "NVMe" || !nvme.SmartAvailable || nvme.Passed == nil || !*nvme.Passed || nvme.PercentageUsed != 3 ||
		nvme.AvailableSpare != 100 || nvme.AvailableSpareThreshold != 10 || nvme.CriticalWarning != 0 || nvme.MediaErrors != 0 || nvme.Temperature != 42 {
		t.Errorf("unexpected NVMe: %+v", nvme)
	}

	failing, _ := parseSmartDevice([]byte(testSmartFailing))
	if failing.Passed == nil || *failing.Passed || failing.ReallocatedSectors != 3912 || failing.PendingSectors != 8 || failing.ErrorLogCount != 112 ||
		strings.Join(failing.FailedAttributes, ",") != "Reallocated_Sector_Ct (now),High_Fly_Writes (past)" {
		t.Errorf("unexpected failing disk: %+v", failing)
	}

	standby, _ := parseSmartDevice([]byte(testSmartStandby))
	if !standby.Standby || standby.Passed != nil {
		t.Errorf("unexpected standby disk: %+v", standby)
	}

	virtual, _ := parseSmartDevice([]byte(testSmartVirtual))
	if virtual.SmartAvailable || virtual.Passed != nil || virtual.Model != "QEMU QEMU HARDDISK" || len(virtual.Messages) != 1 {
		t.Errorf("unexpected virtual disk: %+v", virtual)
	}

	sas, _ := parseSmartDevice([]byte(testSmartSAS))
	if sas.Model != "SEAGATE ST1200MM0099" || sas.ReallocatedSectors != 3 || sas.PercentageUsed != 5 || sas.Passed == nil || !*sas.Passed {
		t.Errorf("unexpected SAS disk: %+v", sas)
	}
}

func TestCheckSmartWithFakeSmartctl(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	smartCacheMutex.Lock()
	smartCache = nil
	smartCacheMutex.Unlock()
	t.Cleanup(func() {
		smartCacheMutex.Lock()
		smartCache = nil
		smartCacheMutex.Unlock()
	})

	dir := t.TempDir()
	fixtures := map[string]string{"sda": testSmartHDD, "nvme0": testSmartNVMe, "sdc": testSmartFailing, "sdd": testSmartStandby}
	for name, content := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	scan := `{"devices": [{"name": "/dev/sda", "info_name": "/dev/sda [SAT]", "type": "sat", "protocol": "ATA"}, {"name": "/dev/nvme0", "info_name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe"}, {"name": "/dev/sdc", "type": "sat", "protocol": "ATA"}, {"name": "/dev/sdd", "type": "sat", "protocol": "ATA"}, {"name": "/dev/sdx", "type": "sat", "protocol": "ATA"}]}`
	// The exit status of smartctl is a bit mask with the disk health, so the output must be parsed for every exit status
	script := `#!/bin/sh
case "$*" in
  "--scan-open --json") echo '` + scan + `' ;;
  "--json --all -n standby -d sat /dev/sda") cat ` + dir + `/sda.json ;;
  "--json --all -n standby -d nvme /dev/nvme0") cat ` + dir + `/nvme0.json ;;
  "--json --all -n standby -d sat /dev/sdc") cat ` + dir + `/sdc.json; exit 24 ;;
  "--json --all -n standby -d sat /dev/sdd") cat ` + dir + `/sdd.json; exit 2 ;;
  "--json --all -n standby -d sat /dev/sdx") echo "Smartctl open device: /dev/sdx failed: No such device" >&2; exit 2 ;;
  *) echo "unexpected arguments: $*" >&2; exit 1 ;;
esac
`
	smartctl := filepath.Join(dir, "smartctl")
	if err := os.WriteFile(smartctl, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	r, err := (&CheckSmart{smartctl: smartctl}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	devices := r.([]*resultSmartDevice)
	if len(devices) != 5 {
		t.Fatalf("expected 5 devices, got %d", len(devices))
	}
	if devices[2].Passed == nil || *devices[2].Passed {
		t.Errorf("the failing disk must be reported although smartctl exited with 24: %+v", devices[2])
	}
	if !devices[3].Standby {
		t.Errorf("standby disk expected: %+v", devices[3])
	}
	if d := devices[4]; d.Device != "/dev/sdx" || len(d.Messages) != 1 || !strings.Contains(d.Messages[0], "failed") {
		t.Errorf("expected an error for /dev/sdx: %+v", d)
	}

	// The result is cached
	if err := os.Remove(smartctl); err != nil {
		t.Fatal(err)
	}
	if r, err := (&CheckSmart{smartctl: smartctl}).Run(context.Background()); err != nil || len(r.([]*resultSmartDevice)) != 5 {
		t.Errorf("expected the cached result: %v", err)
	}
}
