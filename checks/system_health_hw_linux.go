package checks

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type resultBondSlave struct {
	Name             string `json:"name"`               // e.g.: eth0
	MiiStatus        string `json:"mii_status"`         // up or down
	Speed            string `json:"speed"`              // e.g.: 1000 Mbps
	LinkFailureCount int64  `json:"link_failure_count"` // Number of link failures since the bond was created
	AggregatorID     string `json:"aggregator_id"`      // 802.3ad only
}

type resultBond struct {
	Name               string             `json:"name"`                 // e.g.: bond0
	Mode               string             `json:"mode"`                 // e.g.: fault-tolerance (active-backup), IEEE 802.3ad Dynamic link aggregation
	MiiStatus          string             `json:"mii_status"`           // up or down
	ActiveSlave        string             `json:"active_slave"`         // active-backup only
	ActiveAggregatorID string             `json:"active_aggregator_id"` // 802.3ad only, slaves in another aggregator do not transport data
	Slaves             []*resultBondSlave `json:"slaves"`
}

type resultFilesystemErrors struct {
	Device         string `json:"device"`           // e.g.: sda1, dm-0 or the UUID of a btrfs filesystem
	Fstype         string `json:"fstype"`           // ext4 or btrfs
	Mountpoint     string `json:"mountpoint"`       // Empty if the filesystem is not mounted
	Errors         int64  `json:"errors"`           // ext4: errors_count, btrfs: sum of all error counters of all devices
	FirstErrorTime int64  `json:"first_error_time"` // ext4 only, Unix timestamp
	LastErrorTime  int64  `json:"last_error_time"`  // ext4 only, Unix timestamp
	// btrfs only: write_errs, read_errs, flush_errs, corruption_errs and generation_errs of all devices
	Details map[string]int64 `json:"details,omitempty"`
}

type resultEdacDimm struct {
	Name    string `json:"name"`  // e.g.: dimm0
	Label   string `json:"label"` // e.g.: CPU_SrcID#0_Ha#0_Chan#0_DIMM#0
	CeCount int64  `json:"ce_count"`
	UeCount int64  `json:"ue_count"`
}

type resultEdacController struct {
	Name          string            `json:"name"`     // e.g.: mc0
	MCName        string            `json:"mc_name"`  // e.g.: Skylake Socket#0 IMC#0
	CeCount       int64             `json:"ce_count"` // Corrected errors since the boot
	UeCount       int64             `json:"ue_count"` // Uncorrected errors since the boot
	CeNoinfoCount int64             `json:"ce_noinfo_count"`
	UeNoinfoCount int64             `json:"ue_noinfo_count"`
	Dimms         []*resultEdacDimm `json:"dimms"`
}

type resultEdac struct {
	Available   bool                    `json:"available"` // false if no EDAC driver is loaded (e.g. virtual machines or memory without ECC)
	Controllers []*resultEdacController `json:"controllers"`
}

// getBonds parses /proc/net/bonding/*
func getBonds(procPath string) ([]*resultBond, error) {
	files, err := filepath.Glob(filepath.Join(procPath, "net", "bonding", "*"))
	if err != nil {
		return nil, err
	}
	bonds := []*resultBond{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		bonds = append(bonds, parseBond(filepath.Base(file), data))
	}
	return bonds, nil
}

func parseBond(name string, data []byte) *resultBond {
	bond := &resultBond{Name: name, Slaves: []*resultBondSlave{}}
	var slave *resultBondSlave
	inActiveAggregator := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)

		switch key {
		case "Slave Interface":
			slave = &resultBondSlave{Name: value}
			bond.Slaves = append(bond.Slaves, slave)
			inActiveAggregator = false
			continue
		case "Active Aggregator Info":
			inActiveAggregator = true
			continue
		}

		if slave == nil {
			// Settings of the bond itself
			switch {
			case key == "Bonding Mode":
				bond.Mode = value
			case key == "MII Status":
				bond.MiiStatus = value
			case key == "Currently Active Slave":
				bond.ActiveSlave = value
			case key == "Aggregator ID" && inActiveAggregator:
				bond.ActiveAggregatorID = value
			}
			continue
		}

		switch key {
		case "MII Status":
			slave.MiiStatus = value
		case "Speed":
			slave.Speed = value
		case "Link Failure Count":
			slave.LinkFailureCount, _ = strconv.ParseInt(value, 10, 64)
		case "Aggregator ID":
			slave.AggregatorID = value
		}
	}
	return bond
}

// getFilesystemErrors reads the error counters of ext4 and btrfs filesystems
func getFilesystemErrors(procPath, sysPath string) ([]*resultFilesystemErrors, error) {
	mountpoints := kernelDeviceMountpoints(procPath)
	result := []*resultFilesystemErrors{}

	// ext4: /sys/fs/ext4/<kernel device name>/errors_count
	ext4Devices, err := filepath.Glob(filepath.Join(sysPath, "fs", "ext4", "*", "errors_count"))
	if err != nil {
		return nil, err
	}
	for _, file := range ext4Devices {
		dir := filepath.Dir(file)
		device := filepath.Base(dir)
		result = append(result, &resultFilesystemErrors{
			Device:         device,
			Fstype:         "ext4",
			Mountpoint:     mountpoints[device],
			Errors:         readSysInt(file),
			FirstErrorTime: readSysInt(filepath.Join(dir, "first_error_time")),
			LastErrorTime:  readSysInt(filepath.Join(dir, "last_error_time")),
		})
	}

	// btrfs: /sys/fs/btrfs/<uuid>/devinfo/<devid>/error_stats (Linux 5.14 or newer)
	btrfsFilesystems, err := filepath.Glob(filepath.Join(sysPath, "fs", "btrfs", "*", "devinfo"))
	if err != nil {
		return nil, err
	}
	for _, devinfo := range btrfsFilesystems {
		dir := filepath.Dir(devinfo)
		fsErrors := &resultFilesystemErrors{
			Device:  filepath.Base(dir),
			Fstype:  "btrfs",
			Details: map[string]int64{},
		}
		statsFiles, _ := filepath.Glob(filepath.Join(devinfo, "*", "error_stats"))
		for _, statsFile := range statsFiles {
			for counter, value := range parseKeyValueFile(statsFile) {
				fsErrors.Details[counter] += value
				fsErrors.Errors += value
			}
		}
		// The devices of the filesystem are links in /sys/fs/btrfs/<uuid>/devices
		devices, _ := os.ReadDir(filepath.Join(dir, "devices"))
		for _, device := range devices {
			if mountpoint, ok := mountpoints[device.Name()]; ok {
				fsErrors.Mountpoint = mountpoint
				break
			}
		}
		result = append(result, fsErrors)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Device < result[j].Device
	})
	return result, nil
}

// kernelDeviceMountpoints maps kernel device names (e.g. sda1 or dm-0) to the mountpoint
func kernelDeviceMountpoints(procPath string) map[string]string {
	result := map[string]string{}
	data, err := os.ReadFile(filepath.Join(procPath, "self", "mounts"))
	if err != nil {
		return result
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "/dev/") {
			continue
		}
		device := fields[0]
		// /dev/mapper/vg-root is a link to /dev/dm-0
		if resolved, err := filepath.EvalSymlinks(device); err == nil {
			device = resolved
		}
		name := filepath.Base(device)
		if _, exists := result[name]; !exists {
			result[name] = unescapeMountField(fields[1])
		}
	}
	return result
}

// getEdac reads the memory error counters of /sys/devices/system/edac/mc
func getEdac(sysPath string) (*resultEdac, error) {
	result := &resultEdac{Controllers: []*resultEdacController{}}
	controllers, err := filepath.Glob(filepath.Join(sysPath, "devices", "system", "edac", "mc", "mc*"))
	if err != nil {
		return nil, err
	}
	for _, dir := range controllers {
		if _, err := os.Stat(filepath.Join(dir, "ce_count")); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		controller := &resultEdacController{
			Name:          filepath.Base(dir),
			MCName:        readSysString(filepath.Join(dir, "mc_name")),
			CeCount:       readSysInt(filepath.Join(dir, "ce_count")),
			UeCount:       readSysInt(filepath.Join(dir, "ue_count")),
			CeNoinfoCount: readSysInt(filepath.Join(dir, "ce_noinfo_count")),
			UeNoinfoCount: readSysInt(filepath.Join(dir, "ue_noinfo_count")),
			Dimms:         []*resultEdacDimm{},
		}
		// Linux >= 3.6 reports the errors per DIMM (older kernels only per csrow)
		dimms, _ := filepath.Glob(filepath.Join(dir, "dimm*"))
		sort.Strings(dimms)
		for _, dimmDir := range dimms {
			controller.Dimms = append(controller.Dimms, &resultEdacDimm{
				Name:    filepath.Base(dimmDir),
				Label:   readSysString(filepath.Join(dimmDir, "dimm_label")),
				CeCount: readSysInt(filepath.Join(dimmDir, "dimm_ce_count")),
				UeCount: readSysInt(filepath.Join(dimmDir, "dimm_ue_count")),
			})
		}
		result.Controllers = append(result.Controllers, controller)
	}
	result.Available = len(result.Controllers) > 0
	return result, nil
}

func readSysString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readSysInt(path string) int64 {
	value, _ := strconv.ParseInt(readSysString(path), 10, 64)
	return value
}

// parseKeyValueFile parses files like "write_errs 0\nread_errs 2"
func parseKeyValueFile(path string) map[string]int64 {
	result := map[string]int64{}
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			if value, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				result[fields[0]] = value
			}
		}
	}
	return result
}
