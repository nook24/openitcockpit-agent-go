package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
	"github.com/prometheus/procfs"
)

// OOM kill events older than this will be discarded. The receiver evaluates OOM kills within a configurable window
const oomKillEventRetention = 24 * time.Hour

// The OOM kill counter is stored outside of CheckSystemHealth, because the checks get
// recreated on every reload of the agent.
var (
	oomKillStateMutex sync.Mutex
	oomKillState      *oomKillCounterState
)

type oomKillCounterState struct {
	lastTotal uint64
	events    []*resultOomKillEvent
}

// CheckSystemHealth gathers Linux kernel health information like software RAID state,
// OOM kills, file descriptor usage, conntrack table usage, pressure stall information,
// bonding, filesystem errors and memory errors (EDAC)
type CheckSystemHealth struct {
	// procPath and sysPath can be changed by tests
	procPath string
	sysPath  string
}

// Name will be used in the response as check name
func (c *CheckSystemHealth) Name() string {
	return "system_health"
}

type resultRaid struct {
	Name              string   `json:"name"`                // e.g.: md0
	Type              string   `json:"type"`                // e.g.: raid1 (unknown for containers like external:imsm)
	ActivityState     string   `json:"activity_state"`      // e.g.: active, inactive, recovering, resyncing, checking, reshaping
	DisksActive       int64    `json:"disks_active"`        // Number of active disks
	DisksTotal        int64    `json:"disks_total"`         // Number of disks the device requires
	DisksFailed       int64    `json:"disks_failed"`        // Number of failed disks
	DisksDown         int64    `json:"disks_down"`          // Number of missing disks
	DisksSpare        int64    `json:"disks_spare"`         // Number of spare disks
	SyncPercent       float64  `json:"sync_percent"`        // Progress of the current resync/recovery/check
	SyncFinishMinutes float64  `json:"sync_finish_minutes"` // Estimated time until the current sync finishes
	FailedDevices     []string `json:"failed_devices"`      // e.g.: ["sdb1"]
	// Superblock format, e.g.: 1.2, 0.90, external:imsm (container of Intel Matrix Storage) or external:/md127/0 (volume of a container)
	MetadataVersion string `json:"metadata_version"`
}

type resultOomKillEvent struct {
	Timestamp int64  `json:"timestamp"` // Unix timestamp of the check run which detected the OOM kill
	Count     uint64 `json:"count"`     // Number of OOM kills since the last check run
}

type resultOomKills struct {
	Total  uint64                `json:"total"`  // OOM kills since the system was booted
	Events []*resultOomKillEvent `json:"events"` // OOM kills detected by the agent within the last 24 hours
}

type resultFileDescriptors struct {
	Used    uint64  `json:"used"`
	Max     uint64  `json:"max"`
	Percent float64 `json:"percent"`
}

type resultConntrack struct {
	Available bool    `json:"available"` // false if nf_conntrack is not loaded
	Count     uint64  `json:"count"`
	Max       uint64  `json:"max"`
	Percent   float64 `json:"percent"`
}

type resultPressureLine struct {
	Avg10  float64 `json:"avg10"`  // Percentage of time stalled in the last 10 seconds
	Avg60  float64 `json:"avg60"`  // Percentage of time stalled in the last 60 seconds
	Avg300 float64 `json:"avg300"` // Percentage of time stalled in the last 300 seconds
}

type resultPressureResource struct {
	Some *resultPressureLine `json:"some"` // At least one task was stalled
	Full *resultPressureLine `json:"full"` // All non-idle tasks were stalled (null for cpu on older kernels)
}

type resultPressure struct {
	Available bool                               `json:"available"` // false if the kernel does not support PSI or it is disabled
	Resources map[string]*resultPressureResource `json:"resources"` // cpu, memory, io
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckSystemHealth) Run(ctx context.Context) (interface{}, error) {
	procPath := c.procPath
	if procPath == "" {
		procPath = procfs.DefaultMountPoint
	}
	sysPath := c.sysPath
	if sysPath == "" {
		sysPath = "/sys"
	}

	proc, err := procfs.NewFS(procPath)
	if err != nil {
		return nil, err
	}

	// Every part of the check can fail on its own. The error is reported as {"error": "..."} for the affected part only
	result := map[string]interface{}{}
	parts := []struct {
		name string
		run  func() (interface{}, error)
	}{
		{"raid", func() (interface{}, error) { return getRaidStats(proc, sysPath) }},
		{"oom_kills", func() (interface{}, error) { return getOomKills(procPath) }},
		{"file_descriptors", func() (interface{}, error) { return getFileDescriptors(procPath) }},
		{"conntrack", func() (interface{}, error) { return getConntrack(procPath) }},
		{"pressure", func() (interface{}, error) { return getPressure(proc) }},
		{"bonding", func() (interface{}, error) { return getBonds(procPath) }},
		{"filesystem_errors", func() (interface{}, error) { return getFilesystemErrors(procPath, sysPath) }},
		{"edac", func() (interface{}, error) { return getEdac(sysPath) }},
	}
	for _, part := range parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := part.run()
		if err != nil {
			result[part.name] = map[string]string{"error": err.Error()}
			continue
		}
		result[part.name] = res
	}

	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckSystemHealth) Configure(config *config.Configuration) (bool, error) {
	return config.SystemHealth, nil
}

func getRaidStats(proc procfs.FS, sysPath string) ([]*resultRaid, error) {
	mdstats, err := proc.MDStat()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// md driver not loaded, so there is no software RAID
			return []*resultRaid{}, nil
		}
		return nil, err
	}

	result := make([]*resultRaid, 0, len(mdstats))
	for _, md := range mdstats {
		raid := &resultRaid{
			Name:              md.Name,
			Type:              md.Type,
			ActivityState:     md.ActivityState,
			DisksActive:       md.DisksActive,
			DisksTotal:        md.DisksTotal,
			DisksFailed:       md.DisksFailed,
			DisksDown:         md.DisksDown,
			DisksSpare:        md.DisksSpare,
			SyncPercent:       md.BlocksSyncedPct,
			SyncFinishMinutes: md.BlocksSyncedFinishTime,
			FailedDevices:     []string{},
			// An inactive array (e.g. after a boot with missing disks) and a container of Intel Matrix Storage look the same
			// in /proc/mdstat. Only the metadata version shows the difference
			MetadataVersion: readMdMetadataVersion(sysPath, md.Name),
		}
		for _, device := range md.Devices {
			if device.Faulty {
				raid.FailedDevices = append(raid.FailedDevices, device.Name)
			}
		}
		result = append(result, raid)
	}
	return result, nil
}

// readMdMetadataVersion returns the metadata version of an md device or an empty string if it is not available
func readMdMetadataVersion(sysPath, name string) string {
	data, err := os.ReadFile(filepath.Join(sysPath, "block", name, "md", "metadata_version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func getOomKills(procPath string) (*resultOomKills, error) {
	data, err := os.ReadFile(filepath.Join(procPath, "vmstat"))
	if err != nil {
		return nil, err
	}

	var total uint64
	found := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "oom_kill" {
			if total, err = strconv.ParseUint(fields[1], 10, 64); err != nil {
				return nil, fmt.Errorf("could not parse oom_kill of /proc/vmstat: %s", err)
			}
			found = true
			break
		}
	}
	if !found {
		// oom_kill is available since Linux 4.13
		return nil, fmt.Errorf("oom_kill counter not available in /proc/vmstat")
	}

	oomKillStateMutex.Lock()
	defer oomKillStateMutex.Unlock()

	now := time.Now()
	if oomKillState == nil {
		// First run: OOM kills which happened before the agent started can not be assigned to a point in time
		oomKillState = &oomKillCounterState{lastTotal: total}
	} else if total > oomKillState.lastTotal {
		oomKillState.events = append(oomKillState.events, &resultOomKillEvent{
			Timestamp: now.Unix(),
			Count:     total - oomKillState.lastTotal,
		})
	}
	// The counter gets reset on reboot
	oomKillState.lastTotal = total

	retentionStart := now.Add(-oomKillEventRetention).Unix()
	for len(oomKillState.events) > 0 && oomKillState.events[0].Timestamp < retentionStart {
		oomKillState.events = oomKillState.events[1:]
	}

	return &resultOomKills{
		Total:  total,
		Events: append([]*resultOomKillEvent{}, oomKillState.events...),
	}, nil
}

func getFileDescriptors(procPath string) (*resultFileDescriptors, error) {
	// Format: <allocated> <allocated but unused (always 0 since Linux 2.6)> <max>
	values, err := readUintFields(filepath.Join(procPath, "sys", "fs", "file-nr"), 3)
	if err != nil {
		return nil, err
	}

	result := &resultFileDescriptors{
		Max: values[2],
	}
	if values[1] <= values[0] {
		result.Used = values[0] - values[1]
	}
	if result.Max > 0 {
		result.Percent = float64(result.Used) / float64(result.Max) * 100
	}
	return result, nil
}

func getConntrack(procPath string) (*resultConntrack, error) {
	count, err := readUintFields(filepath.Join(procPath, "sys", "net", "netfilter", "nf_conntrack_count"), 1)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &resultConntrack{Available: false}, nil
		}
		return nil, err
	}
	max, err := readUintFields(filepath.Join(procPath, "sys", "net", "netfilter", "nf_conntrack_max"), 1)
	if err != nil {
		return nil, err
	}

	result := &resultConntrack{
		Available: true,
		Count:     count[0],
		Max:       max[0],
	}
	if result.Max > 0 {
		result.Percent = float64(result.Count) / float64(result.Max) * 100
	}
	return result, nil
}

func getPressure(proc procfs.FS) (*resultPressure, error) {
	result := &resultPressure{
		Resources: map[string]*resultPressureResource{},
	}

	for _, resource := range []string{"cpu", "memory", "io"} {
		stats, err := proc.PSIStatsForResource(resource)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Kernel without PSI support (< 4.20, CONFIG_PSI=n or psi=0)
				return &resultPressure{Available: false, Resources: map[string]*resultPressureResource{}}, nil
			}
			return nil, err
		}
		result.Resources[resource] = &resultPressureResource{
			Some: toPressureLine(stats.Some),
			Full: toPressureLine(stats.Full),
		}
	}
	result.Available = true
	return result, nil
}

func toPressureLine(line *procfs.PSILine) *resultPressureLine {
	if line == nil {
		return nil
	}
	return &resultPressureLine{
		Avg10:  line.Avg10,
		Avg60:  line.Avg60,
		Avg300: line.Avg300,
	}
}

// readUintFields reads a file which contains at least n whitespace separated unsigned integers
func readUintFields(path string, n int) ([]uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < n {
		return nil, fmt.Errorf("unexpected content of %s: %q", path, string(data))
	}

	values := make([]uint64, n)
	for i := 0; i < n; i++ {
		if values[i], err = strconv.ParseUint(fields[i], 10, 64); err != nil {
			return nil, fmt.Errorf("could not parse %s: %s", path, err)
		}
	}
	return values, nil
}
