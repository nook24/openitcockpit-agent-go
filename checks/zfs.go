package checks

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

// The commands are executed with LC_ALL=C, as zpool translates its messages
var zfsCommandEnv = []string{"LC_ALL=C", "LANG=C"}

const (
	zfsCommandTimeout = 20 * time.Second
	zfsArcStatsPath   = "/proc/spl/kstat/zfs/arcstats"
)

// The ARC counters of the last check run, to calculate the hit ratio of the check interval
var (
	zfsArcMutex      sync.Mutex
	zfsArcLastHits   uint64
	zfsArcLastMisses uint64
)

// CheckZfs gathers the state of ZFS pools and the ARC (Adaptive Replacement Cache) on Linux and FreeBSD
type CheckZfs struct {
	// can be changed by tests
	arcStatsPath string
}

// Name will be used in the response as check name
func (c *CheckZfs) Name() string {
	return "zfs"
}

type resultZfsScan struct {
	Function        string  `json:"function"`         // scrub, resilver or none
	State           string  `json:"state"`            // finished, in_progress, canceled, paused or none
	StartTime       int64   `json:"start_time"`       // Unix timestamp, in_progress only
	EndTime         int64   `json:"end_time"`         // Unix timestamp, finished or canceled only
	Errors          int64   `json:"errors"`           // Errors of the last finished scan
	Repaired        string  `json:"repaired"`         // e.g.: 0B or 128K
	ProgressPercent float64 `json:"progress_percent"` // in_progress only
	Description     string  `json:"description"`      // The scan line of zpool status
}

type resultZfsDevice struct {
	Name           string `json:"name"`  // e.g.: rpool, mirror-0, ata-Samsung_SSD_870_EVO_1TB_S6PTNX0R123456A-part3
	State          string `json:"state"` // e.g.: ONLINE, DEGRADED, FAULTED, OFFLINE, UNAVAIL, REMOVED, AVAIL (spare)
	ReadErrors     int64  `json:"read_errors"`
	WriteErrors    int64  `json:"write_errors"`
	ChecksumErrors int64  `json:"checksum_errors"`
	Depth          int    `json:"depth"`  // 0 = pool or section (logs, cache, spares, ...), 1 = vdev, 2+ = devices
	Status         string `json:"status"` // Additional information, e.g.: (resilvering) or was /dev/sdb1
}

type resultZfsPool struct {
	Name          string  `json:"name"`
	Health        string  `json:"health"` // ONLINE, DEGRADED, FAULTED, OFFLINE, UNAVAIL, REMOVED or SUSPENDED
	Size          int64   `json:"size"`   // Bytes
	Allocated     int64   `json:"allocated"`
	Free          int64   `json:"free"`
	Capacity      float64 `json:"capacity"`      // Used capacity in percent
	Fragmentation float64 `json:"fragmentation"` // Percent, -1 if not available
	DedupRatio    float64 `json:"dedup_ratio"`

	// zpool status
	Status     string             `json:"status"` // Description of a problem, empty if the pool is healthy
	Action     string             `json:"action"` // Recommended action, empty if the pool is healthy
	Scan       *resultZfsScan     `json:"scan"`
	DataErrors int64              `json:"data_errors"` // Permanent errors in files, -1 if unknown
	Devices    []*resultZfsDevice `json:"devices"`
}

type resultZfsArc struct {
	Size          uint64  `json:"size"`            // Current size of the ARC in bytes
	TargetSize    uint64  `json:"target_size"`     // Target size (c)
	MinSize       uint64  `json:"min_size"`        // c_min
	MaxSize       uint64  `json:"max_size"`        // c_max
	Hits          uint64  `json:"hits"`            // Since boot
	Misses        uint64  `json:"misses"`          // Since boot
	HitRatio      float64 `json:"hit_ratio"`       // Percent within the last check interval, -1 on the first run
	HitRatioTotal float64 `json:"hit_ratio_total"` // Percent since boot
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckZfs) Run(ctx context.Context) (interface{}, error) {
	result := map[string]interface{}{}

	if pools, err := getZfsPools(ctx); err != nil {
		result["pools"] = map[string]string{"error": err.Error()}
	} else {
		result["pools"] = pools
	}

	if values, err := c.readArcStats(ctx); err != nil {
		result["arc"] = map[string]string{"error": err.Error()}
	} else {
		result["arc"] = getZfsArc(values)
	}

	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckZfs) Configure(config *config.Configuration) (bool, error) {
	if !config.Zfs {
		return false, nil
	}
	// Only enable the check on systems with ZFS
	_, err := exec.LookPath("zpool")
	return err == nil, nil
}

func runZfsCommand(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, zfsCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), zfsCommandEnv...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s failed: %s: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func getZfsPools(ctx context.Context) ([]*resultZfsPool, error) {
	listOutput, err := runZfsCommand(ctx, "zpool", "list", "-Hp", "-o", "name,size,allocated,free,fragmentation,capacity,health,dedupratio")
	if err != nil {
		return nil, err
	}
	pools, err := parseZpoolList(listOutput)
	if err != nil || len(pools) == 0 {
		return pools, err
	}

	statusOutput, err := runZfsCommand(ctx, "zpool", "status", "-p")
	if err != nil {
		return nil, err
	}
	statuses := parseZpoolStatus(statusOutput, time.Local)
	for _, pool := range pools {
		if status, ok := statuses[pool.Name]; ok {
			pool.Status = status.Status
			pool.Action = status.Action
			pool.Scan = status.Scan
			pool.DataErrors = status.DataErrors
			pool.Devices = status.Devices
		}
	}
	return pools, nil
}

// parseZpoolList parses the output of "zpool list -Hp -o name,size,allocated,free,fragmentation,capacity,health,dedupratio"
func parseZpoolList(output string) ([]*resultZfsPool, error) {
	pools := []*resultZfsPool{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "no pools available") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			return nil, fmt.Errorf("unexpected output of zpool list: %q", line)
		}
		pool := &resultZfsPool{
			Name:          fields[0],
			Size:          parseZfsInt(fields[1]),
			Allocated:     parseZfsInt(fields[2]),
			Free:          parseZfsInt(fields[3]),
			Fragmentation: parseZfsPercent(fields[4]),
			Capacity:      parseZfsPercent(fields[5]),
			Health:        fields[6],
			DedupRatio:    parseZfsPercent(strings.TrimSuffix(fields[7], "x")),
			DataErrors:    -1,
			Devices:       []*resultZfsDevice{},
			Scan:          &resultZfsScan{Function: "none", State: "none"},
		}
		pools = append(pools, pool)
	}
	return pools, scanner.Err()
}

func parseZfsInt(value string) int64 {
	number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}
	return number
}

// parseZfsPercent parses values like "12", "12%" or "1.00". Returns -1 for "-" (not available)
func parseZfsPercent(value string) float64 {
	value = strings.TrimSuffix(strings.TrimSpace(value), "%")
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return -1
	}
	return number
}

// parseZfsCount parses error counters. zpool status abbreviates large numbers like 1.2K without -p
func parseZfsCount(value string) int64 {
	value = strings.TrimSpace(value)
	multiplier := 1.0
	switch {
	case strings.HasSuffix(value, "K"):
		multiplier = 1e3
	case strings.HasSuffix(value, "M"):
		multiplier = 1e6
	case strings.HasSuffix(value, "G"):
		multiplier = 1e9
	}
	value = strings.TrimRight(value, "KMG")
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return int64(math.Round(number * multiplier))
}

var (
	zfsScanFinishedRegexp   = regexp.MustCompile(`^(scrub|resilver)(?:ed)?(?: repaired)? (\S+) in (\S+) with (\d+) errors on (.+)$`)
	zfsScanInProgressRegexp = regexp.MustCompile(`^(scrub|resilver) in progress since (.+)$`)
	zfsScanCanceledRegexp   = regexp.MustCompile(`^(scrub|resilver) canceled on (.+)$`)
	zfsScanPausedRegexp     = regexp.MustCompile(`^(scrub|resilver) paused since (.+)$`)
	zfsScanProgressRegexp   = regexp.MustCompile(`([\d.]+)% done`)
	zfsDataErrorsRegexp     = regexp.MustCompile(`^(\d+) data errors`)
)

// zfs uses the format of ctime(3), e.g.: Sun Oct 12 00:25:24 2025
const zfsTimeLayout = "Mon Jan _2 15:04:05 2006"

// parseZpoolStatus parses the output of "zpool status -p" for all pools
func parseZpoolStatus(output string, location *time.Location) map[string]*resultZfsPool {
	pools := map[string]*resultZfsPool{}
	var pool *resultZfsPool
	section := ""

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimRight(rawLine, " \t\r")
		trimmed := strings.TrimSpace(line)
		key, value, hasKey := strings.Cut(trimmed, ":")
		isHeader := hasKey && !strings.HasPrefix(line, "\t") && !strings.Contains(key, " ")

		if isHeader {
			value = strings.TrimSpace(value)
			switch key {
			case "pool":
				pool = &resultZfsPool{
					Name:       value,
					DataErrors: -1,
					Devices:    []*resultZfsDevice{},
					Scan:       &resultZfsScan{Function: "none", State: "none"},
				}
				pools[value] = pool
				section = ""
				continue
			case "state", "status", "action", "see", "scan", "config", "errors", "remove", "checkpoint", "expand":
				section = key
				if pool == nil {
					continue
				}
				switch key {
				case "status":
					pool.Status = value
				case "action":
					pool.Action = value
				case "scan":
					parseZfsScanLine(pool.Scan, value, location)
				case "errors":
					pool.DataErrors = parseZfsDataErrors(value)
				}
				continue
			}
		}

		if pool == nil || trimmed == "" {
			continue
		}

		switch section {
		case "status":
			pool.Status += " " + trimmed
		case "action":
			pool.Action += " " + trimmed
		case "scan":
			// Progress lines of a running scrub or resilver
			pool.Scan.Description += "; " + trimmed
			if match := zfsScanProgressRegexp.FindStringSubmatch(trimmed); match != nil {
				pool.Scan.ProgressPercent, _ = strconv.ParseFloat(match[1], 64)
			}
		case "config":
			if device := parseZfsDeviceLine(line); device != nil {
				pool.Devices = append(pool.Devices, device)
			}
		}
	}
	return pools
}

func parseZfsScanLine(scan *resultZfsScan, value string, location *time.Location) {
	scan.Description = value
	parseTime := func(value string) int64 {
		t, err := time.ParseInLocation(zfsTimeLayout, strings.TrimSpace(value), location)
		if err != nil {
			return 0
		}
		return t.Unix()
	}

	switch {
	case value == "none requested":
	case zfsScanFinishedRegexp.MatchString(value):
		match := zfsScanFinishedRegexp.FindStringSubmatch(value)
		scan.Function, scan.State = match[1], "finished"
		scan.Repaired = match[2]
		scan.Errors, _ = strconv.ParseInt(match[4], 10, 64)
		scan.EndTime = parseTime(match[5])
		scan.ProgressPercent = 100
	case zfsScanInProgressRegexp.MatchString(value):
		match := zfsScanInProgressRegexp.FindStringSubmatch(value)
		scan.Function, scan.State = match[1], "in_progress"
		scan.StartTime = parseTime(match[2])
	case zfsScanCanceledRegexp.MatchString(value):
		match := zfsScanCanceledRegexp.FindStringSubmatch(value)
		scan.Function, scan.State = match[1], "canceled"
		scan.EndTime = parseTime(match[2])
	case zfsScanPausedRegexp.MatchString(value):
		match := zfsScanPausedRegexp.FindStringSubmatch(value)
		scan.Function, scan.State = match[1], "paused"
		scan.StartTime = parseTime(match[2])
	}
}

func parseZfsDataErrors(value string) int64 {
	if value == "No known data errors" {
		return 0
	}
	if match := zfsDataErrorsRegexp.FindStringSubmatch(value); match != nil {
		count, _ := strconv.ParseInt(match[1], 10, 64)
		return count
	}
	return -1
}

// parseZfsDeviceLine parses a line of the config section, e.g.:
// "\t    ata-Samsung_SSD_870_EVO_1TB_S6PTNX0R123456A-part3  ONLINE       0     0     0"
func parseZfsDeviceLine(line string) *resultZfsDevice {
	if !strings.HasPrefix(line, "\t") {
		return nil
	}
	content := strings.TrimPrefix(line, "\t")
	indent := len(content) - len(strings.TrimLeft(content, " "))
	fields := strings.Fields(content)
	if len(fields) == 0 || fields[0] == "NAME" {
		return nil
	}

	device := &resultZfsDevice{
		Name:  fields[0],
		Depth: indent / 2,
	}
	// Section headers like "logs", "cache", "spares" or "special" have no state
	if len(fields) >= 2 {
		device.State = fields[1]
	}
	if len(fields) >= 5 {
		device.ReadErrors = parseZfsCount(fields[2])
		device.WriteErrors = parseZfsCount(fields[3])
		device.ChecksumErrors = parseZfsCount(fields[4])
		if len(fields) > 5 {
			device.Status = strings.Join(fields[5:], " ")
		}
	} else if len(fields) > 2 {
		device.Status = strings.Join(fields[2:], " ")
	}
	return device
}

// readArcStats returns the ARC statistics: Linux provides a kstat file, FreeBSD provides sysctls with the same names
func (c *CheckZfs) readArcStats(ctx context.Context) (map[string]uint64, error) {
	if runtime.GOOS == "freebsd" && c.arcStatsPath == "" {
		output, err := runZfsCommand(ctx, "sysctl", "-e", "kstat.zfs.misc.arcstats")
		if err != nil {
			return nil, err
		}
		return parseSysctlArcstats(output), nil
	}

	path := c.arcStatsPath
	if path == "" {
		path = zfsArcStatsPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseKstat(string(data)), nil
}

// parseSysctlArcstats parses the output of "sysctl -e kstat.zfs.misc.arcstats" of FreeBSD, e.g.:
// kstat.zfs.misc.arcstats.hits=100963
func parseSysctlArcstats(output string) map[string]uint64 {
	const prefix = "kstat.zfs.misc.arcstats."
	values := map[string]uint64{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !ok || !strings.HasPrefix(key, prefix) {
			continue
		}
		if number, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64); err == nil {
			values[strings.TrimPrefix(key, prefix)] = number
		}
	}
	return values
}

// getZfsArc calculates the ARC statistics. The hit ratio is calculated for the time since the last check run
func getZfsArc(values map[string]uint64) *resultZfsArc {
	arc := &resultZfsArc{
		Size:       values["size"],
		TargetSize: values["c"],
		MinSize:    values["c_min"],
		MaxSize:    values["c_max"],
		Hits:       values["hits"],
		Misses:     values["misses"],
		HitRatio:   -1,
	}
	arc.HitRatioTotal = hitRatio(arc.Hits, arc.Misses)

	zfsArcMutex.Lock()
	defer zfsArcMutex.Unlock()
	if zfsArcLastHits > 0 && arc.Hits >= zfsArcLastHits && arc.Misses >= zfsArcLastMisses {
		arc.HitRatio = hitRatio(arc.Hits-zfsArcLastHits, arc.Misses-zfsArcLastMisses)
	}
	zfsArcLastHits, zfsArcLastMisses = arc.Hits, arc.Misses
	return arc
}

func hitRatio(hits, misses uint64) float64 {
	if hits+misses == 0 {
		return 100
	}
	return float64(hits) / float64(hits+misses) * 100
}

// parseKstat parses the kstat format of ZFS on Linux:
// 13 1 0x01 147 39984 4237475373 2398732827873
// name                            type data
// hits                            4    1234567
func parseKstat(content string) map[string]uint64 {
	values := map[string]uint64{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || fields[0] == "name" {
			continue
		}
		if value, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
			values[fields[0]] = value
		}
	}
	return values
}
