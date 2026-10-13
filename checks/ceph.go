package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

const (
	cephConfigPath = "/etc/ceph/ceph.conf"
	// Seconds the ceph command waits for a monitor
	cephConnectTimeout = "10"
	cephCommandTimeout = 20 * time.Second
)

// CheckCeph gathers the state of a Ceph cluster with the ceph command line tool.
// On Proxmox VE every node with Ceph installed has access to the cluster.
type CheckCeph struct {
}

// Name will be used in the response as check name
func (c *CheckCeph) Name() string {
	return "ceph"
}

type resultCephHealthCheck struct {
	Code     string `json:"code"`     // e.g.: OSD_DOWN, PG_DEGRADED, MON_DOWN
	Severity string `json:"severity"` // HEALTH_WARN or HEALTH_ERR
	Message  string `json:"message"`  // e.g.: 1 osds down
	Count    int64  `json:"count"`
	Muted    bool   `json:"muted"` // Muted with "ceph health mute"
}

type resultCephHealth struct {
	Status string                   `json:"status"` // HEALTH_OK, HEALTH_WARN or HEALTH_ERR
	Checks []*resultCephHealthCheck `json:"checks"`
}

type resultCephMonitors struct {
	Total       int64    `json:"total"`
	InQuorum    int64    `json:"in_quorum"`
	QuorumNames []string `json:"quorum_names"`
}

type resultCephOsds struct {
	Total int64 `json:"total"`
	Up    int64 `json:"up"`
	In    int64 `json:"in"`
}

type resultCephPgs struct {
	Total  int64            `json:"total"`
	States map[string]int64 `json:"states"` // e.g.: active+clean: 128
}

type resultCephUsage struct {
	TotalBytes     int64   `json:"total_bytes"`
	UsedBytes      int64   `json:"used_bytes"` // Raw usage of all OSDs
	AvailableBytes int64   `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type resultCephIo struct {
	ReadBytesPerSecond  int64 `json:"read_bytes_sec"`
	WriteBytesPerSecond int64 `json:"write_bytes_sec"`
	ReadOpsPerSecond    int64 `json:"read_op_per_sec"`
	WriteOpsPerSecond   int64 `json:"write_op_per_sec"`
}

type resultCephPool struct {
	Name          string  `json:"name"`
	ID            int64   `json:"id"`
	StoredBytes   int64   `json:"stored_bytes"` // Data stored by the clients
	UsedBytes     int64   `json:"used_bytes"`   // Raw usage including replicas
	UsedPercent   float64 `json:"used_percent"`
	MaxAvailBytes int64   `json:"max_avail_bytes"` // Data which can be stored until the first OSD is full
	Objects       int64   `json:"objects"`
}

type resultCephMds struct {
	Name       string `json:"name"`
	Filesystem string `json:"filesystem"`
	Rank       int64  `json:"rank"`
	State      string `json:"state"` // e.g.: up:active, up:replay
}

type resultCephFilesystems struct {
	Up      int64            `json:"up"`  // Active MDS ranks
	In      int64            `json:"in"`  // MDS ranks
	Max     int64            `json:"max"` // Configured MDS ranks
	Standby int64            `json:"standby"`
	Mds     []*resultCephMds `json:"mds"`
}

// Subset of "ceph status -f json"
type cephStatusJSON struct {
	Health struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Severity string `json:"severity"`
			Summary  struct {
				Message string `json:"message"`
				Count   int64  `json:"count"`
			} `json:"summary"`
			Muted bool `json:"muted"`
		} `json:"checks"`
	} `json:"health"`
	QuorumNames []string `json:"quorum_names"`
	Monmap      struct {
		NumMons int64             `json:"num_mons"`
		Mons    []json.RawMessage `json:"mons"` // Ceph < 15
	} `json:"monmap"`
	Osdmap json.RawMessage `json:"osdmap"`
	Pgmap  struct {
		PgsByState []struct {
			StateName string `json:"state_name"`
			Count     int64  `json:"count"`
		} `json:"pgs_by_state"`
		NumPgs        int64 `json:"num_pgs"`
		BytesUsed     int64 `json:"bytes_used"`
		BytesAvail    int64 `json:"bytes_avail"`
		BytesTotal    int64 `json:"bytes_total"`
		ReadBytesSec  int64 `json:"read_bytes_sec"`
		WriteBytesSec int64 `json:"write_bytes_sec"`
		ReadOpPerSec  int64 `json:"read_op_per_sec"`
		WriteOpPerSec int64 `json:"write_op_per_sec"`
	} `json:"pgmap"`
	Fsmap struct {
		Up     int64 `json:"up"`
		In     int64 `json:"in"`
		Max    int64 `json:"max"`
		ByRank []struct {
			FilesystemID int64  `json:"filesystem_id"`
			Rank         int64  `json:"rank"`
			Name         string `json:"name"`
			Status       string `json:"status"`
		} `json:"by_rank"`
		Standby int64 `json:"up:standby"`
	} `json:"fsmap"`
}

type cephOsdmapJSON struct {
	NumOsds   int64 `json:"num_osds"`
	NumUpOsds int64 `json:"num_up_osds"`
	NumInOsds int64 `json:"num_in_osds"`
}

// Subset of "ceph df -f json"
type cephDfJSON struct {
	Stats struct {
		TotalBytes     int64   `json:"total_bytes"`
		TotalAvail     int64   `json:"total_avail_bytes"`
		TotalUsedRaw   int64   `json:"total_used_raw_bytes"`
		TotalUsedRatio float64 `json:"total_used_raw_ratio"`
	} `json:"stats"`
	Pools []struct {
		Name  string `json:"name"`
		ID    int64  `json:"id"`
		Stats struct {
			Stored      int64   `json:"stored"`
			BytesUsed   int64   `json:"bytes_used"`
			PercentUsed float64 `json:"percent_used"` // Ratio between 0 and 1
			MaxAvail    int64   `json:"max_avail"`
			Objects     int64   `json:"objects"`
		} `json:"stats"`
	} `json:"pools"`
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckCeph) Run(ctx context.Context) (interface{}, error) {
	statusOutput, err := runCephCommand(ctx, "status")
	if err != nil {
		return nil, err
	}
	result, err := parseCephStatus(statusOutput)
	if err != nil {
		return nil, err
	}

	// The pools are optional, an error is only reported for this part
	if dfOutput, err := runCephCommand(ctx, "df"); err != nil {
		result["pools"] = map[string]string{"error": err.Error()}
	} else if pools, usage, err := parseCephDf(dfOutput); err != nil {
		result["pools"] = map[string]string{"error": err.Error()}
	} else {
		result["pools"] = pools
		if usage.TotalBytes > 0 {
			// ceph df provides the raw usage ratio, which ceph status does not
			result["usage"] = usage
		}
	}
	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckCeph) Configure(config *config.Configuration) (bool, error) {
	if !config.Ceph {
		return false, nil
	}
	// Only enable the check on systems which are part of a Ceph cluster
	if _, err := exec.LookPath("ceph"); err != nil {
		return false, nil
	}
	if _, err := os.Stat(cephConfigPath); err != nil {
		return false, nil
	}
	return true, nil
}

func runCephCommand(ctx context.Context, command ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, cephCommandTimeout)
	defer cancel()

	args := append(command, "--format", "json", "--connect-timeout", cephConnectTimeout)
	cmd := exec.CommandContext(ctx, "ceph", args...)
	output, err := cmd.Output()
	if err != nil {
		var stderr string
		if exitError, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(exitError.Stderr))
		}
		// The ceph command prints "timed out" if no monitor answered within --connect-timeout
		if ctx.Err() != nil || stderr == "timed out" {
			return nil, fmt.Errorf("ceph %s: timeout, the monitors are not reachable", strings.Join(command, " "))
		}
		return nil, fmt.Errorf("ceph %s failed: %s: %s", strings.Join(command, " "), err, stderr)
	}
	return output, nil
}

func parseCephStatus(data []byte) (map[string]interface{}, error) {
	var status cephStatusJSON
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("could not parse ceph status: %s", err)
	}

	health := &resultCephHealth{Status: status.Health.Status, Checks: []*resultCephHealthCheck{}}
	for code, check := range status.Health.Checks {
		health.Checks = append(health.Checks, &resultCephHealthCheck{
			Code:     code,
			Severity: check.Severity,
			Message:  check.Summary.Message,
			Count:    check.Summary.Count,
			Muted:    check.Muted,
		})
	}
	sort.Slice(health.Checks, func(i, j int) bool {
		return health.Checks[i].Code < health.Checks[j].Code
	})

	monitors := &resultCephMonitors{
		Total:       status.Monmap.NumMons,
		InQuorum:    int64(len(status.QuorumNames)),
		QuorumNames: status.QuorumNames,
	}
	if monitors.Total == 0 {
		monitors.Total = int64(len(status.Monmap.Mons))
	}
	if monitors.QuorumNames == nil {
		monitors.QuorumNames = []string{}
	}

	osds, err := parseCephOsdmap(status.Osdmap)
	if err != nil {
		return nil, err
	}

	pgs := &resultCephPgs{Total: status.Pgmap.NumPgs, States: map[string]int64{}}
	for _, state := range status.Pgmap.PgsByState {
		pgs.States[state.StateName] = state.Count
	}

	usage := &resultCephUsage{
		TotalBytes:     status.Pgmap.BytesTotal,
		UsedBytes:      status.Pgmap.BytesUsed,
		AvailableBytes: status.Pgmap.BytesAvail,
	}
	if usage.TotalBytes > 0 {
		usage.UsedPercent = float64(usage.UsedBytes) / float64(usage.TotalBytes) * 100
	}

	filesystems := &resultCephFilesystems{
		Up:      status.Fsmap.Up,
		In:      status.Fsmap.In,
		Max:     status.Fsmap.Max,
		Standby: status.Fsmap.Standby,
		Mds:     []*resultCephMds{},
	}
	for _, mds := range status.Fsmap.ByRank {
		filesystems.Mds = append(filesystems.Mds, &resultCephMds{
			Name:       mds.Name,
			Filesystem: fmt.Sprintf("%d", mds.FilesystemID),
			Rank:       mds.Rank,
			State:      mds.Status,
		})
	}

	return map[string]interface{}{
		"health":      health,
		"monitors":    monitors,
		"osds":        osds,
		"pgs":         pgs,
		"usage":       usage,
		"filesystems": filesystems,
		"io": &resultCephIo{
			ReadBytesPerSecond:  status.Pgmap.ReadBytesSec,
			WriteBytesPerSecond: status.Pgmap.WriteBytesSec,
			ReadOpsPerSecond:    status.Pgmap.ReadOpPerSec,
			WriteOpsPerSecond:   status.Pgmap.WriteOpPerSec,
		},
	}, nil
}

// parseCephOsdmap supports the flat osdmap of Ceph >= 16 (Pacific) and the nested osdmap of older versions
func parseCephOsdmap(data json.RawMessage) (*resultCephOsds, error) {
	if len(data) == 0 {
		return &resultCephOsds{}, nil
	}

	var osdmap struct {
		cephOsdmapJSON
		Nested *cephOsdmapJSON `json:"osdmap"` // Ceph < 16
	}
	if err := json.Unmarshal(data, &osdmap); err != nil {
		return nil, fmt.Errorf("could not parse osdmap: %s", err)
	}
	values := osdmap.cephOsdmapJSON
	if osdmap.Nested != nil {
		values = *osdmap.Nested
	}
	return &resultCephOsds{Total: values.NumOsds, Up: values.NumUpOsds, In: values.NumInOsds}, nil
}

func parseCephDf(data []byte) ([]*resultCephPool, *resultCephUsage, error) {
	var df cephDfJSON
	if err := json.Unmarshal(data, &df); err != nil {
		return nil, nil, fmt.Errorf("could not parse ceph df: %s", err)
	}

	pools := []*resultCephPool{}
	for _, pool := range df.Pools {
		pools = append(pools, &resultCephPool{
			Name:          pool.Name,
			ID:            pool.ID,
			StoredBytes:   pool.Stats.Stored,
			UsedBytes:     pool.Stats.BytesUsed,
			UsedPercent:   pool.Stats.PercentUsed * 100,
			MaxAvailBytes: pool.Stats.MaxAvail,
			Objects:       pool.Stats.Objects,
		})
	}

	usage := &resultCephUsage{
		TotalBytes:     df.Stats.TotalBytes,
		UsedBytes:      df.Stats.TotalUsedRaw,
		AvailableBytes: df.Stats.TotalAvail,
		UsedPercent:    df.Stats.TotalUsedRatio * 100,
	}
	return pools, usage, nil
}
