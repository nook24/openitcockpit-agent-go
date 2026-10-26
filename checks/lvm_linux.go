package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

const lvmCommandTimeout = 20 * time.Second

// CheckLvm reports the usage of LVM thin pools. A full thin pool corrupts the filesystems of its thin volumes.
type CheckLvm struct {
	lvs string
}

// Name will be used in the response as check name
func (c *CheckLvm) Name() string {
	return "lvm"
}

type resultLvmThinPool struct {
	VG              string  `json:"vg"`               // Volume group, e.g.: pve
	Name            string  `json:"name"`             // e.g.: data
	SizeBytes       int64   `json:"size_bytes"`       // Size of the data volume
	DataPercent     float64 `json:"data_percent"`     // Usage of the data volume
	MetadataPercent float64 `json:"metadata_percent"` // Usage of the metadata volume
	Health          string  `json:"health"`           // Empty if healthy, e.g.: out_of_data, metadata_read_only, failed
	Active          bool    `json:"active"`
}

type resultLvm struct {
	ThinPools []*resultLvmThinPool `json:"thin_pools"`
}

// Subset of "lvs --reportformat json"
type lvsJSON struct {
	Report []struct {
		LV []struct {
			VGName          string `json:"vg_name"`
			LVName          string `json:"lv_name"`
			LVAttr          string `json:"lv_attr"`
			LVSize          string `json:"lv_size"`
			DataPercent     string `json:"data_percent"`
			MetadataPercent string `json:"metadata_percent"`
			LVHealthStatus  string `json:"lv_health_status"`
		} `json:"lv"`
	} `json:"report"`
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckLvm) Run(ctx context.Context) (interface{}, error) {
	lvs := c.lvs
	if lvs == "" {
		lvs = "lvs"
	}
	ctx, cancel := context.WithTimeout(ctx, lvmCommandTimeout)
	defer cancel()

	output, err := exec.CommandContext(ctx, lvs,
		"--reportformat", "json", "--units", "b", "--nosuffix",
		"-o", "vg_name,lv_name,lv_attr,lv_size,data_percent,metadata_percent,lv_health_status",
		"-S", "segtype=thin-pool",
	).Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("lvs: timeout after %s", lvmCommandTimeout)
		}
		var stderr string
		if exitError, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(exitError.Stderr))
		}
		return nil, fmt.Errorf("lvs failed: %s: %s", err, stderr)
	}
	return parseLvs(output)
}

// Configure the command or return false if the command was disabled
func (c *CheckLvm) Configure(cfg *config.Configuration) (bool, error) {
	if !cfg.Lvm {
		return false, nil
	}
	// Only enable the check on systems with LVM
	path, err := exec.LookPath("lvs")
	if err != nil {
		return false, nil
	}
	c.lvs = path
	return true, nil
}

func parseLvs(output []byte) (*resultLvm, error) {
	var report lvsJSON
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("could not parse the output of lvs: %s", err)
	}

	result := &resultLvm{ThinPools: []*resultLvmThinPool{}}
	for _, part := range report.Report {
		for _, lv := range part.LV {
			pool := &resultLvmThinPool{
				VG:     lv.VGName,
				Name:   lv.LVName,
				Health: strings.TrimSpace(lv.LVHealthStatus),
				// The 5th character of lv_attr is the state, a = active
				Active: len(lv.LVAttr) >= 5 && lv.LVAttr[4] == 'a',
			}
			pool.SizeBytes, _ = strconv.ParseInt(strings.TrimSpace(lv.LVSize), 10, 64)
			pool.DataPercent, _ = strconv.ParseFloat(strings.TrimSpace(lv.DataPercent), 64)
			pool.MetadataPercent, _ = strconv.ParseFloat(strings.TrimSpace(lv.MetadataPercent), 64)
			result.ThinPools = append(result.ThinPools, pool)
		}
	}
	return result, nil
}
