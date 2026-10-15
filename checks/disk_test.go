package checks

import (
	"context"
	"math"
	"testing"
)

// The test verifies the values of all filesystems. It does not fail on a full disk of the system running the test.
func TestChecksCheckDisk(t *testing.T) {
	check := &CheckDisk{}
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results, ok := cr.([]*resultDisk)
	if !ok {
		t.Fatalf("unexpected result type %T", cr)
	}
	if len(results) == 0 {
		t.Fatal("no filesystems found")
	}

	for _, result := range results {
		if result.Disk.Mountpoint == "" {
			t.Errorf("filesystem %s: empty mountpoint", result.Disk.Device)
		}
		usage := result.Usage
		if math.IsNaN(usage.Percent) || usage.Percent < 0 || usage.Percent > 100 {
			t.Errorf("filesystem %s: invalid usage %v%%", result.Disk.Mountpoint, usage.Percent)
		}
		if usage.Used > usage.Total || usage.Free > usage.Total {
			t.Errorf("filesystem %s: used %d or free %d is larger than total %d", result.Disk.Mountpoint, usage.Used, usage.Free, usage.Total)
		}
	}
}
