package checks

import (
	"context"
	"math"
	"testing"
	"time"
)

// The rates of the disk IO check are calculated between two check runs. The test does not rely on IO activity
// of the system (an idle disk is valid), it verifies the values of both runs instead.
func TestChecksCheckDiskIO(t *testing.T) {
	check := &CheckDiskIo{}

	first := runDiskIoCheck(t, check)
	// The interval is calculated in seconds
	time.Sleep(1100 * time.Millisecond)
	second := runDiskIoCheck(t, check)

	if len(second) == 0 {
		t.Skip("no disks with IO statistics found (e.g. a container without block devices)")
	}

	for name, result := range second {
		if result.Device == "" {
			t.Errorf("disk %s: empty device name", name)
		}
		if math.IsNaN(result.LoadPercent) || result.LoadPercent < 0 || result.LoadPercent > 100 {
			t.Errorf("disk %s: invalid load %v", name, result.LoadPercent)
		}
		for field, value := range map[string]float64{
			"TotalAvgWait": result.TotalAvgWait,
			"ReadAvgWait":  result.ReadAvgWait,
			"WriteAvgWait": result.WriteAvgWait,
			"ReadAvgSize":  result.ReadAvgSize,
			"WriteAvgSize": result.WriteAvgSize,
		} {
			if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
				t.Errorf("disk %s: invalid %s %v", name, field, value)
			}
		}

		previous, ok := first[name]
		if !ok {
			continue
		}
		// The counters of the operating system never decrease (except an overflow, which is unrealistic within a second)
		if result.ReadCount < previous.ReadCount || result.WriteCount < previous.WriteCount {
			t.Errorf("disk %s: counters decreased: reads %d -> %d, writes %d -> %d", name, previous.ReadCount, result.ReadCount, previous.WriteCount, result.WriteCount)
		}
		if result.Timestamp < previous.Timestamp {
			t.Errorf("disk %s: timestamp decreased: %d -> %d", name, previous.Timestamp, result.Timestamp)
		}
	}
}

func runDiskIoCheck(t *testing.T, check *CheckDiskIo) map[string]*resultDiskIo {
	t.Helper()
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results, ok := cr.(map[string]*resultDiskIo)
	if !ok {
		t.Fatalf("unexpected result type %T", cr)
	}
	return results
}
