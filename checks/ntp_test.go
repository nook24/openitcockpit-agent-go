package checks

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestChecksCheckNtp(t *testing.T) {
	check := &CheckNtp{}
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, ok := cr.(*resultNtp)
	if !ok {
		t.Fatalf("unexpected result type %T", cr)
	}

	// The timestamps are used by openITCOCKPIT to compare the clocks, if the system is not synchronized
	now := time.Now()
	if diff := now.Unix() - result.Timestamp; diff < -5 || diff > 5 {
		t.Errorf("unexpected timestamp %d (now %d)", result.Timestamp, now.Unix())
	}
	if diff := now.UnixMicro() - result.TimestampMicro; diff < -5e6 || diff > 5e6 {
		t.Errorf("unexpected timestamp in microseconds %d (now %d)", result.TimestampMicro, now.UnixMicro())
	}
	if math.IsNaN(result.Offset) || math.IsInf(result.Offset, 0) {
		t.Errorf("invalid offset %v", result.Offset)
	}
}
