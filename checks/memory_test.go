package checks

import (
	"context"
	"math"
	"testing"
)

func TestCheckMemory(t *testing.T) {
	check := &CheckMem{}
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, ok := cr.(*resultMemory)
	if !ok {
		t.Fatalf("unexpected result type %T", cr)
	}
	if result.Total == 0 {
		t.Fatal("total memory is 0")
	}
	if math.IsNaN(result.Percent) || result.Percent <= 0 || result.Percent > 100 {
		t.Errorf("invalid memory usage %v%%", result.Percent)
	}
	if result.Used > result.Total || result.Available > result.Total {
		t.Errorf("used %d or available %d is larger than total %d", result.Used, result.Available, result.Total)
	}
}
