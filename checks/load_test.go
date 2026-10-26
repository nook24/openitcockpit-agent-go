package checks

import (
	"context"
	"math"
	"testing"
)

// A load of 0 is valid on an idle system, so only the values are verified
func TestChecksCheckLoad(t *testing.T) {
	check := &CheckLoad{}
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, ok := cr.(*resultLoad)
	if !ok {
		t.Fatalf("unexpected result type %T", cr)
	}
	for name, value := range map[string]float64{"load1": result.Load1, "load5": result.Load5, "load15": result.Load15} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			t.Errorf("invalid %s: %v", name, value)
		}
	}
}
