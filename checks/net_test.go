package checks

import (
	"context"
	"testing"
)

func TestChecksNet(t *testing.T) {
	check := &CheckNet{}
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results, ok := cr.(map[string]*resultNet)
	if !ok {
		t.Fatalf("unexpected result type %T", cr)
	}
	if len(results) == 0 {
		t.Fatal("there should be at least one network interface")
	}

	for name, nic := range results {
		if name == "" {
			t.Error("empty interface name")
		}
		// The speed is 0 or -1 if it is unknown (e.g. virtual interfaces or macOS)
		if nic.Speed < -1 || nic.MTU < 0 || nic.Duplex < 0 || nic.Duplex > 2 {
			t.Errorf("interface %s: invalid values %+v", name, nic)
		}
	}
}
