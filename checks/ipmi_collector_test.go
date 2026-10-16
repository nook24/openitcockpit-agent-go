//go:build linux || windows
// +build linux windows

package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bougou/go-ipmi/pkg/client"
)

func TestIpmiCollectorPanic(t *testing.T) {
	collector := &ipmiCollector{
		newClient: func() (*client.Client, error) {
			panic("broken BMC data")
		},
		interval: time.Second,
		reader:   newIpmiReader(time.Hour),
		stop:     make(chan struct{}),
	}
	collector.collect()
	snapshot, ok := collector.snapshot().(map[string]interface{})
	if !ok || !strings.Contains(snapshot["error"].(string), "IPMI: internal error: broken BMC data") {
		t.Errorf("expected the panic as error, got %v", collector.snapshot())
	}
}

func TestCheckIpmiWithoutConfigure(t *testing.T) {
	// Run without Configure uses the default interval instead of querying the BMC without pause
	check := &CheckIpmi{}
	if _, err := check.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if check.interval != ipmiDefaultInterval*time.Second || check.selWindow != ipmiDefaultSelWindow*time.Second {
		t.Errorf("unexpected interval %s and window %s", check.interval, check.selWindow)
	}
	ipmiState.Lock()
	if ipmiState.collector != nil {
		ipmiState.collector.close()
		ipmiState.collector = nil
	}
	ipmiState.Unlock()
}
