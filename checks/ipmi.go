//go:build linux || windows
// +build linux windows

package checks

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bougou/go-ipmi/pkg/client"
	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
	log "github.com/sirupsen/logrus"
)

const (
	ipmiDefaultInterval  = 60
	ipmiMinInterval      = 10
	ipmiDefaultSelWindow = 86400
	// The collector stops if the check was not executed for this time (e.g. disabled by a reload)
	ipmiIdleTimeout = 10 * time.Minute
)

// newIpmiClient creates the client for the local BMC
func newIpmiClient() (*client.Client, error) {
	c, err := client.NewOpenClient()
	if err != nil {
		return nil, err
	}
	// Windows: only the WMI COM interface. The PowerShell fallback of go-ipmi starts powershell.exe for every command,
	// which would be several hundred processes per collection. No effect on Linux.
	return c.WithOpenBackend(client.OpenBackendCOM), nil
}

// CheckIpmi monitors the local BMC through the system interface (in-band): sensors, chassis status and SEL.
// The BMC is queried by a background collector, as reading all sensors of a slow BMC can take several seconds.
type CheckIpmi struct {
	interval  time.Duration
	selWindow time.Duration
}

// Name will be used in the response as check name
func (c *CheckIpmi) Name() string {
	return "ipmi"
}

type ipmiCollector struct {
	newClient  func() (*client.Client, error) // nil: newIpmiClient
	mutex      sync.Mutex
	key        string
	interval   time.Duration
	reader     *ipmiReader
	result     *resultIpmi
	lastError  string
	lastAccess time.Time
	stop       chan struct{}
	stopOnce   sync.Once
}

var ipmiState = struct {
	sync.Mutex
	collector *ipmiCollector
}{}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckIpmi) Run(_ context.Context) (interface{}, error) {
	ipmiState.Lock()
	defer ipmiState.Unlock()

	// Run without Configure (e.g. tests): a collector without interval would query the BMC without pause
	if c.interval <= 0 {
		c.interval = ipmiDefaultInterval * time.Second
	}
	if c.selWindow <= 0 {
		c.selWindow = ipmiDefaultSelWindow * time.Second
	}

	key := fmt.Sprintf("%d|%d", c.interval, c.selWindow)
	if ipmiState.collector != nil && ipmiState.collector.key != key {
		ipmiState.collector.close()
		ipmiState.collector = nil
	}
	if ipmiState.collector == nil {
		ipmiState.collector = &ipmiCollector{
			key:        key,
			interval:   c.interval,
			reader:     newIpmiReader(c.selWindow),
			lastAccess: time.Now(),
			stop:       make(chan struct{}),
		}
		go ipmiState.collector.run()
	}
	return ipmiState.collector.snapshot(), nil
}

// Configure the command or return false if the command was disabled
func (c *CheckIpmi) Configure(cfg *config.Configuration) (bool, error) {
	if !cfg.Ipmi || !ipmiAvailable() {
		return false, nil
	}
	c.interval = time.Duration(cfg.IpmiInterval) * time.Second
	if cfg.IpmiInterval <= 0 {
		c.interval = ipmiDefaultInterval * time.Second
	} else if cfg.IpmiInterval < ipmiMinInterval {
		c.interval = ipmiMinInterval * time.Second
	}
	c.selWindow = time.Duration(cfg.IpmiSelWindow) * time.Second
	if cfg.IpmiSelWindow <= 0 {
		c.selWindow = ipmiDefaultSelWindow * time.Second
	}
	return true, nil
}

// snapshot returns the latest result of the collector
func (r *ipmiCollector) snapshot() interface{} {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.lastAccess = time.Now()

	if r.lastError != "" {
		var collectedAt int64
		if r.result != nil {
			collectedAt = r.result.CollectedAt
		}
		return map[string]interface{}{"error": r.lastError, "collected_at": collectedAt}
	}
	if r.result == nil {
		return map[string]interface{}{"error": "waiting for the first collection", "pending": true}
	}
	return r.result
}

func (r *ipmiCollector) run() {
	for {
		r.collect()

		timer := time.NewTimer(r.interval)
		select {
		case <-r.stop:
			timer.Stop()
			return
		case <-timer.C:
		}

		r.mutex.Lock()
		idle := time.Since(r.lastAccess) > ipmiIdleTimeout
		r.mutex.Unlock()
		if idle {
			ipmiState.Lock()
			if ipmiState.collector == r {
				ipmiState.collector = nil
			}
			ipmiState.Unlock()
			return
		}
	}
}

func (r *ipmiCollector) collect() {
	// A collection must not take longer than the interval
	ctx, cancel := context.WithTimeout(context.Background(), r.interval)
	defer cancel()
	go func() {
		select {
		case <-r.stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	newClient := r.newClient
	if newClient == nil {
		newClient = newIpmiClient
	}
	result, err := protect("IPMI", func() (*resultIpmi, error) {
		return collectIpmi(ctx, newClient, r.reader)
	})
	var panicErr *panicError
	if errors.As(err, &panicErr) {
		// The cached SDRs and SEL entries could be incomplete after a panic
		r.reader = newIpmiReader(r.reader.selWindow)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()
	if err != nil {
		log.Debugln("IPMI: collection failed: ", err)
		r.lastError = err.Error()
		return
	}
	r.lastError = ""
	result.Interval = int64(r.interval.Seconds())
	r.result = result
}

func collectIpmi(ctx context.Context, newClient func() (*client.Client, error), reader *ipmiReader) (*resultIpmi, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		return nil, fmt.Errorf("could not connect to the BMC: %w", err)
	}
	defer c.Close(ctx)
	return reader.collect(ctx, c)
}

func (r *ipmiCollector) close() {
	r.stopOnce.Do(func() {
		close(r.stop)
	})
}
