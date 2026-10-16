package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
	log "github.com/sirupsen/logrus"
)

const (
	// A collector stops if the check was not executed for this time (e.g. disabled by a reload)
	redfishIdleTimeout = 10 * time.Minute
)

// CheckRedfish monitors the hardware of servers with the Redfish API of their BMCs (redfish.ini).
// Every BMC is queried by a background collector, so slow BMCs do not delay the other checks.
type CheckRedfish struct {
	definitions []*config.RedfishDefinition
}

// Name will be used in the response as check name
func (c *CheckRedfish) Name() string {
	return "redfish"
}

// redfishCollector queries a single BMC in the background
type redfishCollector struct {
	mutex      sync.Mutex
	key        string
	def        *config.RedfishDefinition
	client     *redfishClient
	result     *resultRedfish
	lastError  string
	lastAccess time.Time
	stop       chan struct{}
	stopOnce   sync.Once
}

var redfishCollectors = struct {
	sync.Mutex
	collectors map[string]*redfishCollector
}{collectors: map[string]*redfishCollector{}}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckRedfish) Run(_ context.Context) (interface{}, error) {
	result := make(map[string]interface{}, len(c.definitions))
	active := make(map[string]bool, len(c.definitions))

	redfishCollectors.Lock()
	defer redfishCollectors.Unlock()

	for _, definition := range c.definitions {
		if definition.ConfigError != "" {
			result[definition.Name] = map[string]string{"error": definition.ConfigError}
			continue
		}
		key := redfishDefinitionKey(definition)
		active[key] = true
		collector, ok := redfishCollectors.collectors[key]
		if !ok {
			collector = &redfishCollector{
				key:        key,
				def:        definition,
				client:     newRedfishClient(definition),
				lastAccess: time.Now(),
				stop:       make(chan struct{}),
			}
			redfishCollectors.collectors[key] = collector
			go collector.run()
		}
		result[definition.Name] = collector.snapshot()
	}

	// Stop the collectors of removed or changed definitions
	for key, collector := range redfishCollectors.collectors {
		if !active[key] {
			collector.close()
			delete(redfishCollectors.collectors, key)
		}
	}
	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckRedfish) Configure(cfg *config.Configuration) (bool, error) {
	c.definitions = cfg.RedfishConfiguration
	return len(c.definitions) > 0, nil
}

// redfishDefinitionKey identifies a definition, so a changed definition starts a new collector
func redfishDefinitionKey(d *config.RedfishDefinition) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%t|%s|%t|%d|%d|%t|%d|%s|%s",
		d.Name, d.URL, d.Username, d.Password, d.SkipVerify, d.Fingerprint, d.AllowHTTP, d.Interval, d.Timeout,
		*d.Eventlog, d.EventlogWindow, d.EventlogServices, d.Proxy)))
	return d.Name + "|" + hex.EncodeToString(hash[:])
}

// snapshot returns the latest result of the collector
func (r *redfishCollector) snapshot() interface{} {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.lastAccess = time.Now()

	if r.lastError != "" {
		var collectedAt int64
		if r.result != nil {
			collectedAt = r.result.CollectedAt
		}
		return map[string]interface{}{"error": r.lastError, "collected_at": collectedAt, "url": r.def.URL}
	}
	if r.result == nil {
		return map[string]interface{}{"error": "waiting for the first collection", "pending": true, "url": r.def.URL}
	}
	return r.result
}

func (r *redfishCollector) run() {
	defer r.client.logout()
	for {
		r.collect()

		timer := time.NewTimer(time.Duration(r.def.Interval) * time.Second)
		select {
		case <-r.stop:
			timer.Stop()
			return
		case <-timer.C:
		}

		r.mutex.Lock()
		idle := time.Since(r.lastAccess) > redfishIdleTimeout
		r.mutex.Unlock()
		if idle {
			// The check is not executed anymore, e.g. it was disabled by a reload
			redfishCollectors.Lock()
			if redfishCollectors.collectors[r.key] == r {
				delete(redfishCollectors.collectors, r.key)
			}
			redfishCollectors.Unlock()
			return
		}
	}
}

func (r *redfishCollector) collect() {
	// A collection must not take longer than the interval
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.def.Interval)*time.Second)
	defer cancel()
	go func() {
		select {
		case <-r.stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	result, err := protect("Redfish "+r.def.Name, func() (*resultRedfish, error) {
		return collectRedfish(ctx, r.client, r.def, time.Now())
	})

	r.mutex.Lock()
	defer r.mutex.Unlock()
	if err != nil {
		log.Debugln("Redfish: collection of ", r.def.Name, " failed: ", err)
		r.lastError = err.Error()
		return
	}
	r.lastError = ""
	r.result = result
}

func (r *redfishCollector) close() {
	r.stopOnce.Do(func() {
		close(r.stop)
	})
}
