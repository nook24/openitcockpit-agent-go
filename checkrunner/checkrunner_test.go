package checkrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/checks"
	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestCheckRunner(t *testing.T) {
	cfg := &config.Configuration{
		CheckInterval: 30,
	}
	checks, err := checks.ChecksForConfiguration(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &CheckRunner{
		Configuration: cfg,
		Result:        make(chan map[string]interface{}),
		Checks:        checks,
	}
	err = c.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	select {
	case res := <-c.Result:
		b, err := json.MarshalIndent(res, "", "    ")
		if err != nil {
			t.Fatal(err)
		} else {
			log.Infoln(string(b))
		}
	case <-time.After(time.Second * 30):
		t.Fatal("timeout waiting for results")
	}

	c.Shutdown()
}

func TestCheckRunnerCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Configuration{
		CheckInterval: 30,
	}
	checks, err := checks.ChecksForConfiguration(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &CheckRunner{
		Configuration: cfg,
		Result:        make(chan map[string]interface{}),
		Checks:        checks,
	}
	err = c.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	done := make(chan struct{})

	go func() {
		c.wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-done:
		// ok
	case <-c.Result:
		t.Fatal("did not expect any result")
	case <-time.After(time.Second * 10):
		t.Fatal("timeout waiting for results")
	}

	// test if another shutdown works
	go func() {
		c.Shutdown()
		done <- struct{}{}
	}()
	select {
	case <-done:
		// ok
	case <-time.After(time.Second * 10):
		t.Fatal("timeout waiting for shutdown")
	}
}

type panicCheck struct {
}

func (c *panicCheck) Name() string {
	return "panic"
}

func (c *panicCheck) Run(ctx context.Context) (interface{}, error) {
	panic("panic test WSD123")
}

func (c *panicCheck) Configure(config *config.Configuration) (bool, error) {
	return true, nil
}

type errorCheck struct {
}

func (c *errorCheck) Name() string {
	return "errchk"
}

func (c *errorCheck) Run(ctx context.Context) (interface{}, error) {
	return struct{}{}, fmt.Errorf("error test WSD123")
}

func (c *errorCheck) Configure(config *config.Configuration) (bool, error) {
	return true, nil
}

func TestCheckRunnerPanicError(t *testing.T) {
	cfg := &config.Configuration{
		CheckInterval: 30,
	}

	c := &CheckRunner{
		Configuration: cfg,
		Result:        make(chan map[string]interface{}),
		Checks: []checks.Check{
			&errorCheck{},
			&panicCheck{},
		},
	}
	err := c.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()

	select {
	case res := <-c.Result:
		if len(res) != 2 {
			t.Fatal("unexpected result")
		}
		_, ok := res["panic"].(*errorResult)
		if !ok {
			t.Fatal("result is not of type errorResult")
		}
		_, ok = res["errchk"].(*errorResult)
		if !ok {
			t.Fatal("result is not of type errorResult")
		}
	case <-time.After(time.Second * 5):
		t.Fatal("timeout waiting for results")
	}
}

// slowCheck ignores the context like a WMI query
type slowCheck struct {
	release chan struct{}
	running atomic.Int32
	maxRuns atomic.Int32
}

func (c *slowCheck) Name() string { return "slow" }

func (c *slowCheck) Run(_ context.Context) (interface{}, error) {
	n := c.running.Add(1)
	defer c.running.Add(-1)
	if n > c.maxRuns.Load() {
		c.maxRuns.Store(n)
	}
	<-c.release
	return "done", nil
}

func (c *slowCheck) Configure(_ *config.Configuration) (bool, error) { return true, nil }

func TestCheckRunnerSkipsRunWhileChecksAreRunning(t *testing.T) {
	check := &slowCheck{release: make(chan struct{})}
	c := &CheckRunner{
		Configuration: &config.Configuration{CheckInterval: 30},
		Result:        make(chan map[string]interface{}, 10),
		Checks:        []checks.Check{check},
	}

	// The first run times out, but the check keeps running
	c.runChecks(context.Background(), c.Checks, 50*time.Millisecond)
	for i := 0; i < 3; i++ {
		c.runChecks(context.Background(), c.Checks, 50*time.Millisecond)
	}
	if max := check.maxRuns.Load(); max != 1 {
		t.Fatalf("the check ran %d times concurrently", max)
	}

	close(check.release)
	deadline := time.Now().Add(5 * time.Second)
	for c.running.Load() {
		if time.Now().After(deadline) {
			t.Fatal("run did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The next run is executed again
	c.runChecks(context.Background(), c.Checks, 5*time.Second)
	select {
	case res := <-c.Result:
		if res["slow"] != "done" {
			t.Fatalf("unexpected result: %v", res)
		}
	default:
		t.Fatal("no result")
	}
}
