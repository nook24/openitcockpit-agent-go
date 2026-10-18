//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package checks

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
)

func testCpuTimes(cores int, user, idle float64) []cpu.TimesStat {
	stats := make([]cpu.TimesStat, cores)
	for i := range stats {
		stats[i] = cpu.TimesStat{CPU: "cpu", User: user, Idle: idle}
	}
	return stats
}

func TestSelectCpuBaseSample(t *testing.T) {
	now := time.Now()
	window := 30 * time.Second
	samples := []*cpuSample{
		{time: now.Add(-40 * time.Second), stats: testCpuTimes(2, 1, 0)},
		{time: now.Add(-35 * time.Second), stats: testCpuTimes(2, 2, 0)},
		{time: now.Add(-25 * time.Second), stats: testCpuTimes(2, 3, 0)},
		{time: now.Add(-5 * time.Second), stats: testCpuTimes(2, 4, 0)},
	}

	// The newest sample which is at least as old as the window
	if base := selectCpuBaseSample(samples, now, window, 2); base == nil || base[0].User != 2 {
		t.Errorf("expected the sample of -35s, got %+v", base)
	}

	// The sampler runs shorter than the window: the oldest sample is used
	if base := selectCpuBaseSample(samples[2:], now, window, 2); base == nil || base[0].User != 3 {
		t.Errorf("expected the oldest sample, got %+v", base)
	}

	// Samples younger than 1 second can not be used, e.g. right after the start of the agent
	young := []*cpuSample{{time: now.Add(-500 * time.Millisecond), stats: testCpuTimes(2, 1, 0)}}
	if base := selectCpuBaseSample(young, now, window, 2); base != nil {
		t.Errorf("expected no base sample, got %+v", base)
	}
	if base := selectCpuBaseSample(nil, now, window, 2); base != nil {
		t.Errorf("expected no base sample without samples, got %+v", base)
	}

	// The number of CPU cores has changed: samples with a different number of cores are ignored
	if base := selectCpuBaseSample(samples, now, window, 4); base != nil {
		t.Errorf("expected no base sample after a CPU hotplug, got %+v", base)
	}
}

func TestCpuResultFromTimes(t *testing.T) {
	// Core 0: 30 of 100 seconds busy, core 1: 10 of 100 seconds busy
	prev := []cpu.TimesStat{
		{CPU: "cpu0", User: 100, System: 50, Idle: 1000},
		{CPU: "cpu1", User: 100, System: 50, Idle: 1000},
	}
	current := []cpu.TimesStat{
		{CPU: "cpu0", User: 120, System: 60, Idle: 1070},
		{CPU: "cpu1", User: 105, System: 55, Idle: 1090},
	}
	result := cpuResultFromTimes(prev, current)

	if len(result.PercentagePerCore) != 2 || math.Abs(result.PercentagePerCore[0]-30) > 0.001 || math.Abs(result.PercentagePerCore[1]-10) > 0.001 {
		t.Errorf("unexpected usage per core: %v", result.PercentagePerCore)
	}
	if math.Abs(result.PercentageTotal-20) > 0.001 {
		t.Errorf("unexpected total usage: %v", result.PercentageTotal)
	}
	if d := result.DetailsTotal; math.Abs(d.User-12.5) > 0.001 || math.Abs(d.System-7.5) > 0.001 || math.Abs(d.Idle-80) > 0.001 {
		t.Errorf("unexpected details: %+v", d)
	}

	// No time has passed: no division by zero
	if result := cpuResultFromTimes(prev, prev); math.IsNaN(result.DetailsTotal.Idle) || result.PercentageTotal != 0 {
		t.Errorf("unexpected result without a time difference: %+v", result)
	}
}

func TestCheckCpuUsesBackgroundSamples(t *testing.T) {
	// The CPU times of 10 seconds ago, as the background sampler would have stored them
	stats, err := cpu.Times(true)
	if err != nil {
		t.Fatal(err)
	}
	cpuSamplerState.mutex.Lock()
	cpuSamplerState.samples = []*cpuSample{{time: time.Now().Add(-10 * time.Second), stats: stats}}
	cpuSamplerState.mutex.Unlock()

	start := time.Now()
	result, err := (&CheckCpu{checkInterval: 30}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// With a background sample the check does not need to measure itself
	if time.Since(start) > 500*time.Millisecond {
		t.Errorf("the check took %v, expected an immediate result", time.Since(start))
	}
	r := result.(*resultCpu)
	if len(r.PercentagePerCore) != len(stats) || r.PercentageTotal < 0 || r.PercentageTotal > 100 {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestCpuSamplerClose(t *testing.T) {
	sampler := &cpuSampler{}
	sampler.base(time.Now(), time.Minute, 1)
	sampler.mutex.Lock()
	stop := sampler.stop
	running := sampler.running
	sampler.mutex.Unlock()
	if !running || stop == nil {
		t.Fatal("the sampler was not started")
	}

	sampler.close()
	select {
	case <-stop:
	default:
		t.Fatal("the stop channel was not closed")
	}
	sampler.mutex.Lock()
	if sampler.running || sampler.samples != nil {
		t.Error("the sampler is still running")
	}
	sampler.mutex.Unlock()

	// The next check run starts a new sampler
	sampler.base(time.Now(), time.Minute, 1)
	sampler.mutex.Lock()
	restarted := sampler.running && sampler.stop != stop
	sampler.mutex.Unlock()
	if !restarted {
		t.Error("the sampler was not started again")
	}
	sampler.close()
	sampler.close()
}
