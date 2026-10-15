//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package checks

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/shirou/gopsutil/v4/cpu"
)

func saturatingSub(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return 0
}

func calcuateBusy(t cpu.TimesStat) (float64, float64, float64) {
	busy := t.User + t.Nice + t.System + t.Irq + t.Softirq + t.Steal
	idle := t.Idle + t.Iowait
	total := busy + idle
	return busy, idle, total
}

func calculateUsagePercentage(prev, current cpu.TimesStat) float64 {
	// This is highly inspired by
	// https://github.com/shirou/gopsutil/blob/aa9796d3d754cc700939236e2fa8c3a95374c61b/cpu/cpu.go#L93-L144
	// and htop
	// https://github.com/htop-dev/htop/blob/main/linux/LinuxProcessList.c#L1948-L2006
	// https://github.com/htop-dev/htop/blob/4102862d12695cdf003e2d51ef6ce5984b7136d7/linux/LinuxMachine.c#L402-L512 (code got moved 31.10.2024)
	// and yes - htop is reading /proc/stat as we do
	prevBusy, _, prevTotal := calcuateBusy(prev)
	currentBusy, _, currentTotal := calcuateBusy(current)

	if currentBusy <= prevBusy {
		return 0
	}

	if currentTotal <= prevTotal {
		return 100
	}
	return math.Min(100, math.Max(0, (currentBusy-prevBusy)/(currentTotal-prevTotal)*100))
}

const (
	// The CPU times are sampled in the background with this interval
	cpuSampleInterval = 5 * time.Second
	// The background sampler stops if the check was not executed for this time (e.g. disabled by a reload)
	cpuSamplerIdleTimeout = 10 * time.Minute
)

type cpuSample struct {
	time  time.Time
	stats []cpu.TimesStat
}

// cpuSampler reads the CPU times in the background, so the check can report the average CPU usage
// of the whole check interval. A short measurement while the agent executes all checks in parallel
// would mainly measure the agent itself.
type cpuSampler struct {
	mutex      sync.Mutex
	samples    []*cpuSample // Oldest first
	window     time.Duration
	running    bool
	lastAccess time.Time
}

var cpuSamplerState = &cpuSampler{}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckCpu) Run(ctx context.Context) (interface{}, error) {
	window := time.Duration(c.checkInterval) * time.Second
	if window <= 0 {
		window = 30 * time.Second
	}

	current, err := cpu.TimesWithContext(ctx, true)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	// The average CPU usage since the sample at the beginning of the check interval
	base := cpuSamplerState.base(now, window, len(current))
	if base == nil {
		// No sample of the background sampler yet, e.g. right after the start of the agent
		log.Debugln("CPU check: no background sample available, measuring for 1 second")
		if err := c.SleepWithContext(ctx, 1*time.Second); err != nil {
			return nil, err
		}
		base = current
		if current, err = cpu.TimesWithContext(ctx, true); err != nil {
			return nil, err
		}
	}

	if len(base) != len(current) {
		return nil, fmt.Errorf("number of CPU cores has changed %v != %v", len(base), len(current))
	}
	return cpuResultFromTimes(base, current), nil
}

// base returns the CPU times at the beginning of the window and starts the background sampler if required
func (s *cpuSampler) base(now time.Time, window time.Duration, cores int) []cpu.TimesStat {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.window = window
	s.lastAccess = now
	if !s.running {
		s.running = true
		go s.run()
	}
	return selectCpuBaseSample(s.samples, now, window, cores)
}

// selectCpuBaseSample returns the newest sample which is at least as old as the window.
// If the sampler runs shorter than the window, the oldest sample is used, if it is at least 1 second old.
func selectCpuBaseSample(samples []*cpuSample, now time.Time, window time.Duration, cores int) []cpu.TimesStat {
	var base *cpuSample
	for _, sample := range samples {
		if len(sample.stats) != cores {
			// The number of CPU cores has changed (CPU hotplug)
			continue
		}
		if now.Sub(sample.time) >= window || base == nil {
			base = sample
		}
	}
	if base == nil || now.Sub(base.time) < time.Second {
		return nil
	}
	return base.stats
}

func (s *cpuSampler) run() {
	for {
		stats, err := cpu.Times(true)
		now := time.Now()

		s.mutex.Lock()
		if now.Sub(s.lastAccess) > cpuSamplerIdleTimeout {
			// The check is not executed anymore
			s.running = false
			s.samples = nil
			s.mutex.Unlock()
			return
		}
		if err != nil {
			log.Debugln("CPU check: could not read the CPU times: ", err)
		} else {
			if len(s.samples) > 0 && len(s.samples[len(s.samples)-1].stats) != len(stats) {
				// The number of CPU cores has changed (CPU hotplug), the old samples can not be compared anymore
				s.samples = nil
			}
			s.samples = append(s.samples, &cpuSample{time: now, stats: stats})
			// Keep the samples of the window and one older sample as base
			keep := now.Add(-s.window - 2*cpuSampleInterval)
			for len(s.samples) > 2 && s.samples[1].time.Before(keep) {
				s.samples = s.samples[1:]
			}
		}
		s.mutex.Unlock()

		time.Sleep(cpuSampleInterval)
	}
}

// cpuResultFromTimes calculates the CPU usage between two samples of the CPU times
func cpuResultFromTimes(prevTimeStats, timeStats []cpu.TimesStat) *resultCpu {
	result := &resultCpu{}

	// Get CPU usage per core
	var cpuPercentages []float64
	for i := range prevTimeStats {
		cpuPercentage := calculateUsagePercentage(prevTimeStats[i], timeStats[i])
		cpuPercentages = append(cpuPercentages, cpuPercentage)
	}
	result.PercentagePerCore = cpuPercentages

	// Get total CPU usage as percentage
	var totalCpuPercentage float64
	for i := range cpuPercentages {
		totalCpuPercentage = totalCpuPercentage + cpuPercentages[i]
	}
	result.PercentageTotal = totalCpuPercentage / float64(len(cpuPercentages))

	// Get CPU timing details per core
	var timings []cpuDetails
	var totalUser, totalNice, totalSystem, totalIoWait, totalIdle, totalTotal float64
	for i := range prevTimeStats {
		// Ignore t.Irq + t.Softirq + t.Steal to get 100% over all values we list in the json
		prevTotal := prevTimeStats[i].User + prevTimeStats[i].Nice + prevTimeStats[i].System + prevTimeStats[i].Idle + prevTimeStats[i].Iowait
		currentTotal := timeStats[i].User + timeStats[i].Nice + timeStats[i].System + timeStats[i].Idle + timeStats[i].Iowait

		userDelta := saturatingSub(timeStats[i].User, prevTimeStats[i].User)
		niceDelta := saturatingSub(timeStats[i].Nice, prevTimeStats[i].Nice)
		systemDelta := saturatingSub(timeStats[i].System, prevTimeStats[i].System)
		ioWaitDelta := saturatingSub(timeStats[i].Iowait, prevTimeStats[i].Iowait)
		idleDelta := saturatingSub(timeStats[i].Idle, prevTimeStats[i].Idle)
		totalDelta := saturatingSub(currentTotal, prevTotal)

		if totalDelta == 0 {
			timings = append(timings, cpuDetails{})
		} else {
			// Do not Division by zero (not sure if this could ever happen to be honest but better safe than sorry)
			timings = append(timings, cpuDetails{
				User:   userDelta / totalDelta * 100,
				Nice:   niceDelta / totalDelta * 100,
				System: systemDelta / totalDelta * 100,
				Idle:   idleDelta / totalDelta * 100,
				Iowait: ioWaitDelta / totalDelta * 100,
			})
		}

		totalUser = totalUser + userDelta
		totalNice = totalNice + niceDelta
		totalSystem = totalSystem + systemDelta
		totalIoWait = totalIoWait + ioWaitDelta
		totalIdle = totalIdle + idleDelta
		totalTotal = totalTotal + totalDelta
	}
	result.DetailsPerCore = timings

	// Get total CPU timing details
	result.DetailsTotal = &cpuDetails{}
	if totalTotal > 0 {
		result.DetailsTotal = &cpuDetails{
			User:   totalUser / totalTotal * 100,
			Nice:   totalNice / totalTotal * 100,
			System: totalSystem / totalTotal * 100,
			Idle:   totalIdle / totalTotal * 100,
			Iowait: totalIoWait / totalTotal * 100,
		}
	}
	return result
}

// Like sleep but can be canceled by context
func (c *CheckCpu) SleepWithContext(ctx context.Context, interval time.Duration) error {
	var timer = time.NewTimer(interval)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
