//go:build linux || freebsd
// +build linux freebsd

package checks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

const eximCommandTimeout = 20 * time.Second

// Debian calls the binary exim4, the other distributions and FreeBSD exim
var eximLocations = []string{
	"exim4",
	"exim",
	"/usr/sbin/exim4",
	"/usr/sbin/exim",
	"/usr/local/sbin/exim",
}

// CheckExim gathers the mail queue of Exim with "exim -bp"
type CheckExim struct {
	exim string
}

// Name will be used in the response as check name
func (c *CheckExim) Name() string {
	return "exim"
}

type resultExim struct {
	Messages  int64 `json:"messages"`
	Frozen    int64 `json:"frozen"` // Messages which Exim does not try to deliver anymore
	SizeBytes int64 `json:"size_bytes"`
	OldestAge int64 `json:"oldest_age"` // Age of the oldest message in seconds, 0 if the queue is empty
}

// Header line of a message, e.g.: "25m  2.1K 1oWbIa-0002Xy-Ad <user@example.com> *** frozen ***"
var eximQueueLine = regexp.MustCompile(`^\s*(\d+)([smhdw])\s+([\d.]+[KMG]?)\s+\S+\s+<[^>]*>(.*)$`)

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckExim) Run(ctx context.Context) (interface{}, error) {
	if c.exim == "" {
		c.exim = findExim()
	}
	if c.exim == "" {
		return nil, fmt.Errorf("exim: %w", exec.ErrNotFound)
	}

	ctx, cancel := context.WithTimeout(ctx, eximCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.exim, "-bp")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("exim -bp: %s", err)
	}
	// The queue can contain a lot of messages, so the output is parsed while it is read
	result := parseEximQueue(stdout)
	_, _ = io.Copy(io.Discard, stdout)

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("exim -bp: timeout after %s", eximCommandTimeout)
		}
		return nil, fmt.Errorf("exim -bp failed: %s: %s", err, strings.TrimSpace(stderr.String()))
	}
	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckExim) Configure(cfg *config.Configuration) (bool, error) {
	if !cfg.Exim {
		return false, nil
	}
	c.exim = findExim()
	return c.exim != "", nil
}

func findExim() string {
	for _, location := range eximLocations {
		if strings.HasPrefix(location, "/") {
			if _, err := os.Stat(location); err == nil {
				return location
			}
			continue
		}
		if path, err := exec.LookPath(location); err == nil {
			return path
		}
	}
	return ""
}

// parseEximQueue parses the output of "exim -bp"
func parseEximQueue(r io.Reader) *resultExim {
	result := &resultExim{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		match := eximQueueLine.FindStringSubmatch(scanner.Text())
		if match == nil {
			// Recipients and empty lines
			continue
		}
		result.Messages++
		if strings.Contains(match[4], "*** frozen ***") {
			result.Frozen++
		}
		result.SizeBytes += parseEximSize(match[3])

		value, _ := strconv.ParseInt(match[1], 10, 64)
		age := value * map[string]int64{"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match[2]]
		if age > result.OldestAge {
			result.OldestAge = age
		}
	}
	return result
}

// parseEximSize parses sizes like 567, 2.1K or 1.2M
func parseEximSize(value string) int64 {
	multiplier := 1.0
	switch {
	case strings.HasSuffix(value, "K"):
		multiplier = 1024
	case strings.HasSuffix(value, "M"):
		multiplier = 1024 * 1024
	case strings.HasSuffix(value, "G"):
		multiplier = 1024 * 1024 * 1024
	}
	number, _ := strconv.ParseFloat(strings.TrimRight(value, "KMG"), 64)
	return int64(number * multiplier)
}
