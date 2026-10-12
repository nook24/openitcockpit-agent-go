package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

// Lines in the check result get truncated to this length to keep the JSON small
const logfileMaxLineLength = 1024

// logfileNow can be replaced by tests
var logfileNow = time.Now

// The state of all log sources is stored outside of CheckLogfile, because the checks get
// recreated on every reload of the agent. Otherwise we would lose the read position and all
// matches of the current window on every reload.
var (
	logfileStatesMutex sync.Mutex
	logfileStates      = map[string]*logfileState{}
)

// CheckLogfile monitors log files, journald and the macOS unified log for lines matching a regular expression
type CheckLogfile struct {
	definitions []*config.LogfileDefinition
}

// Name will be used in the response as check name
func (c *CheckLogfile) Name() string {
	return "logfiles"
}

type resultLogfileLine struct {
	Timestamp int64  `json:"timestamp"` // Unix timestamp of the log entry (time of reading for plain files)
	Source    string `json:"source"`    // e.g.: /var/log/nginx/error.log or ssh.service
	Line      string `json:"line"`
}

type resultLogfile struct {
	Type               string               `json:"type"`                 // file, journald or unifiedlog
	Window             int64                `json:"window"`               // Size of the sliding window in seconds
	Matches            int64                `json:"matches"`              // Number of matching lines within the window
	LastMatchTimestamp int64                `json:"last_match_timestamp"` // Unix timestamp of the last match, also if outside of the window. 0 = no match yet
	Lines              []*resultLogfileLine `json:"lines"`                // The latest matching lines within the window (oldest first)
	Warnings           []string             `json:"warnings"`             // Non fatal problems of the last run, e.g. one file of a glob was not readable
}

// logEntry is a single line returned by a log source
type logEntry struct {
	Timestamp time.Time
	Source    string
	Line      string
}

// logSource returns all log entries which got written since the last call of read
type logSource interface {
	read(ctx context.Context) (entries []*logEntry, warnings []string, err error)
}

// logfileBucket counts the matches of a single run
type logfileBucket struct {
	readAt  time.Time
	matches int64
}

type logfileLine struct {
	readAt time.Time
	result *resultLogfileLine
}

type logfileState struct {
	source    logSource
	buckets   []logfileBucket
	lines     []logfileLine
	lastMatch time.Time
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckLogfile) Run(ctx context.Context) (interface{}, error) {
	logfileStatesMutex.Lock()
	defer logfileStatesMutex.Unlock()

	result := make(map[string]interface{}, len(c.definitions))
	for _, definition := range c.definitions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if definition.ConfigError != "" {
			result[definition.Name] = map[string]string{"error": definition.ConfigError}
			continue
		}

		key := logfileStateKey(definition)
		state, ok := logfileStates[key]
		if !ok {
			source, err := newLogSource(definition)
			if err != nil {
				result[definition.Name] = map[string]string{"error": err.Error()}
				continue
			}
			state = &logfileState{source: source}
			logfileStates[key] = state
		}

		res, err := state.update(ctx, definition)
		if err != nil {
			result[definition.Name] = map[string]string{"error": err.Error()}
			continue
		}
		result[definition.Name] = res
	}

	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckLogfile) Configure(cfg *config.Configuration) (bool, error) {
	c.definitions = cfg.LogfileConfiguration

	// Drop the state of removed or changed definitions
	logfileStatesMutex.Lock()
	defer logfileStatesMutex.Unlock()
	keep := make(map[string]bool, len(c.definitions))
	for _, definition := range c.definitions {
		keep[logfileStateKey(definition)] = true
	}
	for key := range logfileStates {
		if !keep[key] {
			delete(logfileStates, key)
		}
	}

	return len(c.definitions) > 0, nil
}

// logfileStateKey changes if the definition gets modified, so a modified definition starts with a fresh state
func logfileStateKey(d *config.LogfileDefinition) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%d|%d|%d",
		d.Name, d.Type, d.Path, d.Unit, d.Priority, d.Predicate, d.Match, d.Exclude, d.Window, d.MaxLines, d.MaxReadBytes)
}

func newLogSource(d *config.LogfileDefinition) (logSource, error) {
	switch d.Type {
	case config.LogfileTypeFile:
		return newFileLogSource(d.Path, d.MaxReadBytes), nil
	case config.LogfileTypeJournald:
		return newJournaldLogSource(d.Unit, d.Priority, d.MaxReadBytes)
	case config.LogfileTypeUnifiedLog:
		return newUnifiedLogSource(d.Predicate, d.MaxReadBytes)
	}
	return nil, fmt.Errorf("unknown logfile type: %s", d.Type)
}

func (s *logfileState) update(ctx context.Context, d *config.LogfileDefinition) (*resultLogfile, error) {
	entries, warnings, err := s.source.read(ctx)
	if err != nil {
		return nil, err
	}

	now := logfileNow()
	var matches int64
	for _, entry := range entries {
		if d.MatchRegexp != nil && !d.MatchRegexp.MatchString(entry.Line) {
			continue
		}
		if d.ExcludeRegexp != nil && d.ExcludeRegexp.MatchString(entry.Line) {
			continue
		}
		matches++
		if d.MaxLines > 0 {
			s.lines = append(s.lines, logfileLine{
				readAt: now,
				result: &resultLogfileLine{
					Timestamp: entry.Timestamp.Unix(),
					Source:    entry.Source,
					Line:      truncateLogLine(entry.Line),
				},
			})
		}
	}
	if matches > 0 {
		s.buckets = append(s.buckets, logfileBucket{readAt: now, matches: matches})
		s.lastMatch = now
	}

	// Discard everything which is outside of the sliding window
	windowStart := now.Add(-time.Duration(d.Window) * time.Second)
	for len(s.buckets) > 0 && !s.buckets[0].readAt.After(windowStart) {
		s.buckets = s.buckets[1:]
	}
	for len(s.lines) > 0 && !s.lines[0].readAt.After(windowStart) {
		s.lines = s.lines[1:]
	}
	if int64(len(s.lines)) > d.MaxLines {
		s.lines = s.lines[int64(len(s.lines))-d.MaxLines:]
	}
	// Copy the remaining lines, so the underlying array of a resliced slice can be freed
	s.lines = append([]logfileLine(nil), s.lines...)

	res := &resultLogfile{
		Type:     d.Type,
		Window:   d.Window,
		Lines:    make([]*resultLogfileLine, 0, len(s.lines)),
		Warnings: warnings,
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	for _, bucket := range s.buckets {
		res.Matches += bucket.matches
	}
	for _, line := range s.lines {
		res.Lines = append(res.Lines, line.result)
	}
	if !s.lastMatch.IsZero() {
		res.LastMatchTimestamp = s.lastMatch.Unix()
	}

	return res, nil
}

func truncateLogLine(line string) string {
	if len(line) <= logfileMaxLineLength {
		return line
	}
	// Do not cut a multi byte character in half
	cut := logfileMaxLineLength
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + "..."
}

// runLogCommand executes a command and passes every line of stdout to handleLine.
// Reading stops after maxBytes and truncated is set to true.
func runLogCommand(ctx context.Context, maxBytes int64, handleLine func(line []byte) error, name string, args ...string) (truncated bool, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := cmd.Start(); err != nil {
		return false, err
	}

	var readBytes int64
	var handleErr error
	reader := bufio.NewReader(stdout)
	for {
		line, readErr := reader.ReadBytes('\n')
		readBytes += int64(len(line))
		if len(bytes.TrimSpace(line)) > 0 {
			if handleErr = handleLine(line); handleErr != nil {
				break
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				handleErr = readErr
			}
			break
		}
		if readBytes >= maxBytes {
			truncated = true
			break
		}
	}

	if truncated || handleErr != nil {
		// We do not care about the remaining output
		cancel()
		_ = cmd.Wait()
		return truncated, handleErr
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return false, fmt.Errorf("%s failed: %s", name, err)
		}
		return false, fmt.Errorf("%s failed: %s: %s", name, err, msg)
	}
	return false, nil
}
