package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"runtime"
	"strings"
	"time"
)

// Format of the timestamps in the output of "log show --style ndjson"
const unifiedLogTimestampLayout = "2006-01-02 15:04:05.000000-0700"

// unifiedLogSource reads new entries from the macOS unified log via "log show"
type unifiedLogSource struct {
	predicate    string
	maxReadBytes int64
	// timestamp of the last processed entry
	last time.Time
}

type unifiedLogEntry struct {
	Timestamp        string  `json:"timestamp"`
	EventMessage     *string `json:"eventMessage"`
	ProcessImagePath string  `json:"processImagePath"`
	Subsystem        string  `json:"subsystem"`
}

func newUnifiedLogSource(predicate string, maxReadBytes int64) (*unifiedLogSource, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("unified log is not supported on %s", runtime.GOOS)
	}

	return &unifiedLogSource{
		predicate:    strings.TrimSpace(predicate),
		maxReadBytes: maxReadBytes,
	}, nil
}

func (s *unifiedLogSource) read(ctx context.Context) ([]*logEntry, []string, error) {
	if s.last.IsZero() {
		// Only new entries are of interest
		s.last = logfileNow()
		return nil, nil, nil
	}

	// --start only supports seconds, so entries we already processed get filtered by their timestamp
	args := []string{"show", "--style", "ndjson", "--start", s.last.Local().Format("2006-01-02 15:04:05")}
	if s.predicate != "" {
		args = append(args, "--predicate", s.predicate)
	}

	var entries []*logEntry
	last := s.last
	truncated, err := runLogCommand(ctx, s.maxReadBytes, func(line []byte) error {
		entry, err := parseUnifiedLogEntry(line)
		if err != nil {
			return err
		}
		if entry == nil || !entry.Timestamp.After(s.last) {
			return nil
		}
		if entry.Timestamp.After(last) {
			last = entry.Timestamp
		}
		entries = append(entries, entry)
		return nil
	}, "/usr/bin/log", args...)
	if err != nil {
		return nil, nil, err
	}
	s.last = last

	var warnings []string
	if truncated {
		warnings = append(warnings, "max_read_bytes reached, remaining log entries will be processed in the next run")
	}
	return entries, warnings, nil
}

// parseUnifiedLogEntry returns nil if the line is not a log entry (e.g. the summary at the end of the output)
func parseUnifiedLogEntry(line []byte) (*logEntry, error) {
	raw := unifiedLogEntry{}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("could not parse log show output: %s", err)
	}
	if raw.EventMessage == nil || raw.Timestamp == "" {
		return nil, nil
	}

	timestamp, err := time.Parse(unifiedLogTimestampLayout, raw.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("could not parse timestamp of log show output: %s", err)
	}

	source := path.Base(raw.ProcessImagePath)
	if raw.ProcessImagePath == "" {
		source = ""
	}
	if raw.Subsystem != "" {
		if source == "" {
			source = raw.Subsystem
		} else {
			source = fmt.Sprintf("%s (%s)", source, raw.Subsystem)
		}
	}

	return &logEntry{
		Timestamp: timestamp,
		Source:    source,
		Line:      *raw.EventMessage,
	}, nil
}

// Make sure the type implements the interface
var _ logSource = (*unifiedLogSource)(nil)
