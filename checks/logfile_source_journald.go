package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// journaldLogSource reads new entries from the systemd journal via journalctl.
// journalctl is used instead of sd-journal, because the agent gets build without cgo.
type journaldLogSource struct {
	units        []string
	priority     string
	maxReadBytes int64
	initialized  bool
	// cursor of the last processed journal entry
	cursor string
	// used if no cursor is available yet (e.g. the journal is empty)
	since time.Time
}

// journaldEntry contains the fields of "journalctl -o json" we are interested in.
// Fields can be strings, arrays of strings or arrays of bytes (binary data), so they are parsed later.
type journaldEntry struct {
	Cursor            json.RawMessage `json:"__CURSOR"`
	RealtimeTimestamp json.RawMessage `json:"__REALTIME_TIMESTAMP"`
	Message           json.RawMessage `json:"MESSAGE"`
	SystemdUnit       json.RawMessage `json:"_SYSTEMD_UNIT"`
	SyslogIdentifier  json.RawMessage `json:"SYSLOG_IDENTIFIER"`
	Comm              json.RawMessage `json:"_COMM"`
}

func newJournaldLogSource(units, priority string, maxReadBytes int64) (*journaldLogSource, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("journald is not supported on %s", runtime.GOOS)
	}

	s := &journaldLogSource{
		priority:     strings.TrimSpace(priority),
		maxReadBytes: maxReadBytes,
	}
	for _, unit := range strings.Split(units, ",") {
		if unit = strings.TrimSpace(unit); unit != "" {
			s.units = append(s.units, unit)
		}
	}
	return s, nil
}

func (s *journaldLogSource) read(ctx context.Context) ([]*logEntry, []string, error) {
	if !s.initialized {
		// Only new entries are of interest, so we start at the end of the journal
		if err := s.seekTail(ctx); err != nil {
			return nil, nil, err
		}
		s.initialized = true
		return nil, nil, nil
	}

	args := []string{"--no-pager", "--quiet", "--output=json"}
	if s.cursor != "" {
		args = append(args, "--after-cursor="+s.cursor)
	} else {
		args = append(args, fmt.Sprintf("--since=@%d", s.since.Unix()))
	}
	for _, unit := range s.units {
		args = append(args, "--unit="+unit)
	}
	if s.priority != "" {
		args = append(args, "--priority="+s.priority)
	}

	var entries []*logEntry
	truncated, err := runLogCommand(ctx, s.maxReadBytes, func(line []byte) error {
		entry, cursor, err := parseJournaldEntry(line)
		if err != nil {
			return err
		}
		if cursor != "" {
			s.cursor = cursor
		}
		entries = append(entries, entry)
		return nil
	}, "journalctl", args...)
	if err != nil {
		return nil, nil, err
	}

	var warnings []string
	if truncated {
		warnings = append(warnings, "max_read_bytes reached, remaining journal entries will be processed in the next run")
	}
	return entries, warnings, nil
}

// seekTail stores the cursor of the latest journal entry
func (s *journaldLogSource) seekTail(ctx context.Context) error {
	s.since = logfileNow()
	_, err := runLogCommand(ctx, s.maxReadBytes, func(line []byte) error {
		_, cursor, err := parseJournaldEntry(line)
		if err != nil {
			return err
		}
		s.cursor = cursor
		return nil
	}, "journalctl", "--no-pager", "--quiet", "--output=json", "--lines=1")
	return err
}

func parseJournaldEntry(line []byte) (*logEntry, string, error) {
	raw := journaldEntry{}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, "", fmt.Errorf("could not parse journalctl output: %s", err)
	}

	entry := &logEntry{
		Line: journaldField(raw.Message),
	}

	// __REALTIME_TIMESTAMP is in microseconds
	if usec, err := strconv.ParseInt(journaldField(raw.RealtimeTimestamp), 10, 64); err == nil {
		entry.Timestamp = time.UnixMicro(usec)
	} else {
		entry.Timestamp = logfileNow()
	}

	for _, source := range []json.RawMessage{raw.SystemdUnit, raw.SyslogIdentifier, raw.Comm} {
		if entry.Source = journaldField(source); entry.Source != "" {
			break
		}
	}

	return entry, journaldField(raw.Cursor), nil
}

// journaldField converts a field of journalctl's JSON output to a string.
// A field can be a string, null, an array of bytes for binary data or an array of strings/byte arrays if the field exists multiple times.
func journaldField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str
	}

	var data []byte
	var numbers []int
	if err := json.Unmarshal(raw, &numbers); err == nil {
		data = make([]byte, 0, len(numbers))
		for _, n := range numbers {
			data = append(data, byte(n))
		}
		return string(data)
	}

	// Field exists multiple times, we use the first value
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err == nil && len(values) > 0 {
		return journaldField(values[0])
	}

	return ""
}

// Make sure the type implements the interface
var _ logSource = (*journaldLogSource)(nil)
