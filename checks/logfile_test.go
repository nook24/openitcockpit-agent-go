package checks

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

func appendToFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func readLines(t *testing.T, s *fileLogSource) []string {
	t.Helper()
	entries, _, err := s.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, entry.Line)
	}
	return lines
}

func expectLines(t *testing.T, got []string, expected ...string) {
	t.Helper()
	if strings.Join(got, "|") != strings.Join(expected, "|") {
		t.Fatalf("expected lines %q, got %q", expected, got)
	}
}

func TestLogfileFileSourceAppendAndPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	appendToFile(t, path, "old line 1\nold line 2\n")

	s := newFileLogSource(path, 1024*1024)

	// Existing lines get ignored on the first run
	expectLines(t, readLines(t, s))

	appendToFile(t, path, "new line 1\r\nnew line 2\n\nincomplete")
	expectLines(t, readLines(t, s), "new line 1", "new line 2")

	appendToFile(t, path, " line\n")
	expectLines(t, readLines(t, s), "incomplete line")

	expectLines(t, readLines(t, s))
}

func TestLogfileFileSourceTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	appendToFile(t, path, "some old lines which will be truncated\n")

	s := newFileLogSource(path, 1024*1024)
	expectLines(t, readLines(t, s))

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendToFile(t, path, "after truncate\n")
	expectLines(t, readLines(t, s), "after truncate")
}

func TestLogfileFileSourceRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	appendToFile(t, path, "line before rotation which is quite long\n")

	s := newFileLogSource(path, 1024*1024)
	expectLines(t, readLines(t, s))

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	// The new file is bigger than the read offset of the old file
	appendToFile(t, path, "first line after rotation\nsecond line after rotation\n")
	expectLines(t, readLines(t, s), "first line after rotation", "second line after rotation")
}

func TestLogfileFileSourceGlob(t *testing.T) {
	dir := t.TempDir()
	appendToFile(t, filepath.Join(dir, "a.log"), "old a\n")

	s := newFileLogSource(filepath.Join(dir, "*.log"), 1024*1024)
	expectLines(t, readLines(t, s))

	// Files which get created after the first run are read from the beginning
	appendToFile(t, filepath.Join(dir, "b.log"), "new b\n")
	appendToFile(t, filepath.Join(dir, "a.log"), "new a\n")
	expectLines(t, readLines(t, s), "new a", "new b")

	if err := os.Remove(filepath.Join(dir, "a.log")); err != nil {
		t.Fatal(err)
	}
	expectLines(t, readLines(t, s))
	if _, ok := s.files[filepath.Join(dir, "a.log")]; ok {
		t.Fatal("removed file should be forgotten")
	}
}

func TestLogfileFileSourceNoFile(t *testing.T) {
	s := newFileLogSource(filepath.Join(t.TempDir(), "*.log"), 1024)
	if _, _, err := s.read(context.Background()); err == nil || !strings.Contains(err.Error(), "no file matches") {
		t.Fatal("expected error for missing file, got: ", err)
	}
}

func TestLogfileFileSourceMaxReadBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	appendToFile(t, path, "")

	s := newFileLogSource(path, 20)
	expectLines(t, readLines(t, s))

	// Only the last 20 bytes get read, the first incomplete line gets discarded
	appendToFile(t, path, "aaaaaaaaaa\nbbbbbbbbbb\ncccccccccc\n")
	entries, warnings, err := s.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "skipped") {
		t.Fatal("expected skipped warning, got: ", warnings)
	}
	if len(entries) != 1 || entries[0].Line != "cccccccccc" {
		t.Fatalf("unexpected entries: %+v", entries)
	}

	// A line longer than max_read_bytes without a line break must not block the file forever
	appendToFile(t, path, strings.Repeat("x", 30))
	entries, _, err = s.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || len(entries[0].Line) != 20 {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func newTestLogfileCheck(t *testing.T, definitions ...*config.LogfileDefinition) *CheckLogfile {
	t.Helper()
	c := &CheckLogfile{}
	enabled, err := c.Configure(&config.Configuration{LogfileConfiguration: definitions})
	if err != nil {
		t.Fatal(err)
	}
	if enabled != (len(definitions) > 0) {
		t.Fatal("unexpected enabled state: ", enabled)
	}
	t.Cleanup(func() {
		_, _ = c.Configure(&config.Configuration{})
	})
	return c
}

func runLogfileCheck(t *testing.T, c *CheckLogfile, name string) *resultLogfile {
	t.Helper()
	r, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, ok := r.(map[string]interface{})[name].(*resultLogfile)
	if !ok {
		t.Fatalf("unexpected result for %s: %+v", name, r.(map[string]interface{})[name])
	}
	return result
}

func TestCheckLogfileWindow(t *testing.T) {
	now := time.Unix(1700000000, 0)
	logfileNow = func() time.Time { return now }
	defer func() { logfileNow = time.Now }()

	path := filepath.Join(t.TempDir(), "test.log")
	appendToFile(t, path, "ERROR before agent start\n")

	c := newTestLogfileCheck(t, &config.LogfileDefinition{
		Name:          "test",
		Type:          config.LogfileTypeFile,
		Path:          path,
		MatchRegexp:   regexp.MustCompile(`ERROR`),
		ExcludeRegexp: regexp.MustCompile(`ignore me`),
		Window:        60,
		MaxLines:      2,
		MaxReadBytes:  1024 * 1024,
	})

	result := runLogfileCheck(t, c, "test")
	if result.Matches != 0 || result.LastMatchTimestamp != 0 || len(result.Lines) != 0 {
		t.Fatalf("expected no matches on first run: %+v", result)
	}

	appendToFile(t, path, "ERROR 1\nINFO 1\nERROR 2 ignore me\nERROR 3\nERROR 4\n")
	now = now.Add(30 * time.Second)
	result = runLogfileCheck(t, c, "test")
	if result.Matches != 3 {
		t.Fatalf("expected 3 matches: %+v", result)
	}
	if len(result.Lines) != 2 || result.Lines[0].Line != "ERROR 3" || result.Lines[1].Line != "ERROR 4" {
		t.Fatalf("expected the latest 2 lines: %+v", result.Lines)
	}
	if result.Lines[0].Source != path || result.Lines[0].Timestamp != now.Unix() {
		t.Fatalf("unexpected line: %+v", result.Lines[0])
	}

	// Reload with the same definition keeps the state
	c = newTestLogfileCheck(t, c.definitions...)

	appendToFile(t, path, "ERROR 5\n")
	now = now.Add(30 * time.Second)
	result = runLogfileCheck(t, c, "test")
	if result.Matches != 4 || len(result.Lines) != 2 || result.Lines[1].Line != "ERROR 5" {
		t.Fatalf("expected 4 matches in the window: %+v", result)
	}

	// First bucket leaves the window
	now = now.Add(30 * time.Second)
	result = runLogfileCheck(t, c, "test")
	if result.Matches != 1 || len(result.Lines) != 1 || result.Lines[0].Line != "ERROR 5" {
		t.Fatalf("expected 1 match in the window: %+v", result)
	}

	// Everything left the window
	now = now.Add(30 * time.Second)
	result = runLogfileCheck(t, c, "test")
	if result.Matches != 0 || len(result.Lines) != 0 {
		t.Fatalf("expected no match in the window: %+v", result)
	}
	if result.LastMatchTimestamp != now.Add(-60*time.Second).Unix() {
		t.Fatalf("unexpected last match timestamp: %+v", result)
	}

	js, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"lines":[]`) || !strings.Contains(string(js), `"warnings":[]`) {
		t.Fatal("lines and warnings must be serialized as empty arrays: ", string(js))
	}
}

func TestCheckLogfileErrors(t *testing.T) {
	c := newTestLogfileCheck(t,
		&config.LogfileDefinition{
			Name:        "invalid",
			Type:        config.LogfileTypeFile,
			ConfigError: "invalid match regex",
		},
		&config.LogfileDefinition{
			Name:         "missing",
			Type:         config.LogfileTypeFile,
			Path:         filepath.Join(t.TempDir(), "missing.log"),
			Window:       60,
			MaxReadBytes: 1024,
		},
	)

	r, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := r.(map[string]interface{})
	for _, name := range []string{"invalid", "missing"} {
		res, ok := results[name].(map[string]string)
		if !ok || res["error"] == "" {
			t.Fatalf("expected error for %s: %+v", name, results[name])
		}
	}
}

func TestCheckLogfileUnsupportedSource(t *testing.T) {
	definition := &config.LogfileDefinition{Name: "unsupported", Window: 60, MaxReadBytes: 1024}
	if runtime.GOOS == "linux" {
		definition.Type = config.LogfileTypeUnifiedLog
	} else {
		definition.Type = config.LogfileTypeJournald
	}
	c := newTestLogfileCheck(t, definition)

	r, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	res, ok := r.(map[string]interface{})["unsupported"].(map[string]string)
	if !ok || !strings.Contains(res["error"], "not supported") {
		t.Fatalf("expected not supported error: %+v", r)
	}
}

func TestTruncateLogLine(t *testing.T) {
	if truncateLogLine("short") != "short" {
		t.Fatal("short lines must not be truncated")
	}

	line := strings.Repeat("a", logfileMaxLineLength-1) + "äöü"
	truncated := truncateLogLine(line)
	if !utf8.ValidString(truncated) {
		t.Fatal("truncated line is not valid UTF-8")
	}
	if truncated != strings.Repeat("a", logfileMaxLineLength-1)+"..." {
		t.Fatalf("unexpected truncated line: %q", truncated[len(truncated)-10:])
	}
}

func TestParseJournaldEntry(t *testing.T) {
	entry, cursor, err := parseJournaldEntry([]byte(`{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"1700000000123456","MESSAGE":"Failed password for root","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cursor != "s=abc;i=1" || entry.Line != "Failed password for root" || entry.Source != "ssh.service" || entry.Timestamp.UnixMicro() != 1700000000123456 {
		t.Fatalf("unexpected entry: %+v cursor: %s", entry, cursor)
	}

	// Binary message, no unit and a field which exists multiple times
	entry, _, err = parseJournaldEntry([]byte(`{"__CURSOR":"s=abc;i=2","__REALTIME_TIMESTAMP":"1700000000000000","MESSAGE":[104,105,255],"SYSLOG_IDENTIFIER":["kernel","other"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Line != "hi\xff" || entry.Source != "kernel" {
		t.Fatalf("unexpected entry: %+v", entry)
	}

	// MESSAGE can be null
	entry, _, err = parseJournaldEntry([]byte(`{"__CURSOR":"s=abc;i=3","MESSAGE":null,"_COMM":"foo"}`))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Line != "" || entry.Source != "foo" {
		t.Fatalf("unexpected entry: %+v", entry)
	}

	if _, _, err := parseJournaldEntry([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestParseUnifiedLogEntry(t *testing.T) {
	entry, err := parseUnifiedLogEntry([]byte(`{"timestamp":"2025-03-01 10:15:30.123456+0100","eventMessage":"kernel panic","processImagePath":"/kernel","subsystem":"com.apple.kernel","messageType":"Default"}`))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Line != "kernel panic" || entry.Source != "kernel (com.apple.kernel)" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if entry.Timestamp.UTC().Format(time.RFC3339Nano) != "2025-03-01T09:15:30.123456Z" {
		t.Fatalf("unexpected timestamp: %s", entry.Timestamp)
	}

	// Summary at the end of the output
	entry, err = parseUnifiedLogEntry([]byte(`{"count":42,"finished":1}`))
	if err != nil || entry != nil {
		t.Fatalf("expected no entry: %+v %v", entry, err)
	}
}

func TestJournaldLogSource(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("journald is only available on Linux")
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl not installed")
	}

	s, err := newJournaldLogSource("", "", 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, _, err := s.read(context.Background()); err != nil {
			t.Skip("journal not readable: ", err)
		}
	}
}
