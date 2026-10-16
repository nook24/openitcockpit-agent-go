package checks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// fileLogSource reads new lines from one or multiple (glob) plain text log files
type fileLogSource struct {
	pattern      string
	maxReadBytes int64
	initialized  bool
	files        map[string]*fileCursor
}

type fileCursor struct {
	info   os.FileInfo
	offset int64
}

func newFileLogSource(pattern string, maxReadBytes int64) *fileLogSource {
	return &fileLogSource{
		pattern:      pattern,
		maxReadBytes: maxReadBytes,
		files:        map[string]*fileCursor{},
	}
}

func (s *fileLogSource) read(ctx context.Context) ([]*logEntry, []string, error) {
	paths, err := filepath.Glob(s.pattern)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid path %s: %s", s.pattern, err)
	}
	if len(paths) == 0 {
		// A file which gets created later is new, so it is read from the beginning
		s.initialized = true
		return nil, nil, fmt.Errorf("no file matches %s", s.pattern)
	}

	// The cursors of the previous run, to recognize files which got renamed to another path of the glob,
	// e.g. syslog => syslog.1 for /var/log/syslog* or app.log => app-20261016.log for /var/log/app/*.log
	previous := make([]*fileCursor, 0, len(s.files))
	for _, cursor := range s.files {
		if cursor.info != nil {
			previous = append(previous, &fileCursor{info: cursor.info, offset: cursor.offset})
		}
	}

	var entries []*logEntry
	var warnings []string
	var failed int
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		seen[path] = true

		fileEntries, warning, err := s.readFile(path, previous)
		if err != nil {
			if _, ok := s.files[path]; !ok && !s.initialized {
				// Remember the file, so we start at its end once it becomes readable
				s.files[path] = &fileCursor{}
			}
			failed++
			warnings = append(warnings, fmt.Sprintf("%s: %s", path, err))
			continue
		}
		if warning != "" {
			warnings = append(warnings, warning)
		}
		entries = append(entries, fileEntries...)
	}

	// Forget files which do not exist anymore
	for path := range s.files {
		if !seen[path] {
			delete(s.files, path)
		}
	}
	s.initialized = true

	if failed == len(paths) {
		return nil, nil, errors.New(strings.Join(warnings, "; "))
	}
	return entries, warnings, nil
}

func (s *fileLogSource) readFile(path string, previous []*fileCursor) ([]*logEntry, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	// Stat via the open file handle, so os.SameFile also works on Windows after the file got rotated
	info, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if info.IsDir() {
		return nil, "", fmt.Errorf("is a directory")
	}

	cursor, ok := s.files[path]
	if !ok || cursor.info == nil || !os.SameFile(cursor.info, info) {
		// The file was known under another path (renamed), so only the lines after its last offset are new
		for _, known := range previous {
			if os.SameFile(known.info, info) {
				cursor, ok = &fileCursor{info: known.info, offset: known.offset}, true
				break
			}
		}
	}
	switch {
	case !ok && !s.initialized, ok && cursor.info == nil:
		// First run after the agent started (or the file was not readable so far):
		// only new lines are of interest (like tail -F)
		cursor = &fileCursor{offset: info.Size()}
	case !ok:
		// A new file matching the glob got created, so all of its lines are new
		cursor = &fileCursor{}
	case !os.SameFile(cursor.info, info), info.Size() < cursor.offset:
		// File got rotated or truncated
		cursor.offset = 0
	}
	cursor.info = info
	s.files[path] = cursor

	size := info.Size()
	if size == cursor.offset {
		return nil, "", nil
	}

	warning := ""
	skipFirstLine := false
	if size-cursor.offset > s.maxReadBytes {
		// The log is growing faster than we can read it. Skip to the latest lines
		skipped := size - cursor.offset - s.maxReadBytes
		warning = fmt.Sprintf("%s: skipped %d bytes because of max_read_bytes", path, skipped)
		cursor.offset = size - s.maxReadBytes

		// Discard the first line if we jumped into the middle of it
		prev := make([]byte, 1)
		if _, err := f.ReadAt(prev, cursor.offset-1); err != nil || prev[0] != '\n' {
			skipFirstLine = true
		}
	}

	buf := make([]byte, size-cursor.offset)
	n, err := f.ReadAt(buf, cursor.offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, warning, err
	}
	buf = buf[:n]

	// An incomplete last line gets processed in the next run, after the application finished writing it.
	// If no line break is found at all and the buffer is full, the line is longer than max_read_bytes and gets processed anyway.
	end := bytes.LastIndexByte(buf, '\n') + 1
	if end == 0 && int64(len(buf)) >= s.maxReadBytes {
		end = len(buf)
		// The buffer only contains a part of this line, so it must not be discarded
		skipFirstLine = false
	}
	cursor.offset += int64(end)
	buf = buf[:end]

	now := logfileNow()
	var entries []*logEntry
	for len(buf) > 0 {
		var line []byte
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			line, buf = buf[:i], buf[i+1:]
		} else {
			line, buf = buf, nil
		}
		if skipFirstLine {
			skipFirstLine = false
			continue
		}
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		entries = append(entries, &logEntry{
			Timestamp: now,
			Source:    path,
			Line:      string(line),
		})
	}

	return entries, warning, nil
}

// Make sure the type implements the interface
var _ logSource = (*fileLogSource)(nil)
