package loghandler

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestLogHandler(t *testing.T) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "*-test")
	if err != nil {
		log.Fatalln(err)
	}
	defer os.RemoveAll(tempDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stderr := bytes.Buffer{}

	lh := &LogHandler{
		LogPath:       filepath.Join(tempDir, "agent.log"),
		Debug:         true,
		Verbose:       true,
		LogRotate:     2,
		DefaultWriter: &stderr,
	}
	lh.Start(ctx)

	done := make(chan struct{})
	go func() {
		lh.Shutdown()
		done <- struct{}{}
	}()

	select {
	case <-done:
		// ok
	case <-time.After(time.Second * 5):
		t.Fatal("timeout for shutdown of loghandler")
	}
}

func TestLogHandlerRotate(t *testing.T) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "*-test")
	if err != nil {
		log.Fatalln(err)
	}
	defer os.RemoveAll(tempDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stderr := bytes.Buffer{}

	lh := &LogHandler{
		LogPath:       filepath.Join(tempDir, "agent.log"),
		Debug:         true,
		Verbose:       true,
		LogRotate:     2,
		DefaultWriter: &stderr,
	}
	midnight = func() time.Duration {
		return time.Second / 4
	}
	lh.Start(ctx)

	done := make(chan struct{})
	ticker := time.Tick(time.Second / 8)
	timeout := time.After(time.Second * 2)

outerfor:
	for {
		select {
		case <-timeout:
			t.Fatal("timeout for log rotate")
		case <-ticker:
			name1 := filepath.Join(tempDir, fmt.Sprintf("%s.%d", "agent.log", 1))
			name2 := filepath.Join(tempDir, fmt.Sprintf("%s.%d", "agent.log", 2))
			if _, err := os.Stat(name1); !os.IsNotExist(err) {
				if _, err := os.Stat(name2); !os.IsNotExist(err) {
					if _, err := os.Stat(filepath.Join(tempDir, "agent.log")); !os.IsNotExist(err) {
						break outerfor
					}
				}
			}
		}
	}

	go func() {
		lh.Shutdown()
		done <- struct{}{}
	}()

	select {
	case <-done:
		// ok
	case <-time.After(time.Second * 5):
		t.Fatal("timeout for shutdown of loghandler")
	}
}

func TestLogHandlerCancel(t *testing.T) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "*-test")
	if err != nil {
		log.Fatalln(err)
	}
	defer os.RemoveAll(tempDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stderr := bytes.Buffer{}

	lh := &LogHandler{
		Debug:         true,
		Verbose:       true,
		LogPath:       filepath.Join(tempDir, "agent.log"),
		LogRotate:     2,
		DefaultWriter: &stderr,
	}
	lh.Start(ctx)

	// The log file is opened by Start
	if _, err := os.Stat(lh.LogPath); err != nil {
		t.Fatal("log file was not created: ", err)
	}

	cancel()

	// The log handler closes the log file after the context got canceled
	stopped := make(chan struct{})
	go func() {
		lh.wg.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second * 2):
		t.Fatal("timeout for cancel loghandler")
	}
	if lh.logFile != nil {
		t.Error("the log file was not closed")
	}
}

// The agent must keep running if the log file can not be created, e.g. if the disk is full (issue #99)
func TestLogHandlerFileNotWritable(t *testing.T) {
	defer func(interval time.Duration) { logFileRetryInterval = interval }(logFileRetryInterval)
	logFileRetryInterval = 20 * time.Millisecond

	tempDir := t.TempDir()
	// A file instead of the log directory, so the log file can not be created
	blocker := filepath.Join(tempDir, "log")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(blocker, "agent.log")

	stderr := bytes.Buffer{}
	lh := &LogHandler{
		LogPath:       logPath,
		Verbose:       true,
		LogRotate:     2,
		DefaultWriter: &stderr,
	}
	lh.Start(context.Background())
	log.Warningln("before the log file can be created")
	time.Sleep(100 * time.Millisecond)

	// The disk got free again
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		log.Warningln("after the log file got created")
		if data, err := os.ReadFile(logPath); err == nil && bytes.Contains(data, []byte("after the log file got created")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the log file was not opened again")
		}
		time.Sleep(20 * time.Millisecond)
	}
	lh.Shutdown()

	output := stderr.String()
	if n := strings.Count(output, "could not open/create log file"); n != 1 {
		t.Errorf("expected the error once, got %d times:\n%s", n, output)
	}
	if !strings.Contains(output, "before the log file can be created") || !strings.Contains(output, "log file could be opened again") {
		t.Errorf("unexpected output:\n%s", output)
	}
}
