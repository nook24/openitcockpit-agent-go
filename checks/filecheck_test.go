package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

func writeTestFile(t *testing.T, path string, size int, modified time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
}

func runFileCheck(t *testing.T, definition *config.FileDefinition) interface{} {
	t.Helper()
	definition.Name = "test"
	if definition.MaxFiles == 0 {
		definition.MaxFiles = 100000
	}
	c := &CheckFile{}
	if enabled, _ := c.Configure(&config.Configuration{FileConfiguration: []*config.FileDefinition{definition}}); !enabled {
		t.Fatal("check should be enabled")
	}
	r, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	return r.(map[string]interface{})["test"]
}

func runFileCheckOK(t *testing.T, definition *config.FileDefinition) *resultFileCheck {
	t.Helper()
	r := runFileCheck(t, definition)
	res, ok := r.(*resultFileCheck)
	if !ok {
		t.Fatalf("unexpected result: %+v", r)
	}
	return res
}

func TestCheckFileGlob(t *testing.T) {
	now := time.Unix(1700000000, 0)
	fileCheckNow = func() time.Time { return now }
	defer func() { fileCheckNow = time.Now }()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "db-1.sql.gz"), 100, now.Add(-48*time.Hour))
	writeTestFile(t, filepath.Join(dir, "db-2.sql.gz"), 200, now.Add(-time.Hour))

	res := runFileCheckOK(t, &config.FileDefinition{Type: config.FileTypeFile, Path: filepath.Join(dir, "db-*.sql.gz")})
	if !res.Exists || len(res.Files) != 2 {
		t.Fatalf("expected 2 files: %+v", res)
	}
	if res.Files[1].Size != 200 || res.Files[1].Age != 3600 || res.Files[1].Modified != now.Add(-time.Hour).Unix() {
		t.Errorf("unexpected file: %+v", res.Files[1])
	}

	res = runFileCheckOK(t, &config.FileDefinition{Type: config.FileTypeFile, Path: filepath.Join(dir, "missing.txt")})
	if res.Exists || len(res.Files) != 0 {
		t.Errorf("file must not exist: %+v", res)
	}
}

func TestCheckDirectory(t *testing.T) {
	now := time.Unix(1700000000, 0)
	fileCheckNow = func() time.Time { return now }
	defer func() { fileCheckNow = time.Now }()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "a.tar.gz"), 10, now.Add(-3*time.Hour))
	writeTestFile(t, filepath.Join(dir, "b.tar.gz"), 20, now.Add(-1*time.Hour))
	writeTestFile(t, filepath.Join(dir, "notes.txt"), 5, now.Add(-10*time.Hour))
	writeTestFile(t, filepath.Join(dir, "sub", "c.tar.gz"), 30, now.Add(-time.Minute))

	res := runFileCheckOK(t, &config.FileDefinition{Type: config.FileTypeDirectory, Path: dir})
	if !res.Exists || res.FileCount != 3 || res.TotalSize != 35 || res.Truncated {
		t.Errorf("unexpected result: %+v", res)
	}
	if res.Newest.Age != 3600 || res.Oldest.Age != 36000 {
		t.Errorf("unexpected newest/oldest: %+v %+v", res.Newest, res.Oldest)
	}

	res = runFileCheckOK(t, &config.FileDefinition{Type: config.FileTypeDirectory, Path: dir, Pattern: "*.tar.gz", Recursive: true})
	if res.FileCount != 3 || res.TotalSize != 60 || filepath.Base(res.Newest.Path) != "c.tar.gz" || filepath.Base(res.Oldest.Path) != "a.tar.gz" {
		t.Errorf("unexpected result: %+v", res)
	}

	res = runFileCheckOK(t, &config.FileDefinition{Type: config.FileTypeDirectory, Path: dir, MaxFiles: 2})
	if res.FileCount != 2 || !res.Truncated || len(res.Warnings) != 1 {
		t.Errorf("expected truncated result: %+v", res)
	}

	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0700); err != nil {
		t.Fatal(err)
	}
	res = runFileCheckOK(t, &config.FileDefinition{Type: config.FileTypeDirectory, Path: empty})
	if !res.Exists || res.FileCount != 0 || res.Newest != nil || res.Oldest != nil {
		t.Errorf("unexpected result for empty directory: %+v", res)
	}

	res = runFileCheckOK(t, &config.FileDefinition{Type: config.FileTypeDirectory, Path: filepath.Join(dir, "missing")})
	if res.Exists {
		t.Errorf("directory must not exist: %+v", res)
	}

	if r, ok := runFileCheck(t, &config.FileDefinition{Type: config.FileTypeDirectory, Path: filepath.Join(dir, "notes.txt")}).(map[string]string); !ok || !strings.Contains(r["error"], "not a directory") {
		t.Errorf("expected not a directory error: %+v", r)
	}
}

func TestCheckDirectorySymlink(t *testing.T) {
	now := time.Unix(1700000000, 0)
	fileCheckNow = func() time.Time { return now }
	defer func() { fileCheckNow = time.Now }()

	dir := t.TempDir()
	target := filepath.Join(dir, "data", "backups")
	writeTestFile(t, filepath.Join(target, "a.tar.gz"), 10, now.Add(-3*time.Hour))
	writeTestFile(t, filepath.Join(target, "b.tar.gz"), 20, now.Add(-1*time.Hour))
	link := filepath.Join(dir, "backups")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not supported: %s", err)
	}

	// The root of the walk is a symlink, the paths start with the configured path
	res := runFileCheckOK(t, &config.FileDefinition{Type: config.FileTypeDirectory, Path: link})
	if !res.Exists || res.FileCount != 2 || res.TotalSize != 30 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Newest.Path != filepath.Join(link, "b.tar.gz") {
		t.Errorf("unexpected path of the newest file: %s", res.Newest.Path)
	}

	// A trailing separator does not hide the files of a non recursive check
	res = runFileCheckOK(t, &config.FileDefinition{Type: config.FileTypeDirectory, Path: target + string(filepath.Separator)})
	if res.FileCount != 2 {
		t.Errorf("unexpected result with trailing separator: %+v", res)
	}
}
