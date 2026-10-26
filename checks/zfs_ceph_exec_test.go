//go:build linux
// +build linux

package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installFakeCommand creates a shell script in a temporary directory of the PATH
func installFakeCommand(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
}

func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckZfsWithFakeZpool(t *testing.T) {
	dir := t.TempDir()
	list := writeFixture(t, dir, "list.txt", testZpoolList)
	status := writeFixture(t, dir, "status.txt", testZpoolStatus)
	// The fake command only answers the expected arguments and checks the language environment
	installFakeCommand(t, dir, "zpool", `
[ "$LC_ALL" = "C" ] || { echo "LC_ALL not set" >&2; exit 1; }
case "$*" in
  "list -Hp -o name,size,allocated,free,fragmentation,capacity,health,dedupratio") cat `+list+` ;;
  "status -p") cat `+status+` ;;
  *) echo "unexpected arguments: $*" >&2; exit 2 ;;
esac
`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	r, err := (&CheckZfs{arcStatsPath: filepath.Join(dir, "missing")}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(r)
	pools, ok := r.(map[string]interface{})["pools"].([]*resultZfsPool)
	if !ok || len(pools) != 3 {
		t.Fatalf("unexpected result: %s", js)
	}
	// zpool list and zpool status are merged
	if p := pools[1]; p.Name != "tank" || p.Health != "DEGRADED" || p.Capacity != 84 || p.Scan.State != "in_progress" || len(p.Devices) == 0 {
		t.Errorf("unexpected pool: %+v", p)
	}
}

func TestCheckCephWithFakeCeph(t *testing.T) {
	dir := t.TempDir()
	status := writeFixture(t, dir, "status.json", testCephStatusReef)
	df := writeFixture(t, dir, "df.json", testCephDf)
	installFakeCommand(t, dir, "ceph", `
case "$*" in
  "status --format json --connect-timeout 10") cat `+status+` ;;
  "df --format json --connect-timeout 10") cat `+df+` ;;
  *) echo "unexpected arguments: $*" >&2; exit 2 ;;
esac
`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	r, err := (&CheckCeph{}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(r)
	result := r.(map[string]interface{})
	if pools, ok := result["pools"].([]*resultCephPool); !ok || len(pools) != 3 {
		t.Errorf("unexpected pools: %s", js)
	}
	// The usage of ceph df replaces the usage of ceph status
	if usage := result["usage"].(*resultCephUsage); usage.UsedPercent < 27.49 || usage.UsedPercent > 27.5 {
		t.Errorf("unexpected usage: %+v", usage)
	}
	if health := result["health"].(*resultCephHealth); health.Status != "HEALTH_WARN" {
		t.Errorf("unexpected health: %+v", health)
	}
}

func TestCheckCephErrors(t *testing.T) {
	dir := t.TempDir()
	installFakeCommand(t, dir, "ceph", `
case "$1" in
  status) echo "[errno 110] RADOS timed out (error connecting to the cluster)" >&2; exit 1 ;;
esac
`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := (&CheckCeph{}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "RADOS timed out") {
		t.Errorf("expected the error of the ceph command, got: %v", err)
	}

	// Ceph 20 only prints "timed out" if no monitor answered within --connect-timeout
	installFakeCommand(t, dir, "ceph", `echo "timed out" >&2; exit 1`)
	_, err = (&CheckCeph{}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "monitors are not reachable") {
		t.Errorf("expected a timeout error, got: %v", err)
	}

	// ceph df fails, but ceph status works: only the pools report an error
	status := writeFixture(t, dir, "status.json", testCephStatusOctopus)
	installFakeCommand(t, dir, "ceph", `
case "$1" in
  status) cat `+status+` ;;
  df) echo "Error EACCES: access denied" >&2; exit 13 ;;
esac
`)
	r, err := (&CheckCeph{}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pools, ok := r.(map[string]interface{})["pools"].(map[string]string); !ok || !strings.Contains(pools["error"], "access denied") {
		t.Errorf("expected an error for the pools: %+v", r)
	}
}

func TestCheckCephCache(t *testing.T) {
	dir := t.TempDir()
	status := writeFixture(t, dir, "status.json", testCephStatusReef)
	df := writeFixture(t, dir, "df.json", testCephDf)
	calls := filepath.Join(dir, "calls")
	installFakeCommand(t, dir, "ceph", `
echo "$1" >> `+calls+`
case "$1" in
  status) cat `+status+` ;;
  df) cat `+df+` ;;
esac
`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	countCalls := func() int {
		data, _ := os.ReadFile(calls)
		return strings.Count(string(data), "\n")
	}

	check := &CheckCeph{}
	first, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The following runs within the cache time return the same result without calling ceph
	for i := 0; i < 3; i++ {
		r, err := check.Run(context.Background())
		if err != nil || r == nil {
			t.Fatal(err)
		}
		if r.(map[string]interface{})["health"] != first.(map[string]interface{})["health"] {
			t.Error("expected the cached result")
		}
	}
	if n := countCalls(); n != 2 {
		t.Errorf("expected 2 calls of ceph (status, df), got %d", n)
	}

	// After the cache time ceph is called again
	check.cachedAt = time.Now().Add(-cephCacheTime - time.Second)
	if _, err := check.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := countCalls(); n != 4 {
		t.Errorf("expected 4 calls of ceph, got %d", n)
	}

	// Errors are cached as well
	installFakeCommand(t, dir, "ceph", `echo "$1" >> `+calls+`; echo "timed out" >&2; exit 1`)
	check = &CheckCeph{}
	for i := 0; i < 2; i++ {
		if _, err := check.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "monitors are not reachable") {
			t.Errorf("expected a timeout error, got: %v", err)
		}
	}
	if n := countCalls(); n != 5 {
		t.Errorf("expected 5 calls of ceph, got %d", n)
	}

	// A canceled run is not cached
	check = &CheckCeph{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = check.Run(ctx)
	if !check.cachedAt.IsZero() {
		t.Error("a canceled run should not be cached")
	}
}
