package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testMdstat = `Personalities : [raid1] [raid6] [raid5] [raid4]
md1 : active raid1 sdb1[1] sda1[0]
      1046528 blocks super 1.2 [2/2] [UU]
      bitmap: 0/1 pages [0KB], 65536KB chunk

md2 : active raid5 sdd1[3](F) sdc1[1] sde1[0]
      2093056 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/2] [UU_]

md3 : active raid1 sdg1[2] sdf1[0]
      1046528 blocks super 1.2 [2/1] [U_]
      [=>...................]  recovery =  8.5% (89472/1046528) finish=0.1min speed=89472K/sec

md127 : inactive sdh[1](S) sdi[0](S)
      6306 blocks super external:imsm

md4 : inactive sdj1[0](S)
      1046528 blocks super 1.2

unused devices: <none>
`

func writeTestProcFile(t *testing.T, procPath, name, content string) {
	t.Helper()
	path := filepath.Join(procPath, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func newTestProc(t *testing.T) string {
	t.Helper()
	procPath := t.TempDir()
	writeTestProcFile(t, procPath, "mdstat", testMdstat)
	// sysfs of the md devices, see runSystemHealth
	for name, version := range map[string]string{"md1": "1.2", "md2": "1.2", "md3": "1.2", "md4": "1.2", "md127": "external:imsm"} {
		writeTestProcFile(t, procPath, "sys-test/block/"+name+"/md/metadata_version", version+"\n")
	}
	writeTestProcFile(t, procPath, "vmstat", "nr_free_pages 123\noom_kill 2\nnr_zone_active_anon 5\n")
	writeTestProcFile(t, procPath, "sys/fs/file-nr", "1000\t0\t4000\n")
	writeTestProcFile(t, procPath, "sys/net/netfilter/nf_conntrack_count", "300\n")
	writeTestProcFile(t, procPath, "sys/net/netfilter/nf_conntrack_max", "1000\n")
	writeTestProcFile(t, procPath, "pressure/cpu", "some avg10=1.50 avg60=2.25 avg300=3.00 total=1234\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	writeTestProcFile(t, procPath, "pressure/memory", "some avg10=4.00 avg60=5.00 avg300=6.00 total=1234\nfull avg10=7.00 avg60=8.00 avg300=9.00 total=1234\n")
	writeTestProcFile(t, procPath, "pressure/io", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	return procPath
}

func runSystemHealth(t *testing.T, procPath string) map[string]interface{} {
	t.Helper()
	r, err := (&CheckSystemHealth{procPath: procPath, sysPath: filepath.Join(procPath, "sys-test")}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	return r.(map[string]interface{})
}

func resetOomKillState(t *testing.T) {
	oomKillStateMutex.Lock()
	oomKillState = nil
	oomKillStateMutex.Unlock()
	t.Cleanup(func() {
		oomKillStateMutex.Lock()
		oomKillState = nil
		oomKillStateMutex.Unlock()
	})
}

func TestCheckSystemHealth(t *testing.T) {
	resetOomKillState(t)
	procPath := newTestProc(t)
	result := runSystemHealth(t, procPath)

	raids := result["raid"].([]*resultRaid)
	if len(raids) != 5 {
		t.Fatalf("expected 5 md devices, got %d", len(raids))
	}
	byName := map[string]*resultRaid{}
	for _, raid := range raids {
		byName[raid.Name] = raid
	}
	if md := byName["md1"]; md.ActivityState != "active" || md.Type != "raid1" || md.DisksActive != 2 || md.DisksTotal != 2 || md.DisksDown != 0 {
		t.Errorf("unexpected md1: %+v", md)
	}
	if md := byName["md2"]; md.DisksFailed != 1 || md.DisksDown != 1 || strings.Join(md.FailedDevices, ",") != "sdd1" {
		t.Errorf("unexpected md2: %+v", md)
	}
	if md := byName["md3"]; md.ActivityState != "recovering" || md.SyncPercent != 8.5 || md.DisksDown != 1 {
		t.Errorf("unexpected md3: %+v", md)
	}
	if md := byName["md127"]; md.ActivityState != "inactive" || md.DisksSpare != 2 || md.MetadataVersion != "external:imsm" {
		t.Errorf("unexpected md127: %+v", md)
	}
	// An inactive array, which could not be started because of missing disks
	if md := byName["md4"]; md.ActivityState != "inactive" || md.MetadataVersion != "1.2" {
		t.Errorf("unexpected md4: %+v", md)
	}
	if md := byName["md1"]; md.MetadataVersion != "1.2" {
		t.Errorf("unexpected metadata version of md1: %+v", md)
	}

	oom := result["oom_kills"].(*resultOomKills)
	if oom.Total != 2 || len(oom.Events) != 0 {
		t.Errorf("OOM kills before the agent started must not create an event: %+v", oom)
	}

	fds := result["file_descriptors"].(*resultFileDescriptors)
	if fds.Used != 1000 || fds.Max != 4000 || fds.Percent != 25 {
		t.Errorf("unexpected file descriptors: %+v", fds)
	}

	conntrack := result["conntrack"].(*resultConntrack)
	if !conntrack.Available || conntrack.Count != 300 || conntrack.Max != 1000 || conntrack.Percent != 30 {
		t.Errorf("unexpected conntrack: %+v", conntrack)
	}

	pressure := result["pressure"].(*resultPressure)
	if !pressure.Available || pressure.Resources["cpu"].Some.Avg60 != 2.25 || pressure.Resources["memory"].Full.Avg300 != 9 {
		t.Errorf("unexpected pressure: %+v", pressure)
	}

	// New OOM kills get reported as event
	writeTestProcFile(t, procPath, "vmstat", "oom_kill 5\n")
	result = runSystemHealth(t, procPath)
	oom = result["oom_kills"].(*resultOomKills)
	if oom.Total != 5 || len(oom.Events) != 1 || oom.Events[0].Count != 3 || oom.Events[0].Timestamp == 0 {
		t.Errorf("expected one OOM kill event with 3 kills: %+v", oom)
	}

	// Unchanged counter
	result = runSystemHealth(t, procPath)
	if oom = result["oom_kills"].(*resultOomKills); len(oom.Events) != 1 {
		t.Errorf("expected still one OOM kill event: %+v", oom)
	}
}

func TestCheckSystemHealthUnavailable(t *testing.T) {
	resetOomKillState(t)
	procPath := t.TempDir()
	writeTestProcFile(t, procPath, "vmstat", "nr_free_pages 123\n")
	writeTestProcFile(t, procPath, "sys/fs/file-nr", "garbage\n")

	result := runSystemHealth(t, procPath)

	if raids := result["raid"].([]*resultRaid); len(raids) != 0 {
		t.Errorf("expected no md devices: %+v", raids)
	}
	if conntrack := result["conntrack"].(*resultConntrack); conntrack.Available {
		t.Errorf("conntrack must not be available: %+v", conntrack)
	}
	if pressure := result["pressure"].(*resultPressure); pressure.Available {
		t.Errorf("pressure must not be available: %+v", pressure)
	}
	for _, part := range []string{"oom_kills", "file_descriptors"} {
		if res, ok := result[part].(map[string]string); !ok || res["error"] == "" {
			t.Errorf("expected error for %s: %+v", part, result[part])
		}
	}
}
