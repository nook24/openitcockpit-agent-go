package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testZpoolList = "rpool\t998579896320\t123456789012\t875123107308\t3\t12\tONLINE\t1.00\n" +
	"tank\t15994458210304\t13435344896000\t2559113314304\t41\t84\tDEGRADED\t1.00\n" +
	"backup\t3985729650688\t1029392947200\t2956336703488\t-\t25\tONLINE\t1.00x\n"

const testZpoolStatus = `  pool: backup
 state: ONLINE
status: One or more devices has experienced an error resulting in data
	corruption.  Applications may be affected.
action: Restore the file in question if possible.  Otherwise restore the
	entire pool from backup.
   see: https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-8A
  scan: scrub repaired 128K in 02:13:45 with 2 errors on Sun Oct 12 02:37:45 2025
config:

	NAME                                  STATE     READ WRITE CKSUM
	backup                                ONLINE       0     0     0
	  ata-WDC_WD40EFRX-68N32N0_WD-WCC7K1  ONLINE       0     0    14

errors: 2 data errors, use '-v' for a list

  pool: rpool
 state: ONLINE
  scan: scrub repaired 0B in 00:01:23 with 0 errors on Sun Oct 12 00:25:24 2025
config:

	NAME                                                  STATE     READ WRITE CKSUM
	rpool                                                 ONLINE       0     0     0
	  mirror-0                                            ONLINE       0     0     0
	    ata-Samsung_SSD_870_EVO_1TB_S6PTNX0R123456A-part3  ONLINE       0     0     0
	    ata-Samsung_SSD_870_EVO_1TB_S6PTNX0R123457B-part3  ONLINE       0     0     0

errors: No known data errors

  pool: tank
 state: DEGRADED
status: One or more devices is currently being resilvered.  The pool will
	continue to function, possibly in a degraded state.
action: Wait for the resilver to complete.
  scan: resilver in progress since Mon Oct 13 08:12:01 2025
	5.12T / 12.2T scanned at 812M/s, 3.01T / 12.2T issued at 478M/s
	512G resilvered, 24.67% done, 05:36:12 to go
config:

	NAME                        STATE     READ WRITE CKSUM
	tank                        DEGRADED     0     0     0
	  raidz2-0                  DEGRADED     0     0     0
	    sda                     ONLINE       0     0     0
	    sdb                     ONLINE       0     0     0
	    replacing-2             DEGRADED     0     0     0
	      2207285621433212345   UNAVAIL      0     0     0  was /dev/sdc1
	      sdg                   ONLINE       0     0     0  (resilvering)
	    sdd                     ONLINE    1.2K     0     0
	logs
	  nvme0n1p1                 ONLINE       0     0     0
	cache
	  nvme0n1p2                 ONLINE       0     0     0
	spares
	  sdz                       AVAIL

errors: No known data errors
`

// Output of older ZFS versions (e.g. 0.7) and a canceled scrub
const testZpoolStatusOld = `  pool: data
 state: ONLINE
  scan: scrub canceled on Fri Mar  3 10:05:00 2023
config:

	NAME        STATE     READ WRITE CKSUM
	data        ONLINE       0     0     0
	  sdb       ONLINE       0     0     0

errors: No known data errors

  pool: old
 state: ONLINE
  scan: scrub repaired 0 in 0h12m with 0 errors on Sun Mar  5 00:36:01 2023
config:

	NAME        STATE     READ WRITE CKSUM
	old         ONLINE       0     0     0
	  sdc       ONLINE       0     0     0

errors: No known data errors

  pool: never
 state: ONLINE
  scan: none requested
config:

	NAME        STATE     READ WRITE CKSUM
	never       ONLINE       0     0     0
	  sdd       ONLINE       0     0     0

errors: No known data errors
`

func TestParseZpoolList(t *testing.T) {
	pools, err := parseZpoolList(testZpoolList)
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 3 {
		t.Fatalf("expected 3 pools, got %d", len(pools))
	}
	if p := pools[0]; p.Name != "rpool" || p.Size != 998579896320 || p.Allocated != 123456789012 || p.Free != 875123107308 ||
		p.Fragmentation != 3 || p.Capacity != 12 || p.Health != "ONLINE" || p.DedupRatio != 1 {
		t.Errorf("unexpected pool: %+v", p)
	}
	if p := pools[1]; p.Health != "DEGRADED" || p.Capacity != 84 {
		t.Errorf("unexpected pool: %+v", p)
	}
	if p := pools[2]; p.Fragmentation != -1 || p.DedupRatio != 1 {
		t.Errorf("fragmentation must be -1 if not available: %+v", p)
	}

	if pools, err := parseZpoolList("no pools available\n"); err != nil || len(pools) != 0 {
		t.Errorf("expected no pools: %+v %v", pools, err)
	}
}

func TestParseZpoolStatus(t *testing.T) {
	location := time.UTC
	pools := parseZpoolStatus(testZpoolStatus, location)
	if len(pools) != 3 {
		t.Fatalf("expected 3 pools, got %d", len(pools))
	}

	rpool := pools["rpool"]
	if rpool.Status != "" || rpool.DataErrors != 0 || len(rpool.Devices) != 4 {
		t.Errorf("unexpected rpool: %+v", rpool)
	}
	if s := rpool.Scan; s.Function != "scrub" || s.State != "finished" || s.Errors != 0 || s.Repaired != "0B" ||
		s.EndTime != time.Date(2025, 10, 12, 0, 25, 24, 0, location).Unix() {
		t.Errorf("unexpected scan: %+v", s)
	}
	if d := rpool.Devices[2]; d.Depth != 2 || d.State != "ONLINE" || d.Name != "ata-Samsung_SSD_870_EVO_1TB_S6PTNX0R123456A-part3" {
		t.Errorf("unexpected device: %+v", d)
	}

	backup := pools["backup"]
	if backup.DataErrors != 2 || backup.Scan.Errors != 2 || backup.Scan.Repaired != "128K" || backup.Devices[1].ChecksumErrors != 14 {
		t.Errorf("unexpected backup pool: %+v %+v", backup, backup.Scan)
	}
	if backup.Status != "One or more devices has experienced an error resulting in data corruption.  Applications may be affected." {
		t.Errorf("unexpected status: %q", backup.Status)
	}

	tank := pools["tank"]
	if s := tank.Scan; s.Function != "resilver" || s.State != "in_progress" || s.ProgressPercent != 24.67 ||
		s.StartTime != time.Date(2025, 10, 13, 8, 12, 1, 0, location).Unix() {
		t.Errorf("unexpected scan: %+v", s)
	}
	byName := map[string]*resultZfsDevice{}
	for _, device := range tank.Devices {
		byName[device.Name] = device
	}
	if d := byName["2207285621433212345"]; d == nil || d.State != "UNAVAIL" || d.Status != "was /dev/sdc1" || d.Depth != 3 {
		t.Errorf("unexpected device: %+v", d)
	}
	if d := byName["sdg"]; d == nil || d.Status != "(resilvering)" {
		t.Errorf("unexpected device: %+v", d)
	}
	if d := byName["sdd"]; d == nil || d.ReadErrors != 1200 {
		t.Errorf("abbreviated error count not parsed: %+v", d)
	}
	if d := byName["logs"]; d == nil || d.State != "" || d.Depth != 0 {
		t.Errorf("unexpected section: %+v", d)
	}
	if d := byName["sdz"]; d == nil || d.State != "AVAIL" {
		t.Errorf("unexpected spare: %+v", d)
	}

	old := parseZpoolStatus(testZpoolStatusOld, location)
	if s := old["data"].Scan; s.Function != "scrub" || s.State != "canceled" || s.EndTime != time.Date(2023, 3, 3, 10, 5, 0, 0, location).Unix() {
		t.Errorf("unexpected canceled scan: %+v", s)
	}
	if s := old["old"].Scan; s.State != "finished" || s.Repaired != "0" || s.EndTime == 0 {
		t.Errorf("unexpected old scan format: %+v", s)
	}
	if s := old["never"].Scan; s.Function != "none" || s.State != "none" {
		t.Errorf("unexpected scan: %+v", s)
	}
}

func TestZfsArc(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arcstats")
	write := func(hits, misses string) {
		content := "13 1 0x01 147 39984 4237475373 2398732827873\n" +
			"name                            type data\n" +
			"hits                            4    " + hits + "\n" +
			"misses                          4    " + misses + "\n" +
			"c                               4    8589934592\n" +
			"c_min                           4    1073741824\n" +
			"c_max                           4    17179869184\n" +
			"size                            4    8053063680\n"
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	zfsArcMutex.Lock()
	zfsArcLastHits, zfsArcLastMisses = 0, 0
	zfsArcMutex.Unlock()

	write("900000", "100000")
	arc, err := getZfsArc(path)
	if err != nil {
		t.Fatal(err)
	}
	if arc.Size != 8053063680 || arc.TargetSize != 8589934592 || arc.MinSize != 1073741824 || arc.MaxSize != 17179869184 ||
		arc.HitRatioTotal != 90 || arc.HitRatio != -1 {
		t.Errorf("unexpected arc: %+v", arc)
	}

	// 500 hits and 500 misses since the last run
	write("900500", "100500")
	if arc, _ = getZfsArc(path); arc.HitRatio != 50 {
		t.Errorf("expected hit ratio of the interval 50%%: %+v", arc)
	}
}

func TestCheckZfsWithoutZpool(t *testing.T) {
	c := &CheckZfs{arcStatsPath: filepath.Join(t.TempDir(), "missing")}
	r, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	result := r.(map[string]interface{})
	for _, part := range []string{"pools", "arc"} {
		if res, ok := result[part].(map[string]string); !ok || res["error"] == "" {
			t.Errorf("expected error for %s without ZFS: %+v", part, result[part])
		}
	}
}

// Real output of OpenZFS 2.4.2 on Proxmox VE 9.2: a running scrub, a degraded mirror, permanent data errors
// and a pool which was never scrubbed (no scan line at all)
const testZpoolStatusOpenZFS24Scrub = `  pool: oitc-repair
 state: ONLINE
status: One or more devices has experienced an unrecoverable error.  An
	attempt was made to correct the error.  Applications are unaffected.
action: Determine if the device needs to be replaced, and clear the errors
	using 'zpool clear' or replace the device with 'zpool replace'.
   see: https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-9P
  scan: scrub in progress since Tue Oct 13 20:08:31 2026
	259M / 259M scanned, 10.5M / 257M issued at 10.5M/s
	0B repaired, 4.09% done, 00:00:23 to go
config:

	NAME                      STATE     READ WRITE CKSUM
	oitc-repair               ONLINE       0     0     0
	  mirror-0                ONLINE       0     0     0
	    /var/tmp/oitc-zfs/c1  ONLINE       0     0     0
	    /var/tmp/oitc-zfs/c2  ONLINE       0     0   404

errors: No known data errors
`

const testZpoolStatusOpenZFS24 = `  pool: oitc-mirror
 state: DEGRADED
status: One or more devices has been taken offline by the administrator.
	Sufficient replicas exist for the pool to continue functioning in a
	degraded state.
action: Online the device using 'zpool online' or replace the device with
	'zpool replace'.
  scan: scrub repaired 0B in 00:00:01 with 0 errors on Tue Oct 13 20:05:27 2026
config:

	NAME                      STATE     READ WRITE CKSUM
	oitc-mirror               DEGRADED     0     0     0
	  mirror-0                DEGRADED     0     0     0
	    /var/tmp/oitc-zfs/m1  ONLINE       0     0     0
	    /var/tmp/oitc-zfs/m2  OFFLINE      0     0     0

errors: No known data errors

  pool: oitc-single
 state: ONLINE
status: One or more devices has experienced an error resulting in data
	corruption.  Applications may be affected.
action: Restore the file in question if possible.  Otherwise restore the
	entire pool from backup.
   see: https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-8A
  scan: scrub repaired 51.5K in 00:00:01 with 399 errors on Tue Oct 13 20:05:37 2026
config:

	NAME                    STATE     READ WRITE CKSUM
	oitc-single             ONLINE       0     0     0
	  /var/tmp/oitc-zfs/s1  ONLINE       0     0   813

errors: 399 data errors, use '-v' for a list

  pool: rpool
 state: ONLINE
config:

	NAME                                           STATE     READ WRITE CKSUM
	rpool                                          ONLINE       0     0     0
	  ata-VBOX_HARDDISK_VB5e5ef1e0-8c396fbd-part3  ONLINE       0     0     0

errors: No known data errors
`

func TestParseZpoolStatusOpenZFS24(t *testing.T) {
	location := time.Local
	scrub := parseZpoolStatus(testZpoolStatusOpenZFS24Scrub, location)["oitc-repair"]
	if scrub == nil {
		t.Fatal("pool oitc-repair not found")
	}
	if s := scrub.Scan; s.Function != "scrub" || s.State != "in_progress" || s.ProgressPercent != 4.09 || s.StartTime == 0 {
		t.Errorf("unexpected running scrub: %+v", s)
	}
	if d := scrub.Devices[3]; d.Name != "/var/tmp/oitc-zfs/c2" || d.ChecksumErrors != 404 {
		t.Errorf("unexpected device: %+v", d)
	}

	pools := parseZpoolStatus(testZpoolStatusOpenZFS24, location)
	if p := pools["oitc-mirror"]; p == nil || p.Devices[3].State != "OFFLINE" || p.Scan.State != "finished" || p.Scan.Errors != 0 {
		t.Errorf("unexpected degraded mirror: %+v", p)
	}
	if p := pools["oitc-single"]; p == nil || p.DataErrors <= 0 || p.Scan.Errors <= 0 || p.Devices[1].ChecksumErrors <= 0 {
		t.Errorf("unexpected pool with data errors: %+v %+v", p, p.Scan)
	}
	if p := pools["rpool"]; p == nil || p.Scan.State != "none" || p.DataErrors != 0 || len(p.Devices) != 2 {
		t.Errorf("unexpected rpool without scan line: %+v", p)
	}
}
