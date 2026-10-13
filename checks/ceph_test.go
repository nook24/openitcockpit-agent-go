package checks

import (
	"testing"
)

// ceph status -f json of a Reef cluster (Proxmox VE 8), shortened
const testCephStatusReef = `{
  "fsid": "6b1e6c3a-2f4d-4b8e-9a1c-3d5e7f9a1b2c",
  "health": {
    "status": "HEALTH_WARN",
    "checks": {
      "OSD_DOWN": {"severity": "HEALTH_WARN", "summary": {"message": "1 osds down", "count": 1}, "muted": false},
      "PG_DEGRADED": {"severity": "HEALTH_WARN", "summary": {"message": "Degraded data redundancy: 1234/56789 objects degraded (2.173%), 12 pgs degraded", "count": 12}, "muted": false},
      "RECENT_CRASH": {"severity": "HEALTH_WARN", "summary": {"message": "1 daemons have recently crashed", "count": 1}, "muted": true}
    },
    "mutes": [{"code": "RECENT_CRASH", "sticky": false, "summary": "1 daemons have recently crashed", "count": 1}]
  },
  "election_epoch": 42,
  "quorum": [0, 1, 2],
  "quorum_names": ["pve1", "pve2", "pve3"],
  "quorum_age": 123456,
  "monmap": {"epoch": 3, "min_mon_release_name": "reef", "num_mons": 3},
  "osdmap": {"epoch": 1234, "num_osds": 6, "num_up_osds": 5, "osd_up_since": 1760000000, "num_in_osds": 6, "osd_in_since": 1750000000, "num_remapped_pgs": 0},
  "pgmap": {
    "pgs_by_state": [
      {"state_name": "active+clean", "count": 117},
      {"state_name": "active+undersized+degraded", "count": 12}
    ],
    "num_pgs": 129,
    "num_pools": 3,
    "num_objects": 56789,
    "data_bytes": 1099511627776,
    "bytes_used": 3298534883328,
    "bytes_avail": 8697308085248,
    "bytes_total": 11995842968576,
    "degraded_objects": 1234,
    "degraded_total": 56789,
    "degraded_ratio": 0.021729,
    "read_bytes_sec": 1048576,
    "write_bytes_sec": 4194304,
    "read_op_per_sec": 120,
    "write_op_per_sec": 340
  },
  "fsmap": {
    "epoch": 15,
    "id": 1,
    "up": 1,
    "in": 1,
    "max": 1,
    "by_rank": [{"filesystem_id": 1, "rank": 0, "name": "pve1", "status": "up:active", "gid": 24123}],
    "up:standby": 2
  },
  "mgrmap": {"available": true, "num_standbys": 2, "modules": ["iostat", "restful"], "services": {}},
  "servicemap": {"epoch": 1, "modified": "2025-10-13T08:00:00.000000+0200", "services": {}},
  "progress_events": {}
}`

// ceph status -f json of an Octopus cluster (Proxmox VE 6/7) with the nested osdmap and the monitor list
const testCephStatusOctopus = `{
  "health": {"status": "HEALTH_OK", "checks": {}, "mutes": []},
  "quorum_names": ["node1", "node2", "node3"],
  "monmap": {"epoch": 1, "mons": [{"rank": 0, "name": "node1"}, {"rank": 1, "name": "node2"}, {"rank": 2, "name": "node3"}]},
  "osdmap": {"osdmap": {"epoch": 99, "num_osds": 9, "num_up_osds": 9, "num_in_osds": 9, "full": false, "nearfull": false}},
  "pgmap": {"pgs_by_state": [{"state_name": "active+clean", "count": 256}], "num_pgs": 256, "bytes_used": 100, "bytes_avail": 900, "bytes_total": 1000},
  "fsmap": {"epoch": 1, "by_rank": [], "up:standby": 0}
}`

// Real ceph status -f json of a single node Tentacle cluster (Proxmox VE 9) with HEALTH_ERR:
// one OSD down and out, the only MDS stopped, lowered full ratios and a muted health check
const testCephStatusTentacle = `{"fsid":"47c79f49-96a9-4c95-9206-253c2db6dec9","health":{"status":"HEALTH_ERR","checks":{"FS_DEGRADED":{"severity":"HEALTH_WARN","summary":{"message":"1 filesystem is degraded","count":1},"muted":false},"FS_WITH_FAILED_MDS":{"severity":"HEALTH_WARN","summary":{"message":"1 filesystem has a failed mds daemon","count":1},"muted":false},"MDS_ALL_DOWN":{"severity":"HEALTH_ERR","summary":{"message":"1 filesystem is offline","count":1},"muted":false},"OSD_FULL":{"severity":"HEALTH_ERR","summary":{"message":"2 full osd(s)","count":2},"muted":false},"PG_DEGRADED":{"severity":"HEALTH_WARN","summary":{"message":"Degraded data redundancy: 352/1056 objects degraded (33.333%), 128 pgs degraded, 153 pgs undersized","count":281},"muted":false},"POOL_FULL":{"severity":"HEALTH_WARN","summary":{"message":"4 pool(s) full","count":4},"muted":false},"POOL_TOO_MANY_PGS":{"severity":"HEALTH_WARN","summary":{"message":"1 pools have too many placement groups","count":1},"muted":true}},"mutes":[{"code":"POOL_TOO_MANY_PGS","sticky":false,"summary":"1 pools have too many placement groups","count":1}]},"election_epoch":5,"quorum":[0],"quorum_names":["pve"],"quorum_age":10,"monmap":{"epoch":1,"min_mon_release_name":"tentacle","num_mons":1},"osdmap":{"epoch":36,"num_osds":3,"num_up_osds":2,"osd_up_since":1791917745,"num_in_osds":2,"osd_in_since":1791917801,"num_remapped_pgs":0},"pgmap":{"pgs_by_state":[{"state_name":"active+undersized+degraded","count":128},{"state_name":"active+undersized","count":25}],"num_pgs":153,"num_pools":4,"num_objects":352,"data_bytes":1372130230,"bytes_used":2836897792,"bytes_avail":40104386560,"bytes_total":42941284352,"degraded_objects":352,"degraded_total":1056,"degraded_ratio":0.33333333333333326},"fsmap":{"epoch":5,"btime":"2026-10-13T20:56:41:778802+0200","id":1,"up":0,"in":1,"max":1,"by_rank":[],"up:standby":0,"failed":1},"mgrmap":{"available":true,"num_standbys":0,"modules":["iostat","nfs","nvmeof"],"services":{}},"servicemap":{"epoch":6,"modified":"2026-10-13T20:52:38.422539+0200","services":{}},"progress_events":{}}`

const testCephDf = `{
  "stats": {
    "total_bytes": 11995842968576,
    "total_avail_bytes": 8697308085248,
    "total_used_bytes": 3298534883328,
    "total_used_raw_bytes": 3298534883328,
    "total_used_raw_ratio": 0.27497,
    "num_osds": 6,
    "num_per_pool_osds": 6,
    "num_per_pool_omap_osds": 6
  },
  "stats_by_class": {"ssd": {"total_bytes": 11995842968576, "total_avail_bytes": 8697308085248, "total_used_bytes": 3298534883328, "total_used_raw_bytes": 3298534883328, "total_used_raw_ratio": 0.27497}},
  "pools": [
    {"name": ".mgr", "id": 1, "stats": {"stored": 2097152, "objects": 2, "kb_used": 6144, "bytes_used": 6291456, "percent_used": 0.0000002, "max_avail": 2684354560000}},
    {"name": "vm-storage", "id": 2, "stats": {"stored": 1099511627776, "objects": 262144, "kb_used": 3221225472, "bytes_used": 3298534883328, "percent_used": 0.29044, "max_avail": 2684354560000}},
    {"name": "cephfs_data", "id": 3, "stats": {"stored": 0, "objects": 0, "kb_used": 0, "bytes_used": 0, "percent_used": 0, "max_avail": 2684354560000}}
  ]
}`

func TestParseCephStatus(t *testing.T) {
	result, err := parseCephStatus([]byte(testCephStatusReef))
	if err != nil {
		t.Fatal(err)
	}

	health := result["health"].(*resultCephHealth)
	if health.Status != "HEALTH_WARN" || len(health.Checks) != 3 {
		t.Fatalf("unexpected health: %+v", health)
	}
	if c := health.Checks[0]; c.Code != "OSD_DOWN" || c.Severity != "HEALTH_WARN" || c.Message != "1 osds down" || c.Count != 1 || c.Muted {
		t.Errorf("unexpected check: %+v", c)
	}
	if c := health.Checks[2]; c.Code != "RECENT_CRASH" || !c.Muted {
		t.Errorf("unexpected muted check: %+v", c)
	}

	if m := result["monitors"].(*resultCephMonitors); m.Total != 3 || m.InQuorum != 3 || len(m.QuorumNames) != 3 {
		t.Errorf("unexpected monitors: %+v", m)
	}
	if o := result["osds"].(*resultCephOsds); o.Total != 6 || o.Up != 5 || o.In != 6 {
		t.Errorf("unexpected osds: %+v", o)
	}
	if p := result["pgs"].(*resultCephPgs); p.Total != 129 || p.States["active+clean"] != 117 || p.States["active+undersized+degraded"] != 12 {
		t.Errorf("unexpected pgs: %+v", p)
	}
	if u := result["usage"].(*resultCephUsage); u.TotalBytes != 11995842968576 || u.UsedPercent < 27.4 || u.UsedPercent > 27.6 {
		t.Errorf("unexpected usage: %+v", u)
	}
	if f := result["filesystems"].(*resultCephFilesystems); f.Up != 1 || f.Max != 1 || f.Standby != 2 || len(f.Mds) != 1 || f.Mds[0].State != "up:active" || f.Mds[0].Name != "pve1" {
		t.Errorf("unexpected filesystems: %+v", f)
	}
	if io := result["io"].(*resultCephIo); io.WriteBytesPerSecond != 4194304 || io.ReadOpsPerSecond != 120 {
		t.Errorf("unexpected io: %+v", io)
	}
}

func TestParseCephStatusOctopus(t *testing.T) {
	result, err := parseCephStatus([]byte(testCephStatusOctopus))
	if err != nil {
		t.Fatal(err)
	}
	if h := result["health"].(*resultCephHealth); h.Status != "HEALTH_OK" || len(h.Checks) != 0 {
		t.Errorf("unexpected health: %+v", h)
	}
	if m := result["monitors"].(*resultCephMonitors); m.Total != 3 || m.InQuorum != 3 {
		t.Errorf("the monitor count of the monitor list is expected: %+v", m)
	}
	if o := result["osds"].(*resultCephOsds); o.Total != 9 || o.Up != 9 || o.In != 9 {
		t.Errorf("the nested osdmap is not parsed: %+v", o)
	}
	if f := result["filesystems"].(*resultCephFilesystems); f.Up != 0 || len(f.Mds) != 0 {
		t.Errorf("unexpected filesystems: %+v", f)
	}

	if _, err := parseCephStatus([]byte("not json")); err == nil {
		t.Error("expected error for invalid output")
	}
}

func TestParseCephStatusTentacle(t *testing.T) {
	result, err := parseCephStatus([]byte(testCephStatusTentacle))
	if err != nil {
		t.Fatal(err)
	}

	health := result["health"].(*resultCephHealth)
	if health.Status != "HEALTH_ERR" || len(health.Checks) != 7 {
		t.Fatalf("unexpected health: %+v", health)
	}
	if c := health.Checks[2]; c.Code != "MDS_ALL_DOWN" || c.Severity != "HEALTH_ERR" || c.Message != "1 filesystem is offline" {
		t.Errorf("unexpected check: %+v", c)
	}
	if c := health.Checks[6]; c.Code != "POOL_TOO_MANY_PGS" || !c.Muted {
		t.Errorf("unexpected muted check: %+v", c)
	}
	if m := result["monitors"].(*resultCephMonitors); m.Total != 1 || m.InQuorum != 1 || m.QuorumNames[0] != "pve" {
		t.Errorf("unexpected monitors: %+v", m)
	}
	if o := result["osds"].(*resultCephOsds); o.Total != 3 || o.Up != 2 || o.In != 2 {
		t.Errorf("unexpected osds: %+v", o)
	}
	if p := result["pgs"].(*resultCephPgs); p.Total != 153 || p.States["active+undersized+degraded"] != 128 || p.States["active+undersized"] != 25 {
		t.Errorf("unexpected pgs: %+v", p)
	}
	if f := result["filesystems"].(*resultCephFilesystems); f.Up != 0 || f.In != 1 || f.Max != 1 || f.Standby != 0 || len(f.Mds) != 0 {
		t.Errorf("unexpected filesystems: %+v", f)
	}
}

func TestParseCephDf(t *testing.T) {
	pools, usage, err := parseCephDf([]byte(testCephDf))
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 3 {
		t.Fatalf("expected 3 pools, got %d", len(pools))
	}
	if p := pools[1]; p.Name != "vm-storage" || p.ID != 2 || p.StoredBytes != 1099511627776 || p.UsedPercent < 29.04 || p.UsedPercent > 29.05 || p.MaxAvailBytes != 2684354560000 || p.Objects != 262144 {
		t.Errorf("unexpected pool: %+v", p)
	}
	if usage.UsedPercent < 27.49 || usage.UsedPercent > 27.5 || usage.AvailableBytes != 8697308085248 {
		t.Errorf("unexpected usage: %+v", usage)
	}
}
