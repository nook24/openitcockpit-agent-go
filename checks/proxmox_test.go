package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testPveClusterStatus = `[
  {"id":"cluster","name":"pve-cluster","nodes":3,"quorate":1,"type":"cluster","version":7},
  {"id":"node/pve1","ip":"192.168.10.11","level":"","local":1,"name":"pve1","nodeid":1,"online":1,"type":"node"},
  {"id":"node/pve2","ip":"192.168.10.12","level":"","local":0,"name":"pve2","nodeid":2,"online":1,"type":"node"},
  {"id":"node/pve3","ip":"192.168.10.13","level":"","local":0,"name":"pve3","nodeid":3,"online":0,"type":"node"}
]`

const testPveClusterStatusSingle = `[{"id":"node/pve","ip":"192.168.10.20","level":"","local":1,"name":"pve","nodeid":0,"online":1,"type":"node"}]`

const testPveHaStatus = `[
  {"id":"quorum","node":"pve1","quorate":1,"status":"OK","type":"quorum"},
  {"id":"master","node":"pve1","status":"pve1 (active, Mon Oct 13 10:00:00 2025)","timestamp":1760342400,"type":"master"},
  {"id":"lrm:pve1","node":"pve1","status":"pve1 (active, Mon Oct 13 10:00:01 2025)","timestamp":1760342401,"type":"lrm"},
  {"id":"lrm:pve3","node":"pve3","status":"pve3 (old timestamp - dead?, Mon Oct 13 09:50:00 2025)","timestamp":1760341800,"type":"lrm"},
  {"crm_state":"started","id":"service:vm:100","max_relocate":1,"max_restart":1,"node":"pve1","request_state":"started","sid":"vm:100","state":"started","status":"vm:100 (pve1, started)","type":"service"},
  {"crm_state":"error","id":"service:ct:200","max_relocate":1,"max_restart":1,"node":"pve3","request_state":"started","sid":"ct:200","state":"error","status":"ct:200 (pve3, error)","type":"service"}
]`

// Storage entries of /cluster/resources (real output of Proxmox VE 9.2, oitc-nfs and oitc-usb are not available)
const testPveResourceStorages = `
  {"content":"backup","id":"storage/pve1/oitc-usb","node":"pve1","plugintype":"dir","shared":0,"status":"unknown","storage":"oitc-usb","type":"storage"},
  {"content":"backup","id":"storage/pve1/oitc-nfs","node":"pve1","plugintype":"nfs","shared":1,"status":"unknown","storage":"oitc-nfs","type":"storage"},
  {"content":"images,rootdir","disk":1664299827200,"id":"storage/pve1/local-lvm","maxdisk":1879048192000,"node":"pve1","plugintype":"lvmthin","shared":0,"status":"available","storage":"local-lvm","type":"storage"},
  {"content":"vztmpl,import,iso,backup","disk":97156325376,"id":"storage/pve1/local","maxdisk":502468108288,"node":"pve1","plugintype":"dir","shared":0,"status":"available","storage":"local","type":"storage"},
  {"content":"images","disk":100,"id":"storage/pve2/local-lvm","maxdisk":1000,"node":"pve2","plugintype":"lvmthin","shared":0,"status":"available","storage":"local-lvm","type":"storage"},
  {"cpu":0.0315,"disk":3313238016,"hastate":"online","id":"node/pve1","level":"","maxcpu":2,"maxdisk":40596799488,"maxmem":4104704000,"mem":2020179968,"node":"pve1","status":"online","type":"node","uptime":545},`

const testPveResources = `[` + testPveResourceStorages + `
  {"cpu":0.0123,"disk":0,"id":"qemu/100","maxcpu":4,"maxdisk":53687091200,"maxmem":8589934592,"mem":4294967296,"name":"web01","node":"pve1","status":"running","template":0,"type":"qemu","uptime":864000,"vmid":100,"hastate":"started","tags":"prod;web"},
  {"cpu":0,"id":"qemu/101","maxcpu":2,"maxmem":4294967296,"mem":0,"name":"db01","node":"pve1","status":"stopped","template":0,"type":"qemu","uptime":0,"vmid":101,"lock":"backup"},
  {"cpu":0,"id":"qemu/9000","maxcpu":2,"maxmem":2147483648,"mem":0,"name":"debian-template","node":"pve1","status":"stopped","template":1,"type":"qemu","uptime":0,"vmid":9000},
  {"cpu":0.002,"id":"lxc/102","maxcpu":1,"maxmem":536870912,"mem":104857600,"name":"dns01","node":"pve1","status":"running","template":0,"type":"lxc","uptime":3600,"vmid":102},
  {"cpu":0.05,"id":"lxc/200","maxcpu":2,"maxmem":1073741824,"mem":0,"name":"mail01","node":"pve3","status":"unknown","template":0,"type":"lxc","uptime":0,"vmid":200}
]`

const testPveTasks = `[
  {"endtime":1760320800,"id":"","node":"pve1","pid":12345,"pstart":123456789,"starttime":1760317200,"status":"job errors","type":"vzdump","upid":"UPID:pve1:00003039:075BCD15:68EC3A10:vzdump::root@pam:","user":"root@pam"},
  {"endtime":1760234400,"id":"","node":"pve1","pid":12000,"pstart":123000000,"starttime":1760230800,"status":"OK","type":"vzdump","upid":"UPID:pve1:00002EE0:0754D4C0:68EAE890:vzdump::root@pam:","user":"root@pam"},
  {"endtime":1760148000,"id":"101","node":"pve1","pid":11000,"pstart":122000000,"starttime":1760147000,"status":"WARNINGS: 1","type":"vzdump","upid":"UPID:pve1:00002AF8:07458F80:68E99708:vzdump:101:root@pam:","user":"root@pam"}
]`

const testPveNotBackedUp = `[{"name":"dns01","type":"lxc","vmid":102},{"name":"mail01","type":"lxc","vmid":200}]`

const testPveReplication = `[
  {"duration":3.214,"fail_count":0,"guest":100,"id":"100-0","jobnum":0,"last_sync":1760342100,"last_try":1760342100,"next_sync":1760343000,"schedule":"*/15","target":"pve2","type":"local","vmtype":"qemu"},
  {"duration":0.5,"error":"command 'zfs snapshot rpool/data/subvol-102-disk-0@__replicate_102-0_1760342100__' failed: exit code 1","fail_count":3,"guest":102,"id":"102-0","jobnum":0,"last_sync":1760300000,"last_try":1760342100,"next_sync":1760342400,"schedule":"*/15","target":"pve2","type":"local","vmtype":"lxc"}
]`

func TestParseProxmoxClusterStatus(t *testing.T) {
	cluster, local, err := parseProxmoxClusterStatus([]byte(testPveClusterStatus))
	if err != nil {
		t.Fatal(err)
	}
	if local != "pve1" || !cluster.Clustered || cluster.Name != "pve-cluster" || !cluster.Quorate || cluster.NodesTotal != 3 || cluster.NodesOnline != 2 || len(cluster.Nodes) != 3 {
		t.Errorf("unexpected cluster: %+v (local %s)", cluster, local)
	}
	if n := cluster.Nodes[2]; n.Name != "pve3" || n.Online || n.Local || n.IP != "192.168.10.13" {
		t.Errorf("unexpected node: %+v", n)
	}

	single, local, err := parseProxmoxClusterStatus([]byte(testPveClusterStatusSingle))
	if err != nil {
		t.Fatal(err)
	}
	if local != "pve" || single.Clustered || !single.Quorate || single.NodesTotal != 1 || single.NodesOnline != 1 {
		t.Errorf("unexpected single node: %+v", single)
	}
}

func TestParseProxmoxParts(t *testing.T) {
	ha, err := parseProxmoxHa([]byte(testPveHaStatus), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ha.Quorate || !strings.HasPrefix(ha.Master, "pve1 (active") || len(ha.Lrms) != 2 || len(ha.Services) != 2 {
		t.Errorf("unexpected ha: %+v", ha)
	}
	if s := ha.Services[1]; s.Sid != "ct:200" || s.State != "error" || s.Node != "pve3" || s.RequestState != "started" {
		t.Errorf("unexpected service: %+v", s)
	}

	guests, storages, err := parseProxmoxResources([]byte(testPveResources), nil, "pve1")
	if err != nil {
		t.Fatal(err)
	}
	// Only the storages of pve1
	if len(storages) != 4 {
		t.Fatalf("expected the 4 storages of pve1, got %d", len(storages))
	}
	if s := storages[2]; s.Storage != "local-lvm" || s.Type != "lvmthin" || !s.Active || !s.Enabled || s.UsedPercent < 88.5 || s.UsedPercent > 88.6 || s.Available != 1879048192000-1664299827200 {
		t.Errorf("unexpected storage: %+v", s)
	}
	if s := storages[1]; s.Storage != "oitc-nfs" || s.Active || !s.Enabled || !s.Shared || s.Type != "nfs" {
		t.Errorf("unexpected inactive storage: %+v", s)
	}
	if len(guests) != 5 {
		t.Fatalf("expected the 5 guests of the cluster, got %d", len(guests))
	}
	if g := guests[4]; g.Node != "pve3" || g.Status != "unknown" {
		t.Errorf("unexpected guest of another node: %+v", g)
	}
	if g := guests[0]; g.Vmid != 100 || g.Name != "web01" || g.Type != "qemu" || g.Status != "running" || g.HaState != "started" || g.Tags != "prod;web" || g.MaxMem != 8589934592 {
		t.Errorf("unexpected guest: %+v", g)
	}
	if g := guests[1]; g.Lock != "backup" || g.Status != "stopped" {
		t.Errorf("unexpected guest: %+v", g)
	}
	if g := guests[2]; !g.Template {
		t.Errorf("template expected: %+v", g)
	}

	backups, err := parseProxmoxBackups([]byte(testPveTasks), nil, []byte(testPveNotBackedUp), nil, guests, "pve1")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups.Tasks) != 3 || backups.Tasks[0].Status != "job errors" || backups.Tasks[2].ID != "101" || backups.Tasks[0].EndTime != 1760320800 {
		t.Errorf("unexpected tasks: %+v", backups.Tasks)
	}
	// mail01 runs on pve3
	if len(backups.NotBackedUp) != 1 || backups.NotBackedUp[0].Vmid != 102 {
		t.Errorf("unexpected not backed up guests: %+v", backups.NotBackedUp)
	}

	replication, err := parseProxmoxReplication([]byte(testPveReplication), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := replication[1]; r.ID != "102-0" || r.FailCount != 3 || !strings.Contains(r.Error, "zfs snapshot") || r.Target != "pve2" || r.LastSync != 1760300000 {
		t.Errorf("unexpected replication: %+v", r)
	}
}

func TestCheckProxmoxWithFakePvesh(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	resetProxmoxCollector()
	t.Cleanup(resetProxmoxCollector)

	dir := t.TempDir()
	fixtures := map[string]string{
		"status": testPveClusterStatus, "ha": testPveHaStatus, "resources": testPveResources,
		"tasks": testPveTasks, "notbackedup": testPveNotBackedUp,
	}
	for name, content := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Replication is not configured on this node, pvesh fails for this part only
	script := `#!/bin/sh
case "$*" in
  "get /cluster/status --output-format json") cat ` + dir + `/status.json ;;
  "get /cluster/ha/status/current --output-format json") cat ` + dir + `/ha.json ;;
  "get /cluster/resources --output-format json") cat ` + dir + `/resources.json ;;
  "get /nodes/pve1/tasks --typefilter vzdump --limit 50 --output-format json") cat ` + dir + `/tasks.json ;;
  "get /cluster/backup-info/not-backed-up --output-format json") cat ` + dir + `/notbackedup.json ;;
  "get /nodes/pve1/replication --output-format json") echo "replication not available" >&2; exit 2 ;;
  *) echo "unexpected arguments: $*" >&2; exit 1 ;;
esac
`
	pvesh := filepath.Join(dir, "pvesh")
	if err := os.WriteFile(pvesh, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	r, err := (&CheckProxmox{pvesh: pvesh}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Backups and replication are collected in the background after the first run
	for i := 0; i < 50; i++ {
		proxmoxState.mutex.Lock()
		collected := proxmoxState.slow != nil
		proxmoxState.mutex.Unlock()
		if collected {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if r, err = (&CheckProxmox{pvesh: pvesh}).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(r)
	result := r.(map[string]interface{})
	if result["node"] != "pve1" {
		t.Errorf("unexpected node: %s", js)
	}
	for _, part := range []string{"cluster", "ha", "storages", "guests", "backups"} {
		if res, ok := result[part].(map[string]string); ok {
			t.Errorf("unexpected error for %s: %v", part, res)
		}
	}
	if res, ok := result["replication"].(map[string]string); !ok || !strings.Contains(res["error"], "replication not available") {
		t.Errorf("expected an error for the replication: %v", result["replication"])
	}
	if guests := result["guests"].([]*resultProxmoxGuest); len(guests) != 5 {
		t.Errorf("unexpected guests: %d", len(guests))
	}
	if storages := result["storages"].([]*resultProxmoxStorage); len(storages) != 4 {
		t.Errorf("unexpected storages: %d", len(storages))
	}

	// The following runs return the collected data without calling pvesh
	if err := os.WriteFile(pvesh, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if r, err := (&CheckProxmox{pvesh: pvesh}).Run(context.Background()); err != nil || r.(map[string]interface{})["node"] != "pve1" {
		t.Errorf("expected the collected data: %v %v", r, err)
	}

	// Close stops the background collector and discards the data
	(&CheckProxmox{}).Close()
	proxmoxState.mutex.Lock()
	closed := !proxmoxState.running && proxmoxState.core == nil && proxmoxState.coreTime.IsZero()
	proxmoxState.mutex.Unlock()
	if !closed {
		t.Error("the collector was not closed")
	}

	// Cluster status not available: the whole check fails
	resetProxmoxCollector()
	if err := os.WriteFile(pvesh, []byte("#!/bin/sh\necho 'ipcc_send_rec[1] failed: Connection refused' >&2\nexit 111\n"), 0700); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	if err := os.WriteFile(pvesh, []byte("#!/bin/sh\necho call >> "+calls+"\necho 'ipcc_send_rec[1] failed: Connection refused' >&2\nexit 111\n"), 0700); err != nil {
		t.Fatal(err)
	}
	// The following runs return the error of the background collector without calling pvesh again
	for i := 0; i < 3; i++ {
		if _, err := (&CheckProxmox{pvesh: pvesh}).Run(context.Background()); err == nil || !strings.Contains(err.Error(), "Connection refused") {
			t.Errorf("expected an error if pve-cluster is not running: %v", err)
		}
	}
	if data, _ := os.ReadFile(calls); strings.Count(string(data), "call") != 1 {
		t.Errorf("expected one synchronous pvesh call, got %d", strings.Count(string(data), "call"))
	}
}
