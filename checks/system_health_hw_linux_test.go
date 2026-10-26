package checks

import (
	"os"
	"path/filepath"
	"testing"
)

const testBondActiveBackup = `Ethernet Channel Bonding Driver: v6.8.0

Bonding Mode: fault-tolerance (active-backup)
Primary Slave: None
Currently Active Slave: eth1
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0
Peer Notification Delay (ms): 0

Slave Interface: eth0
MII Status: down
Speed: Unknown
Duplex: Unknown
Link Failure Count: 2
Permanent HW addr: 52:54:00:12:34:56
Slave queue ID: 0

Slave Interface: eth1
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 52:54:00:12:34:57
Slave queue ID: 0
`

const testBondLacp = `Ethernet Channel Bonding Driver: v6.8.0

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer3+4 (1)
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0
Peer Notification Delay (ms): 0

802.3ad info
LACP active: on
LACP rate: fast
Min links: 0
Aggregator selection policy (ad_select): stable
System priority: 65535
System MAC address: 3c:ec:ef:00:00:01
Active Aggregator Info:
	Aggregator ID: 1
	Number of ports: 1
	Actor Key: 21
	Partner Key: 1
	Partner Mac Address: 00:1c:73:00:00:02

Slave Interface: eno1
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 3c:ec:ef:00:00:01
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: none
Partner Churn State: none
details actor lacp pdu:
    system priority: 65535
    port state: 63

Slave Interface: eno2
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 1
Permanent HW addr: 3c:ec:ef:00:00:02
Slave queue ID: 0
Aggregator ID: 2
Actor Churn State: churned
Partner Churn State: churned
`

func TestParseBonds(t *testing.T) {
	procPath := t.TempDir()
	writeTestProcFile(t, procPath, "net/bonding/bond0", testBondActiveBackup)
	writeTestProcFile(t, procPath, "net/bonding/bond1", testBondLacp)

	bonds, err := getBonds(procPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(bonds) != 2 {
		t.Fatalf("expected 2 bonds, got %d", len(bonds))
	}

	bond0 := bonds[0]
	if bond0.Name != "bond0" || bond0.Mode != "fault-tolerance (active-backup)" || bond0.ActiveSlave != "eth1" || bond0.MiiStatus != "up" || len(bond0.Slaves) != 2 {
		t.Errorf("unexpected bond0: %+v", bond0)
	}
	if s := bond0.Slaves[0]; s.Name != "eth0" || s.MiiStatus != "down" || s.LinkFailureCount != 2 || s.Speed != "Unknown" {
		t.Errorf("unexpected slave eth0: %+v", s)
	}

	bond1 := bonds[1]
	if bond1.ActiveAggregatorID != "1" || len(bond1.Slaves) != 2 {
		t.Fatalf("unexpected bond1: %+v", bond1)
	}
	// eno2 is up, but in another aggregator than the active one, e.g. because of a wrong switch configuration
	if s := bond1.Slaves[1]; s.Name != "eno2" || s.AggregatorID != "2" || s.MiiStatus != "up" || s.Speed != "10000 Mbps" || s.LinkFailureCount != 1 {
		t.Errorf("unexpected slave eno2: %+v", s)
	}

	// No bonding driver loaded
	if bonds, err := getBonds(t.TempDir()); err != nil || len(bonds) != 0 {
		t.Errorf("expected no bonds: %v %v", bonds, err)
	}
}

func TestGetFilesystemErrors(t *testing.T) {
	procPath := t.TempDir()
	sysPath := t.TempDir()
	writeTestProcFile(t, procPath, "self/mounts", "/dev/sda1 / ext4 rw,relatime 0 0\n/dev/sdb1 /mnt/data\\040disk ext4 rw 0 0\n/dev/sdc /srv btrfs rw 0 0\nproc /proc proc rw 0 0\n")

	writeTestProcFile(t, sysPath, "fs/ext4/sda1/errors_count", "0\n")
	writeTestProcFile(t, sysPath, "fs/ext4/sdb1/errors_count", "3\n")
	writeTestProcFile(t, sysPath, "fs/ext4/sdb1/first_error_time", "1760000000\n")
	writeTestProcFile(t, sysPath, "fs/ext4/sdb1/last_error_time", "1760003600\n")
	btrfs := "fs/btrfs/4c0e12ab-1d64-4a8e-9b4f-6c7f2a1b3c4d/"
	writeTestProcFile(t, sysPath, btrfs+"devinfo/1/error_stats", "write_errs 0\nread_errs 2\nflush_errs 0\ncorruption_errs 1\ngeneration_errs 0\n")
	writeTestProcFile(t, sysPath, btrfs+"devinfo/2/error_stats", "write_errs 1\nread_errs 0\nflush_errs 0\ncorruption_errs 0\ngeneration_errs 0\n")
	if err := os.MkdirAll(filepath.Join(sysPath, btrfs, "devices", "sdc"), 0755); err != nil {
		t.Fatal(err)
	}

	result, err := getFilesystemErrors(procPath, sysPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 filesystems, got %d: %+v", len(result), result)
	}
	byDevice := map[string]*resultFilesystemErrors{}
	for _, fs := range result {
		byDevice[fs.Device] = fs
	}
	if fs := byDevice["sda1"]; fs.Errors != 0 || fs.Mountpoint != "/" || fs.Fstype != "ext4" {
		t.Errorf("unexpected sda1: %+v", fs)
	}
	if fs := byDevice["sdb1"]; fs.Errors != 3 || fs.Mountpoint != "/mnt/data disk" || fs.FirstErrorTime != 1760000000 || fs.LastErrorTime != 1760003600 {
		t.Errorf("unexpected sdb1: %+v", fs)
	}
	if fs := byDevice["4c0e12ab-1d64-4a8e-9b4f-6c7f2a1b3c4d"]; fs.Errors != 4 || fs.Fstype != "btrfs" || fs.Mountpoint != "/srv" || fs.Details["read_errs"] != 2 || fs.Details["write_errs"] != 1 {
		t.Errorf("unexpected btrfs: %+v", fs)
	}
}

func TestGetEdac(t *testing.T) {
	sysPath := t.TempDir()
	mc := "devices/system/edac/mc/mc0/"
	writeTestProcFile(t, sysPath, mc+"mc_name", "Skylake Socket#0 IMC#0\n")
	writeTestProcFile(t, sysPath, mc+"ce_count", "12\n")
	writeTestProcFile(t, sysPath, mc+"ue_count", "1\n")
	writeTestProcFile(t, sysPath, mc+"ce_noinfo_count", "0\n")
	writeTestProcFile(t, sysPath, mc+"ue_noinfo_count", "0\n")
	writeTestProcFile(t, sysPath, mc+"dimm0/dimm_label", "CPU_SrcID#0_MC#0_Chan#0_DIMM#0\n")
	writeTestProcFile(t, sysPath, mc+"dimm0/dimm_ce_count", "12\n")
	writeTestProcFile(t, sysPath, mc+"dimm0/dimm_ue_count", "1\n")
	writeTestProcFile(t, sysPath, mc+"dimm1/dimm_label", "CPU_SrcID#0_MC#0_Chan#1_DIMM#0\n")
	writeTestProcFile(t, sysPath, mc+"dimm1/dimm_ce_count", "0\n")
	writeTestProcFile(t, sysPath, mc+"dimm1/dimm_ue_count", "0\n")

	edac, err := getEdac(sysPath)
	if err != nil {
		t.Fatal(err)
	}
	if !edac.Available || len(edac.Controllers) != 1 {
		t.Fatalf("unexpected edac: %+v", edac)
	}
	c := edac.Controllers[0]
	if c.Name != "mc0" || c.MCName != "Skylake Socket#0 IMC#0" || c.CeCount != 12 || c.UeCount != 1 || len(c.Dimms) != 2 {
		t.Errorf("unexpected controller: %+v", c)
	}
	if d := c.Dimms[0]; d.Label != "CPU_SrcID#0_MC#0_Chan#0_DIMM#0" || d.CeCount != 12 || d.UeCount != 1 {
		t.Errorf("unexpected dimm: %+v", d)
	}

	// Virtual machines and memory without ECC have no EDAC driver
	if edac, err := getEdac(t.TempDir()); err != nil || edac.Available || len(edac.Controllers) != 0 {
		t.Errorf("expected no EDAC: %+v %v", edac, err)
	}
}
