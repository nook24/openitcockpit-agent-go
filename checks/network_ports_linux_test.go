package checks

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"testing"
)

const procNetTcpFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   114        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0501A8C0:0016 6C01A8C0:DCE6 01 00000000:00000000 02:00092B4B 00000000     0        0 1003 4 0000000000000000 20 4 31 10 -1
   3: 0501A8C0:9C40 0101A8C0:01BB 06 00000000:00000000 03:00001570 00000000     0        0 0 3 0000000000000000
   4: 0501A8C0:9C41 0101A8C0:01BB 08 00000000:00000000 00:00000000 00000000     0        0 1004 1 0000000000000000 20 4 30 10 -1
`

const procNetTcp6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000501A8C0:01BB 0000000000000000FFFF00006C01A8C0:DCE7 01 00000000:00000000 00:00000000 00000000    33        0 2002 1 0000000000000000 20 4 30 10 -1
   2: B80D0120000000000000000001000000:01BB B80D0120000000000000000009000000:C350 0C 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000
`

const procNetUdpFixture = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2 0000000000000000 0
  101: 0501A8C0:A000 0201A8C0:0035 01 00000000:00000000 00:00000000 00000000     0        0 3002 2 0000000000000000 0
`

func writeNetworkPortsFixture(t *testing.T) string {
	dir := t.TempDir()
	files := map[string]string{
		"net/tcp":                          procNetTcpFixture,
		"net/tcp6":                         procNetTcp6Fixture,
		"net/udp":                          procNetUdpFixture,
		"sys/net/ipv4/ip_local_port_range": "32768\t60999\n",
		"1/comm":                           "systemd\n",
		"10/comm":                          "sshd\n",
		"20/comm":                          "postgres\n",
		"30/comm":                          "nginx\n",
		"31/comm":                          "nginx\n",
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"1/fd/0":  "/dev/null",
		"10/fd/3": "socket:[1001]",
		"10/fd/4": "socket:[1003]",
		"20/fd/5": "socket:[1002]",
		"30/fd/6": "socket:[2001]",
		"31/fd/6": "socket:[2001]",
		"31/fd/7": "pipe:[99]",
	}
	for name, target := range links {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDecodeProcNetAddress(t *testing.T) {
	for _, test := range []struct {
		value string
		ip    string
		port  uint16
	}{
		{"0100007F:0CEA", "127.0.0.1", 3306},
		{"00000000:0016", "0.0.0.0", 22},
		{"00000000000000000000000000000000:01BB", "::", 443},
		{"00000000000000000000000001000000:0143", "::1", 323},
		{"B80D0120000000000000000001000000:01BB", "2001:db8::1", 443},
		{"0000000000000000FFFF00000501A8C0:01BB", "192.168.1.5", 443},
	} {
		ip, port, err := decodeProcNetAddress(test.value)
		if err != nil || ip != test.ip || port != test.port {
			t.Errorf("%s: expected %s:%d, got %s:%d (%v)", test.value, test.ip, test.port, ip, port, err)
		}
	}
	for _, value := range []string{"", "0100007F", "0100007F:XYZ", "01007F:0016"} {
		if _, _, err := decodeProcNetAddress(value); err == nil {
			t.Errorf("%s: expected an error", value)
		}
	}
}

func TestCheckNetworkPortsLinuxFixture(t *testing.T) {
	check := &CheckNetworkPorts{platform: networkPortsPlatform{procPath: writeNetworkPortsFixture(t)}}
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result := cr.(*resultNetworkPorts)

	expected := []resultNetworkListener{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Pid: 10, Process: "sshd", Connections: 1},
		{Protocol: "tcp", Address: "::", Port: 443, Pid: 30, Process: "nginx", Connections: 1},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 5432, Pid: 20, Process: "postgres"},
		{Protocol: "udp", Address: "0.0.0.0", Port: 53},
	}
	if len(result.Listeners) != len(expected) {
		t.Fatalf("expected %d listeners, got %d", len(expected), len(result.Listeners))
	}
	for i, listener := range result.Listeners {
		if *listener != expected[i] {
			t.Errorf("listener %d: expected %+v, got %+v", i, expected[i], *listener)
		}
	}

	states := map[string]int64{"listen": 3, "established": 2, "time_wait": 1, "close_wait": 1, "syn_recv": 1}
	for _, state := range tcpStateNames {
		if result.TcpStates[state] != states[state] {
			t.Errorf("state %s: expected %d, got %d", state, states[state], result.TcpStates[state])
		}
	}

	e := result.EphemeralPorts
	if e == nil || e.First != 32768 || e.Last != 60999 || e.Used != 2 || e.MaxPerDestination != 2 || e.Destination != "192.168.1.1:443" {
		t.Errorf("unexpected ephemeral ports: %+v", e)
	}

	// The unresolved udp socket is not searched again
	if len(check.platform.owners) != 3 || len(check.platform.unresolved) != 1 {
		t.Errorf("unexpected cache: %v %v", check.platform.owners, check.platform.unresolved)
	}
}

func TestParseProcNetSnmp(t *testing.T) {
	counters := map[string]uint64{}
	parseProcNetSnmp([]byte(`Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 1996 1139 380 151 18 277540 383208 288 0 684 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 2115 0 7 2115 5 0 0 519 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
UdpLite: 0 0 99 0 0 0 0 0 0
`), counters)
	parseProcNetSnmp([]byte("TcpExt: SyncookiesSent SyncookiesRecv ListenOverflows ListenDrops\nTcpExt: 1 0 12 15\n"), counters)
	parseProcNetSnmp6([]byte("Udp6InDatagrams                 \t10\nUdp6InErrors                    \t3\nIp6InReceives 5\n"), counters)

	expected := map[string]uint64{
		"Tcp.OutSegs": 383208, "Tcp.RetransSegs": 288, "Udp.InErrors": 7, "Udp.RcvbufErrors": 5, "UdpLite.InErrors": 99,
		"TcpExt.ListenOverflows": 12, "TcpExt.ListenDrops": 15, "Udp6InErrors": 3,
	}
	for name, value := range expected {
		if counters[name] != value {
			t.Errorf("%s: expected %d, got %d", name, value, counters[name])
		}
	}
	if _, ok := counters["Tcp.MaxConn"]; ok {
		t.Error("negative counters should be skipped")
	}
	if _, ok := counters["Ip6InReceives"]; ok {
		t.Error("only Udp6 counters of snmp6 should be read")
	}
}

func TestCalculateTcpErrors(t *testing.T) {
	last := map[string]uint64{"Tcp.OutSegs": 1000, "Tcp.RetransSegs": 10, "TcpExt.ListenOverflows": 5, "Udp.RcvbufErrors": 1, "Udp6RcvbufErrors": 1, "Tcp.InErrs": 50}
	current := map[string]uint64{"Tcp.OutSegs": 2000, "Tcp.RetransSegs": 60, "TcpExt.ListenOverflows": 25, "Udp.RcvbufErrors": 11, "Udp6RcvbufErrors": 11, "Tcp.InErrs": 0}
	result := calculateTcpErrors(last, current, 10)
	if result.Interval != 10 || result.ListenOverflows != 2 || result.Retransmits != 5 || result.OutSegments != 100 || math.Abs(result.RetransmitPercent-5) > 0.001 || result.UdpRcvbufErrors != 2 {
		t.Errorf("unexpected result: %+v", result)
	}
	// Reset counter
	if result.InErrors != 0 {
		t.Errorf("expected 0 for a reset counter, got %f", result.InErrors)
	}
}

func TestCheckNetworkPortsLinuxTcpErrors(t *testing.T) {
	if _, err := os.Stat("/proc/net/snmp"); err != nil {
		t.Skip("/proc/net/snmp not available")
	}
	check := &CheckNetworkPorts{}
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if errors := cr.(*resultNetworkPorts).TcpErrors; errors == nil || errors.Interval != 0 {
		t.Errorf("expected empty tcp errors for the first run, got %+v", errors)
	}
	cr, err = check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	errors := cr.(*resultNetworkPorts).TcpErrors
	if errors == nil || errors.Interval <= 0 || errors.RetransmitPercent < 0 || errors.RetransmitPercent > 100 {
		t.Errorf("unexpected tcp errors: %+v", errors)
	}

}
