package checks

import (
	"context"
	"net"
	"os"
	"testing"
)

func TestAggregateNetworkSockets(t *testing.T) {
	sockets := []*networkSocket{
		// nginx with master and worker process on both address families
		{Protocol: "tcp", Family: 4, LocalIP: "0.0.0.0", LocalPort: 443, State: "listen", Pid: 120, Process: "nginx"},
		{Protocol: "tcp", Family: 4, LocalIP: "0.0.0.0", LocalPort: 443, State: "listen", Pid: 100, Process: "nginx"},
		{Protocol: "tcp", Family: 6, LocalIP: "::", LocalPort: 443, State: "listen", Pid: 100, Process: "nginx"},
		{Protocol: "tcp", Family: 4, LocalIP: "127.0.0.1", LocalPort: 5432, State: "listen", Pid: 200, Process: "postgres"},
		{Protocol: "udp", Family: 4, LocalIP: "0.0.0.0", LocalPort: 53, State: "listen"},
		{Protocol: "udp", Family: 4, LocalIP: "0.0.0.0", LocalPort: 0, State: "listen", Pid: 229, Process: "airportd"},
		{Protocol: "udp", Family: 4, LocalIP: "10.0.0.1", LocalPort: 40000, RemoteIP: "10.0.0.2", RemotePort: 53, State: "established"},
		{Protocol: "tcp", Family: 4, LocalIP: "10.0.0.1", LocalPort: 443, RemoteIP: "10.0.0.9", RemotePort: 50000, State: "established"},
		{Protocol: "tcp", Family: 4, LocalIP: "10.0.0.1", LocalPort: 443, RemoteIP: "10.0.0.9", RemotePort: 50001, State: "established"},
		{Protocol: "tcp", Family: 6, LocalIP: "2001:db8::1", LocalPort: 443, RemoteIP: "2001:db8::9", RemotePort: 50002, State: "established"},
		{Protocol: "tcp", Family: 4, LocalIP: "10.0.0.1", LocalPort: 443, RemoteIP: "10.0.0.9", RemotePort: 50003, State: "time_wait"},
		{Protocol: "tcp", Family: 4, LocalIP: "127.0.0.1", LocalPort: 5432, RemoteIP: "127.0.0.1", RemotePort: 40001, State: "established"},
		{Protocol: "tcp", Family: 4, LocalIP: "127.0.0.1", LocalPort: 40001, RemoteIP: "127.0.0.1", RemotePort: 5432, State: "established"},
		{Protocol: "tcp", Family: 4, LocalIP: "10.0.0.1", LocalPort: 40002, RemoteIP: "10.0.0.7", RemotePort: 8080, State: "close_wait"},
	}
	result := aggregateNetworkSockets(sockets)

	if len(result.Listeners) != 4 {
		t.Fatalf("expected 4 listeners, got %d", len(result.Listeners))
	}
	expected := []resultNetworkListener{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 443, Pid: 100, Process: "nginx", Connections: 2},
		{Protocol: "tcp", Address: "::", Port: 443, Pid: 100, Process: "nginx", Connections: 1},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 5432, Pid: 200, Process: "postgres", Connections: 1},
		{Protocol: "udp", Address: "0.0.0.0", Port: 53},
	}
	for i, listener := range result.Listeners {
		if *listener != expected[i] {
			t.Errorf("listener %d: expected %+v, got %+v", i, expected[i], *listener)
		}
	}

	if result.TcpStates["listen"] != 4 || result.TcpStates["established"] != 5 || result.TcpStates["time_wait"] != 1 || result.TcpStates["close_wait"] != 1 {
		t.Errorf("unexpected tcp states: %v", result.TcpStates)
	}
	if len(result.TcpStates) != len(tcpStateNames) {
		t.Errorf("expected all tcp states, got %v", result.TcpStates)
	}
}

func TestAggregateNetworkSocketsDualStack(t *testing.T) {
	// FreeBSD tcp46 or Linux [::] without IPV6_V6ONLY: IPv4 connections belong to the IPv6 listener
	result := aggregateNetworkSockets([]*networkSocket{
		{Protocol: "tcp", Family: 6, LocalIP: "::", LocalPort: 3333, State: "listen"},
		{Protocol: "tcp", Family: 4, LocalIP: "192.168.1.5", LocalPort: 3333, RemoteIP: "192.168.1.9", RemotePort: 50000, State: "established"},
	})
	if len(result.Listeners) != 1 || result.Listeners[0].Connections != 1 {
		t.Errorf("unexpected listeners: %+v", result.Listeners[0])
	}
}

func TestEphemeralPortUsage(t *testing.T) {
	listeners := []*resultNetworkListener{{Protocol: "tcp", Address: "0.0.0.0", Port: 50000}}
	sockets := []*networkSocket{
		{Protocol: "tcp", LocalPort: 40000, RemoteIP: "10.0.0.5", RemotePort: 5432, State: "established"},
		{Protocol: "tcp", LocalPort: 40001, RemoteIP: "10.0.0.5", RemotePort: 5432, State: "time_wait"},
		// The same local port to another destination
		{Protocol: "tcp", LocalPort: 40001, RemoteIP: "10.0.0.6", RemotePort: 443, State: "established"},
		// Incoming connection to a listener in the ephemeral range
		{Protocol: "tcp", LocalPort: 50000, RemoteIP: "10.0.0.7", RemotePort: 40000, State: "established"},
		// Outside of the range
		{Protocol: "tcp", LocalPort: 22, RemoteIP: "10.0.0.8", RemotePort: 50000, State: "established"},
		{Protocol: "udp", LocalPort: 40002, RemoteIP: "10.0.0.2", RemotePort: 53, State: "established"},
		{Protocol: "tcp", LocalPort: 40003, State: "listen"},
	}
	result := ephemeralPortUsage(sockets, listeners, 32768, 60999)
	if result.Total != 28232 || result.Used != 2 || result.MaxPerDestination != 2 || result.Destination != "10.0.0.5:5432" {
		t.Errorf("unexpected result: %+v", result)
	}

	result = ephemeralPortUsage([]*networkSocket{{Protocol: "tcp", LocalPort: 49152, RemoteIP: "2001:db8::1", RemotePort: 443, State: "established"}}, nil, 49152, 65535)
	if result.Destination != "[2001:db8::1]:443" {
		t.Errorf("unexpected destination: %s", result.Destination)
	}

	if ephemeralPortUsage(nil, nil, 0, 0) != nil {
		t.Error("expected nil for an invalid range")
	}
}

func TestParseNetshDynamicPorts(t *testing.T) {
	english := "\r\nProtocol tcp Dynamic Port Range\r\n---------------------------------\r\nStart Port      : 49152\r\nNumber of Ports : 16384\r\n\r\n"
	german := "\r\nDynamischer Portbereich für tcp-Protokoll\r\n---------------------------------\r\nStartport       : 1025\r\nAnzahl von Ports: 64511\r\n"
	for _, test := range []struct {
		output       string
		first, count int
	}{{english, 49152, 16384}, {german, 1025, 64511}} {
		first, count, err := parseNetshDynamicPorts(test.output)
		if err != nil || first != test.first || count != test.count {
			t.Errorf("expected %d/%d, got %d/%d (%v)", test.first, test.count, first, count, err)
		}
	}
	if _, _, err := parseNetshDynamicPorts("The requested operation requires elevation"); err == nil {
		t.Error("expected an error")
	}
}

func TestNormalizeSocketIP(t *testing.T) {
	for _, test := range []struct {
		address  string
		family   int
		expected string
	}{
		{"*", 4, "0.0.0.0"},
		{"*", 6, "::"},
		{"[::1]", 6, "::1"},
		{"fe80::1%lo0", 6, "fe80::1%lo0"},
		{"::ffff:192.168.1.5", 6, "192.168.1.5"},
		{"192.168.1.5", 4, "192.168.1.5"},
	} {
		if actual := normalizeSocketIP(test.address, test.family); actual != test.expected {
			t.Errorf("%s: expected %s, got %s", test.address, test.expected, actual)
		}
	}
}

func TestParseFreeBSDNetstat(t *testing.T) {
	output := `{"statistics": {"socket": [{"protocol":"tcp4","receive-bytes-waiting":0,"send-bytes-waiting":940, "local": {"address":"192.168.1.244","port":"22"}, "remote": {"address":"192.168.1.108","port":"56534"},"tcp-state":"ESTABLISHED"}, {"protocol":"tcp46","receive-bytes-waiting":0,"send-bytes-waiting":0, "local": {"address":"*","port":"3333"}, "remote": {"address":"*","port":"*"},"tcp-state":"LISTEN"}, {"protocol":"tcp4","local": {"address":"192.168.1.244","port":"10001"}, "remote": {"address":"192.168.1.1","port":"443"},"tcp-state":"SYN_RCVD"}, {"protocol":"udp6", "local": {"address":"fe80::1%lo0","port":"123"}, "remote": {"address":"*","port":"*"}}]}}`
	sockets, err := parseFreeBSDNetstat([]byte(output))
	if err != nil {
		t.Fatal(err)
	}
	expected := []networkSocket{
		{Protocol: "tcp", Family: 4, LocalIP: "192.168.1.244", LocalPort: 22, RemoteIP: "192.168.1.108", RemotePort: 56534, State: "established"},
		{Protocol: "tcp", Family: 6, LocalIP: "::", LocalPort: 3333, RemoteIP: "::", State: "listen"},
		{Protocol: "tcp", Family: 4, LocalIP: "192.168.1.244", LocalPort: 10001, RemoteIP: "192.168.1.1", RemotePort: 443, State: "syn_recv"},
		{Protocol: "udp", Family: 6, LocalIP: "fe80::1%lo0", LocalPort: 123, RemoteIP: "::", State: "listen"},
	}
	if len(sockets) != len(expected) {
		t.Fatalf("expected %d sockets, got %d", len(expected), len(sockets))
	}
	for i, socket := range sockets {
		if *socket != expected[i] {
			t.Errorf("socket %d: expected %+v, got %+v", i, expected[i], *socket)
		}
	}

	if _, err := parseFreeBSDNetstat([]byte("netstat: illegal option")); err == nil {
		t.Error("expected an error")
	}
}

func TestParseFreeBSDSockstat(t *testing.T) {
	json := `{"__version": "1", "sockstat": {"socket": [{"user":"root","command":"oitc-agent","pid":7642,"fd":5,"proto":"tcp46", "local": {"address":"*","port":3333}, "foreign": {"address":"*","port":0}}, {"user":"ntpd","command":"ntpd","pid":1299,"fd":23,"proto":"udp4", "local": {"address":"192.168.1.244","port":123}, "foreign": {"address":"*","port":0}}]}}`
	text := "root     oitc-agent 7642  5 tcp46  *:3333                *:*\nntpd     ntpd       1299 23 udp4   192.168.1.244:123     *:*\nntpd     ntpd       1299 24 udp6   [::1]:123             *:*\n"
	for name, output := range map[string]string{"json": json, "text": text} {
		sockets := parseFreeBSDSockstat([]byte(output))
		if len(sockets) < 2 {
			t.Fatalf("%s: expected at least 2 sockets, got %d", name, len(sockets))
		}
		if s := sockets[0]; s.Protocol != "tcp" || s.LocalIP != "::" || s.LocalPort != 3333 || s.Pid != 7642 || s.Process != "oitc-agent" || s.State != "listen" {
			t.Errorf("%s: unexpected socket %+v", name, *s)
		}
		if s := sockets[1]; s.Protocol != "udp" || s.LocalIP != "192.168.1.244" || s.LocalPort != 123 || s.Pid != 1299 || s.Process != "ntpd" {
			t.Errorf("%s: unexpected socket %+v", name, *s)
		}
	}
	sockets := parseFreeBSDSockstat([]byte(text))
	if len(sockets) != 3 || sockets[2].LocalIP != "::1" {
		t.Errorf("unexpected IPv6 socket of the text output: %+v", sockets)
	}
}

func TestParseDarwinNetstat(t *testing.T) {
	tcp := `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  192.168.1.221.22       192.168.1.108.56582    ESTABLISHED         7848         3202  131072  131768     sshd-session:4998   00182 0000000c 000000000009d351 00000080 01000800      2      0 000000
tcp4       0      0  192.168.1.221.58045    34.107.243.93.443      TIME_WAIT           4884         3315  131072  131600  Google Chrome H:29019  00102 00000008 000000000009d27c 00000080 04000900      2      0 000000
tcp46      0      0  *.22                   *.*                    LISTEN                 0            0  131072  131072        launchd:1      00180 00000006 0000000000000d07 00000000 00000800      1      0 000000
tcp6       0      0  fe80::aede:48ff:fe00:1122%en5.57978           fe80::aede:48ff:fe33:4455%en5.49162           ESTABLISHED         1218          393  398080  143352 mobileactivation:334    00182 00000000 000000000009c8dc 00100001 04080900      2      0 000000
tcp6       0      0  fe80::1%lo0.631        *.*                    LISTEN                 0            0  131072  131072        cupsd:512      00180 00000006 0000000000000d08 00000000 00000800      1      0 000000
`
	udp := `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
udp4       0      0  *.61805                *.*                                           0        57836  786896    9216          syslogd:133    00180 00000000 000000000009c93e 00000000 04000800      1      0 000002
udp4       0      0  192.168.1.221.5353     224.0.0.251.5353                              0            0  786896    9216    mDNSResponder:400  00080 00000000 0000000000002ee7 00000000 00000800      1      0 000000
`
	sockets := append(parseDarwinNetstat([]byte(tcp)), parseDarwinNetstat([]byte(udp))...)
	expected := []networkSocket{
		{Protocol: "tcp", Family: 4, LocalIP: "192.168.1.221", LocalPort: 22, RemoteIP: "192.168.1.108", RemotePort: 56582, State: "established", Pid: 4998, Process: "sshd-session"},
		{Protocol: "tcp", Family: 4, LocalIP: "192.168.1.221", LocalPort: 58045, RemoteIP: "34.107.243.93", RemotePort: 443, State: "time_wait", Pid: 29019, Process: "Google Chrome H"},
		{Protocol: "tcp", Family: 6, LocalIP: "::", LocalPort: 22, RemoteIP: "::", State: "listen", Pid: 1, Process: "launchd"},
		{Protocol: "tcp", Family: 6, LocalIP: "fe80::aede:48ff:fe00:1122%en5", LocalPort: 57978, RemoteIP: "fe80::aede:48ff:fe33:4455%en5", RemotePort: 49162, State: "established", Pid: 334, Process: "mobileactivation"},
		{Protocol: "tcp", Family: 6, LocalIP: "fe80::1%lo0", LocalPort: 631, RemoteIP: "::", State: "listen", Pid: 512, Process: "cupsd"},
		{Protocol: "udp", Family: 4, LocalIP: "0.0.0.0", LocalPort: 61805, RemoteIP: "0.0.0.0", State: "listen", Pid: 133, Process: "syslogd"},
		{Protocol: "udp", Family: 4, LocalIP: "192.168.1.221", LocalPort: 5353, RemoteIP: "224.0.0.251", RemotePort: 5353, State: "established", Pid: 400, Process: "mDNSResponder"},
	}
	if len(sockets) != len(expected) {
		t.Fatalf("expected %d sockets, got %d", len(expected), len(sockets))
	}
	for i, socket := range sockets {
		if *socket != expected[i] {
			t.Errorf("socket %d: expected %+v, got %+v", i, expected[i], *socket)
		}
	}
}

func TestCheckNetworkPorts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	check := &CheckNetworkPorts{}
	cr, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, ok := cr.(*resultNetworkPorts)
	if !ok {
		t.Fatal("False type")
	}

	var total int64
	for _, state := range tcpStateNames {
		count, ok := result.TcpStates[state]
		if !ok || count < 0 {
			t.Errorf("missing or invalid state %s", state)
		}
		total += count
	}
	var tcpListeners int64
	found := false
	for _, listener := range result.Listeners {
		if listener.Protocol == "tcp" && listener.Port == port && listener.Address == "127.0.0.1" {
			found = true
			// The process of an own socket is always visible
			if listener.Pid != int32(os.Getpid()) {
				t.Errorf("expected pid %d for the own listener, got %d (%s)", os.Getpid(), listener.Pid, listener.Process)
			}
		}
		if listener.Protocol != "tcp" && listener.Protocol != "udp" {
			t.Errorf("invalid protocol %s", listener.Protocol)
		}
		if listener.Protocol == "tcp" {
			tcpListeners++
		}
	}
	if !found {
		t.Errorf("own listener 127.0.0.1:%d not found", port)
	}
	// Multiple sockets can listen on the same address (SO_REUSEPORT)
	if result.TcpStates["listen"] < tcpListeners {
		t.Errorf("%d tcp listeners, but only %d sockets in state listen", tcpListeners, result.TcpStates["listen"])
	}
	if e := result.EphemeralPorts; e != nil {
		if e.First <= 0 || e.Last < e.First || e.Total != e.Last-e.First+1 || e.Used > e.Total || int64(e.Used) > total {
			t.Errorf("invalid ephemeral ports: %+v", e)
		}
	}
}

// macOS 15 and older report the pid in its own column, without the name of the process
func TestParseDarwinNetstatPidColumn(t *testing.T) {
	outputs := []string{
		// macOS 15.7 (Intel), addresses replaced
		`Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat    pid   epid state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  192.0.2.10.22                                 198.51.100.1.59909                            ESTABLISHED        11200         4933  131072  131376  59554      0 00182 0000000c 00000000007207b6 20000080 01000900      3      0 000004
udp4       0      0  *.49466                                       *.*                                                                  0       138117  786896    9216    137      0 00180 00000000 00000000006feb41 00000000 04000800      1      0 000002
`,
		// Older versions without rxbytes and txbytes
		`Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)     rhiwat shiwat    pid   epid  state    options
tcp4       0      0  192.0.2.10.22          198.51.100.1.59909     ESTABLISHED 131072 131376  59554      0 0x0182 0x0000000c
udp4       0      0  *.49466                *.*                                786896   9216    137      0 0x0180 0x00000000
`,
	}
	expected := []networkSocket{
		{Protocol: "tcp", Family: 4, LocalIP: "192.0.2.10", LocalPort: 22, RemoteIP: "198.51.100.1", RemotePort: 59909, State: "established", Pid: 59554},
		{Protocol: "udp", Family: 4, LocalIP: "0.0.0.0", LocalPort: 49466, RemoteIP: "0.0.0.0", State: "listen", Pid: 137},
	}
	for i, output := range outputs {
		sockets := parseDarwinNetstat([]byte(output))
		if len(sockets) != len(expected) {
			t.Fatalf("output %d: expected %d sockets, got %d", i, len(expected), len(sockets))
		}
		for j, socket := range sockets {
			if *socket != expected[j] {
				t.Errorf("output %d socket %d: expected %+v, got %+v", i, j, expected[j], *socket)
			}
		}
	}
}
