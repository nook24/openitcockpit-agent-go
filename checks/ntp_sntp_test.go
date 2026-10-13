package checks

import (
	"context"
	"math"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeNtpServer struct {
	offset  time.Duration // Offset of the server clock compared to the local clock
	leap    byte
	stratum byte
	kiss    string
	spoof   bool // Send a response with a wrong origin timestamp first
	silent  bool // Do not respond at all
}

func startFakeNtpServer(t *testing.T, server fakeNtpServer) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		request := make([]byte, 128)
		for {
			n, addr, err := conn.ReadFrom(request)
			if err != nil {
				return
			}
			if n < sntpPacketSize || server.silent {
				continue
			}
			receiveTime := time.Now().Add(server.offset)

			response := make([]byte, sntpPacketSize)
			response[0] = server.leap<<6 | sntpVersion<<3 | sntpModeServer
			response[1] = server.stratum
			copy(response[12:16], server.kiss)
			copy(response[24:32], request[40:48])
			copy(response[32:40], timeToNtpTimestamp(receiveTime))
			copy(response[40:48], timeToNtpTimestamp(time.Now().Add(server.offset)))

			if server.spoof {
				spoofed := make([]byte, sntpPacketSize)
				copy(spoofed, response)
				copy(spoofed[24:32], []byte{1, 2, 3, 4, 5, 6, 7, 8})
				copy(spoofed[32:48], timeToNtpTimestamp(time.Now().Add(time.Hour)))
				copy(spoofed[40:48], timeToNtpTimestamp(time.Now().Add(time.Hour)))
				_, _ = conn.WriteTo(spoofed, addr)
			}
			_, _ = conn.WriteTo(response, addr)
		}
	}()
	return conn.LocalAddr().String()
}

func TestQuerySNTP(t *testing.T) {
	for _, offset := range []time.Duration{2500 * time.Millisecond, -1250 * time.Millisecond, 0} {
		address := startFakeNtpServer(t, fakeNtpServer{offset: offset, stratum: 2})
		res, err := querySNTPAddress(context.Background(), "fake.ntp", address, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs((res.Offset - offset).Seconds()) > 0.05 {
			t.Errorf("expected offset %s, got %s", offset, res.Offset)
		}
		if res.Stratum != 2 || res.Server != "fake.ntp" || res.Address != "127.0.0.1" || res.Delay < 0 || res.Delay > time.Second {
			t.Errorf("unexpected result: %+v", res)
		}
	}
}

func TestQuerySNTPErrors(t *testing.T) {
	for name, test := range map[string]struct {
		server   fakeNtpServer
		expected string
	}{
		"kiss of death": {fakeNtpServer{stratum: 0, kiss: "RATE"}, "kiss code RATE"},
		"leap alarm":    {fakeNtpServer{stratum: 2, leap: sntpLeapAlarm}, "not synchronized"},
		"stratum 16":    {fakeNtpServer{stratum: 16}, "not synchronized"},
		"no response":   {fakeNtpServer{silent: true}, "no response"},
	} {
		address := startFakeNtpServer(t, test.server)
		_, err := querySNTPAddress(context.Background(), "fake.ntp", address, 500*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), test.expected) {
			t.Errorf("%s: expected error '%s', got: %v", name, test.expected, err)
		}
	}
}

func TestQuerySNTPIgnoresSpoofedResponse(t *testing.T) {
	address := startFakeNtpServer(t, fakeNtpServer{offset: 3 * time.Second, stratum: 1, spoof: true})
	res, err := querySNTPAddress(context.Background(), "fake.ntp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(res.Offset.Seconds()-3) > 0.05 {
		t.Errorf("the spoofed response must be ignored, offset: %s", res.Offset)
	}
}

func TestNtpTimestampConversion(t *testing.T) {
	for _, value := range []time.Time{
		time.Date(2026, 10, 13, 8, 30, 15, 123456000, time.UTC),
		// NTP era 1 starts at 2036-02-07T06:28:16Z
		time.Date(2036, 2, 7, 6, 28, 15, 0, time.UTC),
		time.Date(2036, 2, 7, 6, 28, 17, 500000000, time.UTC),
		time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		converted := ntpTimestampToTime(timeToNtpTimestamp(value))
		if diff := converted.Sub(value); diff < -time.Microsecond || diff > time.Microsecond {
			t.Errorf("%s converted to %s", value, converted.UTC())
		}
	}
	if !ntpTimestampToTime(make([]byte, 8)).IsZero() {
		t.Error("zero timestamp must be converted to zero time")
	}
}

func TestParseNtpConfServers(t *testing.T) {
	servers := parseNtpConfServers("# comment\nserver time.euro.apple.com\nserver 192.168.1.1 iburst\npool pool.ntp.org\ndriftfile /var/db/ntp.drift\nserver\n")
	if strings.Join(servers, ",") != "time.euro.apple.com,192.168.1.1,pool.ntp.org" {
		t.Errorf("unexpected servers: %v", servers)
	}

	// Default ntp.conf of FreeBSD
	servers = parseNtpConfServers("tos minclock 3 maxclock 6\npool 0.freebsd.pool.ntp.org iburst\nrestrict default limited kod nomodify notrap noquery nopeer\n")
	if strings.Join(servers, ",") != "0.freebsd.pool.ntp.org" {
		t.Errorf("unexpected servers: %v", servers)
	}

	// chrony.conf and ntpd.conf of OpenNTPD
	servers = parseNtpConfServers("pool 2.freebsd.pool.ntp.org iburst\nmakestep 1.0 3\n")
	if strings.Join(servers, ",") != "2.freebsd.pool.ntp.org" {
		t.Errorf("unexpected chrony servers: %v", servers)
	}
	servers = parseNtpConfServers("servers pool.ntp.org\nsensor *\nconstraints from \"https://www.google.com\"\n")
	if strings.Join(servers, ",") != "pool.ntp.org" {
		t.Errorf("unexpected OpenNTPD servers: %v", servers)
	}
}

func TestParseNtpqOutput(t *testing.T) {
	// ntpd started, but not synchronized yet
	notSynchronized := `associd=0 status=c016 leap_alarm, sync_unspec, 1 event, restart,
version="ntpd 4.2.8p18-a (1)", processor="amd64",
system="FreeBSD/15.0-RELEASE", leap=11, stratum=16, precision=-25,
rootdelay=0.000, rootdisp=0.015, refid=INIT, reftime=(no time),
clock=ecdb11d2.88100972  Wed, Dec  3 2025 20:45:22.531, peer=0, tc=3,
mintc=3, offset=+0.000000, frequency=+0.000, sys_jitter=0.000000,
clk_jitter=0.000, clk_wander=0.000, leapsec=201701010000,
expire=202606280000`
	if synchronized, _ := parseNtpqOutput(notSynchronized); synchronized {
		t.Error("ntpd must not be synchronized")
	}

	synchronized := `associd=0 status=0615 leap_none, sync_ntp, 1 event, clock_sync,
version="ntpd 4.2.8p18-a (1)", processor="amd64",
system="FreeBSD/15.0-RELEASE", leap=00, stratum=3, precision=-24,
rootdelay=14.871, rootdisp=31.213, refid=192.0.2.10,
clock=ecdb1a2b.5e2d1c3a  Wed, Dec  3 2025 21:20:59.367, peer=21712, tc=6,
mintc=3, offset=-1.534210, frequency=-12.345, sys_jitter=0.421337,
clk_jitter=0.512, clk_wander=0.012, tai=37, leapsec=201701010000,
expire=202606280000`
	ok, offset := parseNtpqOutput(synchronized)
	if !ok || offset != -0.00153421 {
		t.Errorf("expected synchronized with offset -0.00153421 s, got %v %v", ok, offset)
	}
}
