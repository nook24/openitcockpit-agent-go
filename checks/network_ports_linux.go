package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Unresolved listening sockets (e.g. sockets of the kernel like nfsd) are searched again after this time
const networkPortsUnresolvedRetry = 10 * time.Minute

type networkSocketOwner struct {
	pid     int32
	process string
}

type networkPortsPlatform struct {
	procPath string // can be changed by tests

	// Process of the listening sockets by inode. The inode of a socket does not change, so a process has
	// only to be searched if a new socket is listening. This avoids to read all file descriptors of all processes.
	owners     map[uint64]*networkSocketOwner
	unresolved map[uint64]time.Time

	lastCounters  map[string]uint64
	lastTimestamp time.Time
}

// Linux TCP states of /proc/net/tcp (include/net/tcp_states.h)
var linuxTcpStates = map[string]string{
	"01": "established",
	"02": "syn_sent",
	"03": "syn_recv",
	"04": "fin_wait1",
	"05": "fin_wait2",
	"06": "time_wait",
	"07": "close",
	"08": "close_wait",
	"09": "last_ack",
	"0A": "listen",
	"0B": "closing",
	"0C": "syn_recv", // TCP_NEW_SYN_RECV
}

func (p *networkPortsPlatform) proc() string {
	if p.procPath == "" {
		return "/proc"
	}
	return p.procPath
}

func (p *networkPortsPlatform) sockets(ctx context.Context) ([]*networkSocket, error) {
	files := []struct {
		name     string
		protocol string
		family   int
	}{
		{"tcp", "tcp", 4},
		{"tcp6", "tcp", 6},
		{"udp", "udp", 4},
		{"udp6", "udp", 6},
	}
	var sockets []*networkSocket
	for _, file := range files {
		fh, err := os.Open(filepath.Join(p.proc(), "net", file.name))
		if err != nil {
			// IPv6 can be disabled
			if os.IsNotExist(err) && file.family == 6 {
				continue
			}
			return nil, err
		}
		result, err := parseProcNetSockets(fh, file.protocol, file.family)
		_ = fh.Close()
		if err != nil {
			return nil, fmt.Errorf("could not parse /proc/net/%s: %s", file.name, err)
		}
		sockets = append(sockets, result...)
	}

	p.resolveListenerProcesses(ctx, sockets)
	return sockets, nil
}

// parseProcNetSockets parses /proc/net/tcp, tcp6, udp and udp6
// sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
// 0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 21768 1 ...
func parseProcNetSockets(reader io.Reader, protocol string, family int) ([]*networkSocket, error) {
	var sockets []*networkSocket
	scanner := bufio.NewScanner(reader)
	first := true
	for scanner.Scan() {
		if first {
			// Header
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		localIP, localPort, err := decodeProcNetAddress(fields[1])
		if err != nil {
			return nil, err
		}
		remoteIP, remotePort, err := decodeProcNetAddress(fields[2])
		if err != nil {
			return nil, err
		}
		socket := &networkSocket{
			Protocol:   protocol,
			Family:     family,
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
		}
		socket.Inode, _ = strconv.ParseUint(fields[9], 10, 64)
		if protocol == "tcp" {
			state, ok := linuxTcpStates[strings.ToUpper(fields[3])]
			if !ok {
				continue
			}
			socket.State = state
		} else {
			// UDP sockets without remote address receive packets from everybody (07 = TCP_CLOSE)
			if remotePort != 0 {
				socket.State = "established"
			} else {
				socket.State = "listen"
			}
		}
		sockets = append(sockets, socket)
	}
	return sockets, scanner.Err()
}

// decodeProcNetAddress decodes an address like 0100007F:0CEA (127.0.0.1:3306).
// The IP address is stored as 32 bit words in host byte order.
func decodeProcNetAddress(value string) (string, uint16, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address %s", value)
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port of address %s", value)
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, fmt.Errorf("invalid ip of address %s", value)
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(ip[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	return ip.String(), uint16(port), nil
}

// resolveListenerProcesses sets the process of the listening sockets
func (p *networkPortsPlatform) resolveListenerProcesses(ctx context.Context, sockets []*networkSocket) {
	if p.owners == nil {
		p.owners = map[uint64]*networkSocketOwner{}
		p.unresolved = map[uint64]time.Time{}
	}

	listening := map[uint64]bool{}
	missing := map[uint64]bool{}
	now := time.Now()
	for _, socket := range sockets {
		if socket.State != "listen" || socket.Inode == 0 {
			continue
		}
		listening[socket.Inode] = true
		if _, ok := p.owners[socket.Inode]; ok {
			continue
		}
		if lastTry, ok := p.unresolved[socket.Inode]; ok && now.Sub(lastTry) < networkPortsUnresolvedRetry {
			continue
		}
		missing[socket.Inode] = true
	}

	if len(missing) > 0 {
		for inode, owner := range findSocketOwners(ctx, p.proc(), missing) {
			p.owners[inode] = owner
		}
		for inode := range missing {
			if _, ok := p.owners[inode]; !ok {
				p.unresolved[inode] = now
			}
		}
	}

	// Forget closed sockets
	for inode := range p.owners {
		if !listening[inode] {
			delete(p.owners, inode)
		}
	}
	for inode := range p.unresolved {
		if !listening[inode] {
			delete(p.unresolved, inode)
		}
	}

	for _, socket := range sockets {
		if owner, ok := p.owners[socket.Inode]; ok && socket.State == "listen" {
			socket.Pid = owner.pid
			socket.Process = owner.process
		}
	}
}

// findSocketOwners searches the file descriptors of all processes for the given socket inodes.
// The processes are searched in the order of their pid, so a socket shared by forked processes belongs to the parent process.
func findSocketOwners(ctx context.Context, procPath string, inodes map[uint64]bool) map[uint64]*networkSocketOwner {
	owners := map[uint64]*networkSocketOwner{}
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return owners
	}
	var pids []int
	for _, entry := range entries {
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)

	for _, pid := range pids {
		if ctx.Err() != nil || len(owners) == len(inodes) {
			break
		}
		fdPath := filepath.Join(procPath, strconv.Itoa(pid), "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			// Process exited or missing permissions
			continue
		}
		var process string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err != nil || !inodes[inode] {
				continue
			}
			if _, ok := owners[inode]; ok {
				continue
			}
			if process == "" {
				comm, _ := os.ReadFile(filepath.Join(procPath, strconv.Itoa(pid), "comm"))
				process = strings.TrimSpace(string(comm))
			}
			owners[inode] = &networkSocketOwner{pid: int32(pid), process: process}
		}
	}
	return owners
}

func (p *networkPortsPlatform) ephemeralPortRange(_ context.Context) (int, int, error) {
	data, err := os.ReadFile(filepath.Join(p.proc(), "sys", "net", "ipv4", "ip_local_port_range"))
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("invalid ip_local_port_range: %s", string(data))
	}
	first, err1 := strconv.Atoi(fields[0])
	last, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("invalid ip_local_port_range: %s", string(data))
	}
	return first, last, nil
}

func (p *networkPortsPlatform) tcpErrors() *resultTcpErrors {
	counters := map[string]uint64{}
	for _, file := range []string{"snmp", "netstat"} {
		if data, err := os.ReadFile(filepath.Join(p.proc(), "net", file)); err == nil {
			parseProcNetSnmp(data, counters)
		}
	}
	if data, err := os.ReadFile(filepath.Join(p.proc(), "net", "snmp6")); err == nil {
		parseProcNetSnmp6(data, counters)
	}
	if _, ok := counters["Tcp.OutSegs"]; !ok {
		return nil
	}

	now := time.Now()
	last, lastTimestamp := p.lastCounters, p.lastTimestamp
	p.lastCounters, p.lastTimestamp = counters, now
	if last == nil {
		// First measurement, the rates are calculated with the next check run
		return &resultTcpErrors{}
	}
	return calculateTcpErrors(last, counters, now.Sub(lastTimestamp).Seconds())
}

// parseProcNetSnmp parses the pairs of header and value lines of /proc/net/snmp and /proc/net/netstat
// Tcp: RtoAlgorithm RtoMin ...
// Tcp: 1 200 ...
func parseProcNetSnmp(data []byte, counters map[string]uint64) {
	var header []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if header == nil || header[0] != fields[0] {
			header = fields
			continue
		}
		prefix := strings.TrimSuffix(fields[0], ":")
		for i := 1; i < len(fields) && i < len(header); i++ {
			// Some counters (e.g. Tcp.MaxConn) are signed
			if value, err := strconv.ParseInt(fields[i], 10, 64); err == nil && value >= 0 {
				counters[prefix+"."+header[i]] = uint64(value)
			}
		}
		header = nil
	}
}

// parseProcNetSnmp6 parses /proc/net/snmp6 ("Udp6InErrors 0")
func parseProcNetSnmp6(data []byte, counters map[string]uint64) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || !strings.HasPrefix(fields[0], "Udp6") {
			continue
		}
		if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
			counters[fields[0]] = value
		}
	}
}

func calculateTcpErrors(last, current map[string]uint64, interval float64) *resultTcpErrors {
	if interval <= 0 {
		return &resultTcpErrors{}
	}
	delta := func(names ...string) uint64 {
		var sum uint64
		for _, name := range names {
			// The counters are reset if the network namespace is recreated
			if current[name] >= last[name] {
				sum += current[name] - last[name]
			}
		}
		return sum
	}
	rate := func(names ...string) float64 {
		return float64(delta(names...)) / interval
	}

	result := &resultTcpErrors{
		Interval:        interval,
		ListenOverflows: rate("TcpExt.ListenOverflows"),
		ListenDrops:     rate("TcpExt.ListenDrops"),
		SyncookiesSent:  rate("TcpExt.SyncookiesSent"),
		Retransmits:     rate("Tcp.RetransSegs"),
		OutSegments:     rate("Tcp.OutSegs"),
		InErrors:        rate("Tcp.InErrs"),
		UdpInErrors:     rate("Udp.InErrors", "Udp6InErrors"),
		UdpRcvbufErrors: rate("Udp.RcvbufErrors", "Udp6RcvbufErrors"),
		UdpSndbufErrors: rate("Udp.SndbufErrors", "Udp6SndbufErrors"),
	}
	if outSegments := delta("Tcp.OutSegs"); outSegments > 0 {
		result.RetransmitPercent = float64(delta("Tcp.RetransSegs")) / float64(outSegments) * 100
	}
	return result
}
