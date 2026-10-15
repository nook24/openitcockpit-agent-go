package checks

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Parsers of netstat and sockstat (FreeBSD and macOS). They are not limited to these platforms to run the tests everywhere.

// TCP states of the BSD netstat
var bsdTcpStates = map[string]string{
	"ESTABLISHED": "established",
	"SYN_SENT":    "syn_sent",
	"SYN_RCVD":    "syn_recv",
	"FIN_WAIT_1":  "fin_wait1",
	"FIN_WAIT_2":  "fin_wait2",
	"TIME_WAIT":   "time_wait",
	"CLOSED":      "close",
	"CLOSE_WAIT":  "close_wait",
	"LAST_ACK":    "last_ack",
	"LISTEN":      "listen",
	"CLOSING":     "closing",
}

// bsdSocketFamily returns the protocol and the address family of e.g. tcp4, tcp6, tcp46 or udp4
// tcp46 is a dual stack socket of [::]
func bsdSocketFamily(proto string) (string, int, bool) {
	proto = strings.ToLower(proto)
	var protocol string
	switch {
	case strings.HasPrefix(proto, "tcp"):
		protocol = "tcp"
	case strings.HasPrefix(proto, "udp"):
		protocol = "udp"
	default:
		return "", 0, false
	}
	if strings.HasSuffix(proto, "4") {
		return protocol, 4, true
	}
	return protocol, 6, true
}

// parseBsdPort parses the port of netstat and sockstat, "*" is 0
func parseBsdPort(value string) uint16 {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

// splitBsdAddress splits the addresses of netstat like 192.168.1.5.22, *.22, fe80::1%lo0.123 or *.*
func splitBsdAddress(value string) (string, uint16) {
	i := strings.LastIndex(value, ".")
	if i < 0 {
		return value, 0
	}
	return value[:i], parseBsdPort(value[i+1:])
}

func newBsdSocket(proto, localAddress, localPort, remoteAddress, remotePort, state string) *networkSocket {
	protocol, family, ok := bsdSocketFamily(proto)
	if !ok {
		return nil
	}
	socket := &networkSocket{
		Protocol:   protocol,
		Family:     family,
		LocalIP:    normalizeSocketIP(localAddress, family),
		LocalPort:  parseBsdPort(localPort),
		RemoteIP:   normalizeSocketIP(remoteAddress, family),
		RemotePort: parseBsdPort(remotePort),
	}
	if protocol == "tcp" {
		socket.State, ok = bsdTcpStates[strings.ToUpper(state)]
		if !ok {
			return nil
		}
	} else if socket.RemotePort != 0 {
		socket.State = "established"
	} else {
		socket.State = "listen"
	}
	return socket
}

type netstatLibxoAddress struct {
	Address string `json:"address"`
	Port    string `json:"port"`
}

// FreeBSD: netstat --libxo json -anW -p tcp (-W does not truncate the addresses)
type netstatLibxoJSON struct {
	Statistics struct {
		Socket []struct {
			Protocol string              `json:"protocol"`
			Local    netstatLibxoAddress `json:"local"`
			Remote   netstatLibxoAddress `json:"remote"`
			TcpState string              `json:"tcp-state"`
		} `json:"socket"`
	} `json:"statistics"`
}

func parseFreeBSDNetstat(output []byte) ([]*networkSocket, error) {
	var data netstatLibxoJSON
	if err := json.Unmarshal(output, &data); err != nil {
		return nil, fmt.Errorf("could not parse output of netstat: %s", err)
	}
	var sockets []*networkSocket
	for _, s := range data.Statistics.Socket {
		if socket := newBsdSocket(s.Protocol, s.Local.Address, s.Local.Port, s.Remote.Address, s.Remote.Port, s.TcpState); socket != nil {
			sockets = append(sockets, socket)
		}
	}
	return sockets, nil
}

type sockstatLibxoAddress struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// FreeBSD 15 and newer: sockstat --libxo json -46 -l -q
type sockstatLibxoJSON struct {
	Sockstat struct {
		Socket []struct {
			Command string               `json:"command"`
			Pid     int32                `json:"pid"`
			Proto   string               `json:"proto"`
			Local   sockstatLibxoAddress `json:"local"`
		} `json:"socket"`
	} `json:"sockstat"`
}

// parseFreeBSDSockstat returns the listening sockets with their processes.
// The JSON output of sockstat requires FreeBSD 15. The text output of older versions is used as fallback:
// root     sshd       1456  6 tcp6   *:22                  *:*
func parseFreeBSDSockstat(output []byte) []*networkSocket {
	var sockets []*networkSocket
	trimmed := bytes.TrimSpace(output)
	if bytes.HasPrefix(trimmed, []byte("{")) {
		var data sockstatLibxoJSON
		if err := json.Unmarshal(trimmed, &data); err == nil {
			for _, s := range data.Sockstat.Socket {
				socket := newBsdSocket(s.Proto, s.Local.Address, strconv.Itoa(s.Local.Port), "*", "0", "LISTEN")
				if socket != nil {
					socket.Pid = s.Pid
					socket.Process = s.Command
					sockets = append(sockets, socket)
				}
			}
			return sockets
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] == "USER" {
			continue
		}
		pid, err := strconv.ParseInt(fields[2], 10, 32)
		if err != nil {
			continue
		}
		i := strings.LastIndex(fields[5], ":")
		if i < 0 {
			continue
		}
		socket := newBsdSocket(fields[4], fields[5][:i], fields[5][i+1:], "*", "0", "LISTEN")
		if socket != nil {
			socket.Pid = int32(pid)
			socket.Process = fields[1]
			sockets = append(sockets, socket)
		}
	}
	return sockets
}

// parseDarwinNetstat parses the output of "netstat -anvl -p tcp" or "netstat -anvl -p udp" of macOS.
// The process is reported since macOS 12 in the column process:pid, which is followed by 8 columns:
// tcp4 0 0  192.168.1.221.22  192.168.1.108.56582  ESTABLISHED  7848 3202 131072 131768  sshd-session:4998  00182 0000000c 000000000009d351 00000080 01000800 2 0 000000
// udp4 0 0  *.61805  *.*  0 57836 786896 9216  syslogd:133  00180 00000000 000000000009c93e 00000000 04000800 1 0 000002
func parseDarwinNetstat(output []byte) []*networkSocket {
	var sockets []*networkSocket
	hasProcess := false
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Proto") {
			hasProcess = strings.Contains(line, "process:pid")
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		protocol, _, ok := bsdSocketFamily(fields[0])
		if !ok {
			continue
		}
		localAddress, localPort := splitBsdAddress(fields[3])
		remoteAddress, remotePort := splitBsdAddress(fields[4])
		state := ""
		processColumn := 9
		if protocol == "tcp" {
			if len(fields) < 6 {
				continue
			}
			state = fields[5]
			processColumn = 10
		}
		socket := newBsdSocket(fields[0], localAddress, strconv.Itoa(int(localPort)), remoteAddress, strconv.Itoa(int(remotePort)), state)
		if socket == nil {
			continue
		}
		// The name of the process can contain spaces
		if hasProcess && len(fields)-8 > processColumn {
			process := strings.Join(fields[processColumn:len(fields)-8], " ")
			if i := strings.LastIndex(process, ":"); i > 0 {
				if pid, err := strconv.ParseInt(process[i+1:], 10, 32); err == nil {
					socket.Pid = int32(pid)
					socket.Process = process[:i]
				}
			}
		}
		sockets = append(sockets, socket)
	}
	return sockets
}
