package checks

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/winpsapi"
	"github.com/shirou/gopsutil/v4/net"
)

// The dynamic port range is changed rarely, netsh is only executed once per hour
const networkPortsRangeCacheTime = time.Hour

type networkPortsPlatform struct {
	first, last    int
	rangeTimestamp time.Time
}

// TCP states of GetExtendedTcpTable as named by gopsutil
var windowsTcpStates = map[string]string{
	"ESTABLISHED":  "established",
	"SYN_SENT":     "syn_sent",
	"SYN_RECEIVED": "syn_recv",
	"FIN_WAIT_1":   "fin_wait1",
	"FIN_WAIT_2":   "fin_wait2",
	"TIME_WAIT":    "time_wait",
	"CLOSED":       "close",
	"DELETE":       "close",
	"CLOSE_WAIT":   "close_wait",
	"LAST_ACK":     "last_ack",
	"LISTEN":       "listen",
	"CLOSING":      "closing",
}

// sockets uses GetExtendedTcpTable and GetExtendedUdpTable, which report the pid of every socket
func (p *networkPortsPlatform) sockets(ctx context.Context) ([]*networkSocket, error) {
	connections, err := net.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, err
	}

	processes := map[int32]string{}
	if procs, err := winpsapi.CreateToolhelp32Snapshot(); err == nil {
		for _, proc := range procs {
			processes[int32(proc.PID)] = proc.ExeFile
		}
	}

	sockets := make([]*networkSocket, 0, len(connections))
	for _, connection := range connections {
		family := 4
		if connection.Family == syscall.AF_INET6 {
			family = 6
		}
		socket := &networkSocket{
			Family:     family,
			LocalIP:    normalizeSocketIP(connection.Laddr.IP, family),
			LocalPort:  uint16(connection.Laddr.Port),
			RemoteIP:   normalizeSocketIP(connection.Raddr.IP, family),
			RemotePort: uint16(connection.Raddr.Port),
			Pid:        connection.Pid,
			Process:    processes[connection.Pid],
		}
		if connection.Type == syscall.SOCK_STREAM {
			socket.Protocol = "tcp"
			state, ok := windowsTcpStates[connection.Status]
			if !ok {
				continue
			}
			socket.State = state
		} else {
			// The UDP table only contains the local address
			socket.Protocol = "udp"
			socket.State = "listen"
		}
		if socket.Pid == 4 && socket.Process == "" {
			// Kernel sockets, e.g. SMB (445) or HTTP.sys (80 and 443 of IIS)
			socket.Process = "System"
		}
		sockets = append(sockets, socket)
	}
	return sockets, nil
}

// ephemeralPortRange returns the dynamic port range of TCP (netsh int ipv4 show dynamicport tcp)
func (p *networkPortsPlatform) ephemeralPortRange(ctx context.Context) (int, int, error) {
	if p.first > 0 && time.Since(p.rangeTimestamp) < networkPortsRangeCacheTime {
		return p.first, p.last, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netsh", "int", "ipv4", "show", "dynamicport", "tcp")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return 0, 0, fmt.Errorf("netsh int ipv4 show dynamicport tcp: %s", err)
	}
	first, count, err := parseNetshDynamicPorts(string(output))
	if err != nil {
		return 0, 0, err
	}
	p.first, p.last, p.rangeTimestamp = first, first+count-1, time.Now()
	return p.first, p.last, nil
}

func (p *networkPortsPlatform) tcpErrors() *resultTcpErrors {
	return nil
}
