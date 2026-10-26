package checks

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

// CheckNetworkPorts reports the listening ports with their processes, the number of TCP connections per state
// and the usage of the ephemeral ports. Single connections are not reported, as busy servers have thousands of them.
type CheckNetworkPorts struct {
	// Platform specific state, e.g. the cache of the process of a listening socket
	platform networkPortsPlatform
}

// Name will be used in the response as check name
func (c *CheckNetworkPorts) Name() string {
	return "network_ports"
}

// TCP states as reported by the agent, the keys are lower case
var tcpStateNames = []string{
	"established", "syn_sent", "syn_recv", "fin_wait1", "fin_wait2", "time_wait",
	"close", "close_wait", "last_ack", "listen", "closing",
}

type resultNetworkListener struct {
	Protocol    string `json:"protocol"`    // tcp or udp
	Address     string `json:"address"`     // e.g.: 0.0.0.0, ::, 127.0.0.1
	Port        uint16 `json:"port"`        // e.g.: 443
	Pid         int32  `json:"pid"`         // 0 if unknown (e.g. kernel sockets or missing permissions)
	Process     string `json:"process"`     // e.g.: nginx, empty if unknown
	Connections int64  `json:"connections"` // Established TCP connections to this listener
}

type resultEphemeralPorts struct {
	First int `json:"first"` // First port of the range for outgoing connections, e.g. 32768
	Last  int `json:"last"`  // Last port of the range, e.g. 60999
	Total int `json:"total"` // Number of ports of the range
	// Number of distinct local ports of the range which are used by outgoing TCP connections (including TIME_WAIT)
	Used int `json:"used"`
	// The ports are exhausted per destination on Linux, macOS and FreeBSD (a local port can be reused for another destination).
	// Destination with the most connections from the ephemeral range, e.g.: 10.0.0.5:5432
	MaxPerDestination int    `json:"max_per_destination"`
	Destination       string `json:"destination"`
}

// TCP and UDP errors per second (Linux only), averaged since the previous check run
type resultTcpErrors struct {
	Interval float64 `json:"interval"` // Seconds since the previous check run, 0 for the first check run
	// Connections which were dropped because the accept queue of a listening socket was full,
	// e.g. if the application does not accept the connections fast enough
	ListenOverflows float64 `json:"listen_overflows"`
	ListenDrops     float64 `json:"listen_drops"`    // All dropped SYNs of listening sockets (includes ListenOverflows)
	SyncookiesSent  float64 `json:"syncookies_sent"` // The SYN queue was full, e.g. SYN flood
	Retransmits     float64 `json:"retransmits"`     // Retransmitted TCP segments
	OutSegments     float64 `json:"out_segments"`    // Sent TCP segments
	// Retransmitted segments of all sent segments in percent
	RetransmitPercent float64 `json:"retransmit_percent"`
	InErrors          float64 `json:"in_errors"`         // Received TCP segments with errors (e.g. bad checksum)
	UdpInErrors       float64 `json:"udp_in_errors"`     // Received UDP packets which were not delivered (includes buffer errors)
	UdpRcvbufErrors   float64 `json:"udp_rcvbuf_errors"` // Dropped UDP packets because the receive buffer of a socket was full
	UdpSndbufErrors   float64 `json:"udp_sndbuf_errors"`
}

type resultNetworkPorts struct {
	Listeners      []*resultNetworkListener `json:"listeners"`
	TcpStates      map[string]int64         `json:"tcp_states"`
	EphemeralPorts *resultEphemeralPorts    `json:"ephemeral_ports,omitempty"`
	TcpErrors      *resultTcpErrors         `json:"tcp_errors,omitempty"` // Linux only
}

// networkSocket is a socket as read from the operating system
type networkSocket struct {
	Protocol   string // tcp or udp
	Family     int    // 4 or 6
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	State      string // TCP state in lower case (see tcpStateNames), "listen" for unconnected UDP sockets
	Pid        int32
	Process    string
	Inode      uint64 // Linux only, used to find the process of a listening socket
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckNetworkPorts) Run(ctx context.Context) (interface{}, error) {
	sockets, err := c.platform.sockets(ctx)
	if err != nil {
		return nil, err
	}
	result := aggregateNetworkSockets(sockets)

	if first, last, err := c.platform.ephemeralPortRange(ctx); err == nil {
		result.EphemeralPorts = ephemeralPortUsage(sockets, result.Listeners, first, last)
	}
	result.TcpErrors = c.platform.tcpErrors()

	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckNetworkPorts) Configure(cfg *config.Configuration) (bool, error) {
	return cfg.NetworkPorts, nil
}

// parseNetshDynamicPorts returns the start port and the number of ports of "netsh int ipv4 show dynamicport tcp".
// The output is translated, so the values are read by their order:
// Start Port      : 49152
// Number of Ports : 16384
func parseNetshDynamicPorts(output string) (int, int, error) {
	var values []int
	for _, line := range strings.Split(output, "\n") {
		i := strings.LastIndex(line, ":")
		if i < 0 {
			continue
		}
		if value, err := strconv.Atoi(strings.TrimSpace(line[i+1:])); err == nil {
			values = append(values, value)
		}
	}
	if len(values) < 2 || values[0] <= 0 || values[1] <= 0 || values[0]+values[1]-1 > 65535 {
		return 0, 0, fmt.Errorf("could not parse the dynamic port range of netsh: %s", strings.TrimSpace(output))
	}
	return values[0], values[1], nil
}

func isWildcardAddress(address string) bool {
	return address == "0.0.0.0" || address == "::" || address == "*" || address == ""
}

// normalizeSocketIP removes zone indexes (fe80::1%lo0) and converts wildcards (*) to 0.0.0.0 or ::
func normalizeSocketIP(address string, family int) string {
	if address == "*" || address == "" {
		if family == 6 {
			return "::"
		}
		return "0.0.0.0"
	}
	address = strings.Trim(address, "[]")
	if ip := net.ParseIP(address); ip != nil {
		return ip.String()
	}
	if i := strings.Index(address, "%"); i > 0 {
		if ip := net.ParseIP(address[:i]); ip != nil {
			return ip.String() + address[i:]
		}
	}
	return address
}

// aggregateNetworkSockets returns the listening sockets and the number of TCP sockets per state
func aggregateNetworkSockets(sockets []*networkSocket) *resultNetworkPorts {
	result := &resultNetworkPorts{
		Listeners: []*resultNetworkListener{},
		TcpStates: make(map[string]int64, len(tcpStateNames)),
	}
	for _, state := range tcpStateNames {
		result.TcpStates[state] = 0
	}

	type listenerKey struct {
		protocol string
		address  string
		port     uint16
	}
	listeners := map[listenerKey]*resultNetworkListener{}
	// Address family of a listener to assign the connections
	families := map[*resultNetworkListener]int{}

	for _, socket := range sockets {
		if socket.Protocol == "tcp" {
			result.TcpStates[socket.State]++
		}
		// Unbound sockets (port 0) do not receive anything
		if socket.State != "listen" || socket.LocalPort == 0 {
			continue
		}
		key := listenerKey{socket.Protocol, socket.LocalIP, socket.LocalPort}
		listener, ok := listeners[key]
		if !ok {
			// SO_REUSEPORT and forked processes (e.g. nginx workers) result in multiple sockets for the same address
			listener = &resultNetworkListener{
				Protocol: socket.Protocol,
				Address:  socket.LocalIP,
				Port:     socket.LocalPort,
			}
			listeners[key] = listener
			families[listener] = socket.Family
			result.Listeners = append(result.Listeners, listener)
		}
		// The process with the lowest pid is usually the parent process (e.g. the nginx master process)
		if socket.Pid > 0 && (listener.Pid == 0 || socket.Pid < listener.Pid) {
			listener.Pid = socket.Pid
			listener.Process = socket.Process
		}
	}

	// Assign the established connections to the listeners
	tcpListenersByPort := map[uint16][]*resultNetworkListener{}
	for _, listener := range result.Listeners {
		if listener.Protocol == "tcp" {
			tcpListenersByPort[listener.Port] = append(tcpListenersByPort[listener.Port], listener)
		}
	}
	for _, socket := range sockets {
		if socket.Protocol != "tcp" || socket.State != "established" {
			continue
		}
		candidates := tcpListenersByPort[socket.LocalPort]
		if len(candidates) == 0 {
			continue
		}
		var match *resultNetworkListener
		for _, listener := range candidates {
			if listener.Address == socket.LocalIP {
				match = listener
				break
			}
			if isWildcardAddress(listener.Address) {
				// Prefer the wildcard listener of the same address family (0.0.0.0 and [::] with IPV6_V6ONLY)
				if match == nil || families[listener] == socket.Family {
					match = listener
				}
			}
		}
		if match != nil {
			match.Connections++
		}
	}

	sort.SliceStable(result.Listeners, func(i, j int) bool {
		a, b := result.Listeners[i], result.Listeners[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Address < b.Address
	})
	return result
}

// ephemeralPortUsage counts the local ports of the ephemeral range which are used by outgoing TCP connections
func ephemeralPortUsage(sockets []*networkSocket, listeners []*resultNetworkListener, first, last int) *resultEphemeralPorts {
	if first <= 0 || last < first {
		return nil
	}
	result := &resultEphemeralPorts{
		First: first,
		Last:  last,
		Total: last - first + 1,
	}

	// Incoming connections use the port of the listener
	listening := map[uint16]bool{}
	for _, listener := range listeners {
		if listener.Protocol == "tcp" {
			listening[listener.Port] = true
		}
	}

	used := map[uint16]bool{}
	destinations := map[string]int{}
	for _, socket := range sockets {
		if socket.Protocol != "tcp" || socket.State == "listen" || socket.RemotePort == 0 {
			continue
		}
		port := int(socket.LocalPort)
		if port < first || port > last || listening[socket.LocalPort] {
			continue
		}
		used[socket.LocalPort] = true
		destinations[net.JoinHostPort(socket.RemoteIP, strconv.Itoa(int(socket.RemotePort)))]++
	}
	result.Used = len(used)
	for destination, count := range destinations {
		if count > result.MaxPerDestination || (count == result.MaxPerDestination && destination < result.Destination) {
			result.MaxPerDestination = count
			result.Destination = destination
		}
	}
	return result
}
