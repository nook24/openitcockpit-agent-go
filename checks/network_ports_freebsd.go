package checks

import (
	"context"
)

type networkListenerKey struct {
	protocol string
	address  string
	port     uint16
}

func (p *networkPortsPlatform) sockets(ctx context.Context) ([]*networkSocket, error) {
	var sockets []*networkSocket
	for _, protocol := range []string{"tcp", "udp"} {
		output, err := runNetworkPortsCommand(ctx, "netstat", "--libxo", "json", "-anW", "-p", protocol)
		if err != nil {
			return nil, err
		}
		result, err := parseFreeBSDNetstat(output)
		if err != nil {
			return nil, err
		}
		sockets = append(sockets, result...)
	}

	// netstat does not report the processes. sockstat supports JSON since FreeBSD 15.
	output, err := runNetworkPortsCommand(ctx, "sockstat", "--libxo", "json", "-46", "-l", "-q")
	if err != nil {
		output, err = runNetworkPortsCommand(ctx, "sockstat", "-46", "-l", "-q")
	}
	if err != nil {
		// The ports are reported without processes
		return sockets, nil
	}
	owners := map[networkListenerKey]*networkSocket{}
	for _, owner := range parseFreeBSDSockstat(output) {
		key := networkListenerKey{owner.Protocol, owner.LocalIP, owner.LocalPort}
		if current, ok := owners[key]; !ok || owner.Pid < current.Pid {
			owners[key] = owner
		}
	}
	for _, socket := range sockets {
		if socket.State != "listen" {
			continue
		}
		if owner, ok := owners[networkListenerKey{socket.Protocol, socket.LocalIP, socket.LocalPort}]; ok {
			socket.Pid = owner.Pid
			socket.Process = owner.Process
		}
	}
	return sockets, nil
}
