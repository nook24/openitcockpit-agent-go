package checks

import (
	"context"
)

// The netstat of macOS reports the processes of all users without root (since macOS 12).
// -l prints the full IPv6 addresses.
func (p *networkPortsPlatform) sockets(ctx context.Context) ([]*networkSocket, error) {
	var sockets []*networkSocket
	for _, protocol := range []string{"tcp", "udp"} {
		output, err := runNetworkPortsCommand(ctx, "netstat", "-anvl", "-p", protocol)
		if err != nil {
			return nil, err
		}
		sockets = append(sockets, parseDarwinNetstat(output)...)
	}
	return sockets, nil
}
