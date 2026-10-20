package checks

import (
	"context"

	"github.com/shirou/gopsutil/v4/process"
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
	addDarwinProcessNames(ctx, sockets)
	return sockets, nil
}

// addDarwinProcessNames adds the process names if netstat only reports the pid (macOS 15 and older)
func addDarwinProcessNames(ctx context.Context, sockets []*networkSocket) {
	names := map[int32]string{}
	for _, socket := range sockets {
		if socket.Pid <= 0 || socket.Process != "" {
			continue
		}
		name, ok := names[socket.Pid]
		if !ok {
			if proc, err := process.NewProcessWithContext(ctx, socket.Pid); err == nil {
				name, _ = proc.NameWithContext(ctx)
			}
			names[socket.Pid] = name
		}
		socket.Process = name
	}
}
