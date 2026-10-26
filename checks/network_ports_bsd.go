//go:build freebsd || darwin
// +build freebsd darwin

package checks

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const networkPortsCommandTimeout = 20 * time.Second

type networkPortsPlatform struct{}

func runNetworkPortsCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, networkPortsCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %s %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return output, nil
}

// ephemeralPortRange returns the range of the ports for outgoing connections (net.inet.ip.portrange.first and last)
func (p *networkPortsPlatform) ephemeralPortRange(_ context.Context) (int, int, error) {
	first, err := unix.SysctlUint32("net.inet.ip.portrange.first")
	if err != nil {
		return 0, 0, err
	}
	last, err := unix.SysctlUint32("net.inet.ip.portrange.last")
	if err != nil {
		return 0, 0, err
	}
	return int(first), int(last), nil
}

func (p *networkPortsPlatform) tcpErrors() *resultTcpErrors {
	return nil
}
