//go:build !linux && !windows

package checks

import (
	"context"
	"time"
)

// countNvidiaPciDevices is only implemented on Linux
func countNvidiaPciDevices() int {
	return -1
}

// readXidErrors is only implemented on Linux, nil means that Xid errors are not supported
func readXidErrors(since time.Time) ([]*resultGpuXid, error) {
	return nil, nil
}

// Only nvidia-smi is supported on this platform
func hasPlatformGpus() bool {
	return false
}

func collectPlatformGpus(ctx context.Context, existing []*resultGpu) []*resultGpu {
	return nil
}

func readGpuDriverEvents(ctx context.Context) *resultGpuDriverEventList {
	return nil
}
