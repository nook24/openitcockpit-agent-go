//go:build !linux

package checks

import "time"

// countNvidiaPciDevices is only implemented on Linux
func countNvidiaPciDevices() int {
	return -1
}

// readXidErrors is only implemented on Linux, nil means that Xid errors are not supported
func readXidErrors(since time.Time) ([]*resultGpuXid, error) {
	return nil, nil
}

// AMD GPUs are only supported on Linux
func hasAmdGpus() bool {
	return false
}

func collectAmdGpus() []*resultGpu {
	return nil
}
