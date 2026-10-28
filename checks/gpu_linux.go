package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	gpuPciDevicesPath = "/sys/bus/pci/devices"
	gpuKmsgPath       = "/dev/kmsg"
)

// countNvidiaPciDevices returns the number of NVIDIA GPUs (PCI class display controller) on the PCI bus, -1 if
// unknown. NVSwitches have another PCI class (bridge) and are not counted.
func countNvidiaPciDevices() int {
	devices, err := os.ReadDir(gpuPciDevicesPath)
	if err != nil {
		return -1
	}
	count := 0
	for _, device := range devices {
		vendor, err := os.ReadFile(filepath.Join(gpuPciDevicesPath, device.Name(), "vendor"))
		if err != nil || strings.TrimSpace(string(vendor)) != "0x10de" {
			continue
		}
		class, err := os.ReadFile(filepath.Join(gpuPciDevicesPath, device.Name(), "class"))
		if err != nil {
			continue
		}
		// 0x0300 VGA compatible controller, 0x0302 3D controller (data center GPUs)
		if c := strings.TrimSpace(string(class)); strings.HasPrefix(c, "0x0300") || strings.HasPrefix(c, "0x0302") {
			count++
		}
	}
	return count
}

// e.g.: NVRM: Xid (PCI:0000:3b:00): 79, pid=1234, name=python3, GPU has fallen off the bus.
// or:   nvidia-nvswitch3: SXid (PCI:0000:05:00.0): 12028, Non-fatal, Link 32 egress non-posted PRIV error (First)
var (
	xidPattern        = regexp.MustCompile(`\b(S?Xid) \(PCI:([0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+(?:\.[0-9a-fA-F])?)\): (\d+),\s*(.*)`)
	xidProcessPattern = regexp.MustCompile(`^pid=[^,]*, name=[^,]*,\s*`)
)

// readXidErrors returns the Xid errors of the NVIDIA driver in the kernel log (/dev/kmsg) since the given time.
// The kernel log is a ring buffer, older messages may already be overwritten on systems with many kernel messages.
func readXidErrors(since time.Time) ([]*resultGpuXid, error) {
	fd, err := unix.Open(gpuKmsgPath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("could not read the kernel log %s: %w", gpuKmsgPath, err)
	}
	defer unix.Close(fd)

	var monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		return nil, fmt.Errorf("could not determine the boot time: %w", err)
	}
	bootTime := time.Now().Add(-time.Duration(monotonic.Nano()))

	xids := []*resultGpuXid{}
	buf := make([]byte, 16*1024)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			switch {
			case errors.Is(err, unix.EAGAIN):
				// No more messages
				return xids, nil
			case errors.Is(err, unix.EPIPE), errors.Is(err, unix.EINTR):
				// The message was overwritten while reading
				continue
			}
			return nil, fmt.Errorf("could not read the kernel log %s: %w", gpuKmsgPath, err)
		}
		if n == 0 {
			return xids, nil
		}
		if xid := parseKmsgXid(string(buf[:n]), bootTime); xid != nil && xid.Timestamp >= since.Unix() {
			xids = append(xids, xid)
		}
	}
}

// parseKmsgXid parses a record of /dev/kmsg: "priority,sequence,microseconds since boot,flags;message"
func parseKmsgXid(record string, bootTime time.Time) *resultGpuXid {
	header, message, found := strings.Cut(record, ";")
	if !found || !strings.Contains(message, "Xid") {
		return nil
	}
	// Continuation lines (dictionary) start with a space
	message, _, _ = strings.Cut(message, "\n")

	fields := strings.Split(header, ",")
	if len(fields) < 3 {
		return nil
	}
	microseconds, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil
	}
	xid := parseXidMessage(message)
	if xid != nil {
		xid.Timestamp = bootTime.Add(time.Duration(microseconds) * time.Microsecond).Unix()
	}
	return xid
}

// parseXidMessage parses the Xid and SXid messages of the NVIDIA driver. The name of the process is removed.
func parseXidMessage(message string) *resultGpuXid {
	match := xidPattern.FindStringSubmatch(message)
	if match == nil {
		return nil
	}
	code, err := strconv.ParseInt(match[3], 10, 64)
	if err != nil {
		return nil
	}
	return &resultGpuXid{
		Type:     match[1],
		Code:     code,
		PciBusID: normalizePciBusID(match[2]),
		Message:  strings.TrimSpace(xidProcessPattern.ReplaceAllString(match[4], "")),
	}
}

// hasPlatformGpus returns true if a GPU of the amdgpu driver exists
func hasPlatformGpus() bool {
	return hasAmdGpus()
}

func collectPlatformGpus(ctx context.Context, existing []*resultGpu) []*resultGpu {
	return collectAmdGpus()
}

// readGpuDriverEvents is only implemented on Windows, the errors of the NVIDIA driver are read from the kernel log
func readGpuDriverEvents(ctx context.Context) *resultGpuDriverEventList {
	return nil
}
