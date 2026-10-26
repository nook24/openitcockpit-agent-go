package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseXidMessage(t *testing.T) {
	tests := []struct {
		message string
		xid     *resultGpuXid
	}{
		{
			"NVRM: Xid (PCI:0000:3b:00): 79, pid=1234, name=python3, GPU has fallen off the bus.",
			&resultGpuXid{Type: "Xid", Code: 79, PciBusID: "0000:3b:00.0", Message: "GPU has fallen off the bus."},
		},
		{
			"NVRM: Xid (PCI:0000:18:00): 119, pid='<unknown>', name=<unknown>, Timeout after 6s of waiting for RPC response from GPU0 GSP!",
			&resultGpuXid{Type: "Xid", Code: 119, PciBusID: "0000:18:00.0", Message: "Timeout after 6s of waiting for RPC response from GPU0 GSP!"},
		},
		{
			"NVRM: Xid (PCI:0000:01:00): 13, Graphics SM Warp Exception on (GPC 0, TPC 0, SM 0): Out Of Range Address",
			&resultGpuXid{Type: "Xid", Code: 13, PciBusID: "0000:01:00.0", Message: "Graphics SM Warp Exception on (GPC 0, TPC 0, SM 0): Out Of Range Address"},
		},
		{
			"nvidia-nvswitch3: SXid (PCI:0000:05:00.0): 12028, Non-fatal, Link 32 egress non-posted PRIV error (First)",
			&resultGpuXid{Type: "SXid", Code: 12028, PciBusID: "0000:05:00.0", Message: "Non-fatal, Link 32 egress non-posted PRIV error (First)"},
		},
		{"NVRM: loading NVIDIA UNIX Open Kernel Module for x86_64  595.91.07", nil},
		{"Xid is mentioned without PCI address", nil},
	}
	for _, test := range tests {
		xid := parseXidMessage(test.message)
		if (xid == nil) != (test.xid == nil) || (xid != nil && *xid != *test.xid) {
			t.Errorf("%q: expected %+v, got %+v", test.message, test.xid, xid)
		}
	}
}

func TestParseKmsgXid(t *testing.T) {
	bootTime := time.Unix(1792483200, 0)
	record := "3,1234,90000000,-;NVRM: Xid (PCI:0000:3b:00): 48, pid=1234, name=python3, An uncorrectable double bit error (DBE) has been detected on GPU in the framebuffer at partition 6, subpartition 0.\n SUBSYSTEM=pci\n DEVICE=+pci:0000:3b:00.0\n"
	xid := parseKmsgXid(record, bootTime)
	if xid == nil || xid.Code != 48 || xid.Timestamp != 1792483290 || xid.PciBusID != "0000:3b:00.0" ||
		xid.Message != "An uncorrectable double bit error (DBE) has been detected on GPU in the framebuffer at partition 6, subpartition 0." {
		t.Errorf("unexpected Xid: %+v", xid)
	}
	for _, record := range []string{"6,1235,90000001,-;EXT4-fs (sda1): mounted filesystem", "invalid", "3,1,x,-;NVRM: Xid (PCI:0000:3b:00): 48, foo"} {
		if xid := parseKmsgXid(record, bootTime); xid != nil {
			t.Errorf("%q: unexpected Xid: %+v", record, xid)
		}
	}
}

func TestReadXidErrors(t *testing.T) {
	// Reads the real kernel log, the system has no NVIDIA GPU with Xid errors
	xids, err := readXidErrors(time.Now().Add(-gpuXidWindow))
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
			t.Skipf("the kernel log is not readable: %s", err)
		}
		t.Fatal(err)
	}
	if xids == nil {
		t.Error("expected an empty list")
	}
}

func TestCountNvidiaPciDevices(t *testing.T) {
	dir := t.TempDir()
	devices := map[string][2]string{
		"0000:18:00.0": {"0x10de", "0x030200"}, // H200
		"0000:2d:00.0": {"0x10de", "0x030000"}, // GeForce
		"0000:2d:00.1": {"0x10de", "0x040300"}, // HDMI audio of the GeForce
		"0000:05:00.0": {"0x10de", "0x068000"}, // NVSwitch
		"0000:00:02.0": {"0x8086", "0x030000"}, // Intel iGPU
	}
	for name, values := range devices {
		if err := os.MkdirAll(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "vendor"), []byte(values[0]+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "class"), []byte(values[1]+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	defer func(path string) { gpuPciDevicesPath = path }(gpuPciDevicesPath)

	gpuPciDevicesPath = dir
	if count := countNvidiaPciDevices(); count != 2 {
		t.Errorf("expected 2 GPUs, got %d", count)
	}
	gpuPciDevicesPath = filepath.Join(dir, "missing")
	if count := countNvidiaPciDevices(); count != -1 {
		t.Errorf("expected -1, got %d", count)
	}
}

func TestCheckGpuRun(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gpu", "nvidia", "h200-nvl-4x-linux-595.91.07.xml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "query.xml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	nvidiaSmi := filepath.Join(dir, "nvidia-smi")
	writeScript := func(script string) {
		if err := os.WriteFile(nvidiaSmi, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	defer func(path string) { gpuKmsgPath = path }(gpuKmsgPath)
	gpuKmsgPath = filepath.Join(dir, "kmsg")

	writeScript("#!/bin/sh\n[ \"$*\" = \"-q -x\" ] || exit 1\ncat " + filepath.Join(dir, "query.xml") + "\n")
	r, err := (&CheckGpu{nvidiaSmi: nvidiaSmi}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result := r.(*resultGpus)
	if len(result.Gpus) != 4 || result.Nvidia == nil || result.Nvidia.Error != "" || result.Nvidia.AttachedGpus != 4 {
		t.Fatalf("unexpected result: %+v %+v", result, result.Nvidia)
	}
	for i, gpu := range result.Gpus {
		if gpu.Index != i {
			t.Errorf("unexpected index of GPU %d: %d", i, gpu.Index)
		}
	}
	// The kernel log is not readable
	if result.Xid == nil || !strings.Contains(result.Xid.Error, "could not read the kernel log") || result.Xid.Unassigned == nil {
		t.Errorf("expected an error for the kernel log: %+v", result.Xid)
	}

	// The driver is not loaded
	writeScript("#!/bin/sh\necho \"NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver. Make sure that the latest NVIDIA driver is installed and running.\"\nexit 9\n")
	r, err = (&CheckGpu{nvidiaSmi: nvidiaSmi}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result = r.(*resultGpus)
	if len(result.Gpus) != 0 || result.Nvidia == nil || !strings.Contains(result.Nvidia.Error, "couldn't communicate with the NVIDIA driver") {
		t.Errorf("expected an error: %+v %+v", result, result.Nvidia)
	}

	// One GPU has fallen off the bus, nvidia-smi still reports the other GPUs
	writeScript("#!/bin/sh\ncat " + filepath.Join(dir, "query.xml") + "\necho 'Unable to determine the device handle for GPU0000:AF:00.0: Unknown Error' >&2\nexit 15\n")
	r, err = (&CheckGpu{nvidiaSmi: nvidiaSmi}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result = r.(*resultGpus)
	if len(result.Gpus) != 4 || !strings.Contains(result.Nvidia.Error, "Unable to determine the device handle for GPU0000:AF:00.0") {
		t.Errorf("expected 4 GPUs and an error: %d %+v", len(result.Gpus), result.Nvidia)
	}
}
