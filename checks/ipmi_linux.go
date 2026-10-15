package checks

import "os"

// Device files of the OpenIPMI driver (ipmi_si and ipmi_devintf)
var ipmiDevices = []string{"/dev/ipmi0", "/dev/ipmi/0", "/dev/ipmidev/0"}

func ipmiAvailable() bool {
	for _, device := range ipmiDevices {
		if _, err := os.Stat(device); err == nil {
			return true
		}
	}
	return false
}
