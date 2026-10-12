package checks

func getPlatformChecks() []Check {
	checks := []Check{
		&CheckMem{},
		&CheckProcess{},
		&CheckAgent{},
		&CheckSwap{},
		&CheckUser{},
		&CheckDisk{},
		&CheckDiskIo{},
		&CheckLoad{},
		&CheckCpu{},
		&CheckNet{},
		&CheckNetIo{},
		&CheckSensor{},
		&CheckDocker{},
		&CheckSystemd{},
		&CheckNtp{},
		&CheckLogfile{},
		&CheckCertificate{},
		&CheckFile{},
		&CheckSystemHealth{},
	}

	// Only contains the libvirt check if the agent got build with the "libvirt" build tag
	return append(checks, libvirtChecks()...)
}
