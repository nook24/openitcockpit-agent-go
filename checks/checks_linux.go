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
		&CheckHTTP{},
		&CheckRedfish{},
		&CheckSmart{},
		&CheckSecurity{},
		&CheckZfs{},
		&CheckCeph{},
		&CheckProxmox{},
		&CheckPostfix{},
		&CheckExim{},
		&CheckLvm{},
		&CheckMounts{},
		&CheckSystemHealth{},
	}

	// Only contains the libvirt check if the agent got build with the "libvirt" build tag
	return append(checks, libvirtChecks()...)
}
