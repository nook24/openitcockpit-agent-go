package checks

import (
	"golang.org/x/sys/windows"
)

// ipmiAvailable returns true if the Microsoft IPMI driver (IPMIDRV) is running. The driver only starts if the system has a BMC.
func ipmiAvailable() bool {
	scManager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(scManager)

	name, err := windows.UTF16PtrFromString("IPMIDRV")
	if err != nil {
		return false
	}
	service, err := windows.OpenService(scManager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(service)

	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(service, &status); err != nil {
		return false
	}
	return status.CurrentState == windows.SERVICE_RUNNING
}
