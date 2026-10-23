//go:build !libvirt
// +build !libvirt

package checks

// libvirtChecks returns no checks, as the agent got build without the "libvirt" build tag
func libvirtChecks() []Check {
	return nil
}
