//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package checks

// securityParts returns no parts, as there are no security features implemented for this platform (e.g. FreeBSD)
func securityParts() []securityPart {
	return []securityPart{}
}
