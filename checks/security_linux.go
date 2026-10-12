package checks

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// securityRootPath can be changed by tests
var securityRootPath = "/"

type resultSELinux struct {
	Mode       string `json:"mode"`        // Current mode: enforcing, permissive or disabled
	ConfigMode string `json:"config_mode"` // Mode after the next reboot (SELINUX= of /etc/selinux/config), empty if not configured
	Policy     string `json:"policy"`      // e.g.: targeted (SELINUXTYPE= of /etc/selinux/config)
}

type resultAppArmor struct {
	Enabled          bool `json:"enabled"`
	ProfilesLoaded   *int `json:"profiles_loaded"`   // null if the profiles are not readable (requires root)
	ProfilesEnforce  *int `json:"profiles_enforce"`  // Profiles in enforce mode
	ProfilesComplain *int `json:"profiles_complain"` // Profiles in complain mode (violations are only logged)
}

func securityParts() []securityPart {
	return []securityPart{
		{"selinux", func(ctx context.Context) (interface{}, error) { return getSELinux() }},
		{"apparmor", func(ctx context.Context) (interface{}, error) { return getAppArmor() }},
	}
}

func securityPath(path string) string {
	return filepath.Join(securityRootPath, path)
}

func getSELinux() (*resultSELinux, error) {
	res := &resultSELinux{Mode: "disabled"}

	// The enforce file only exists if SELinux is enabled
	data, err := os.ReadFile(securityPath("/sys/fs/selinux/enforce"))
	switch {
	case err == nil:
		if strings.TrimSpace(string(data)) == "1" {
			res.Mode = "enforcing"
		} else {
			res.Mode = "permissive"
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}

	file, err := os.Open(securityPath("/etc/selinux/config"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return res, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "SELINUX":
			res.ConfigMode = strings.ToLower(value)
		case "SELINUXTYPE":
			res.Policy = value
		}
	}
	return res, scanner.Err()
}

func getAppArmor() (*resultAppArmor, error) {
	res := &resultAppArmor{}

	data, err := os.ReadFile(securityPath("/sys/module/apparmor/parameters/enabled"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// AppArmor is not part of the kernel
			return res, nil
		}
		return nil, err
	}
	res.Enabled = strings.TrimSpace(string(data)) == "Y"
	if !res.Enabled {
		return res, nil
	}

	// One line per profile, e.g.: /usr/sbin/cupsd (enforce)
	file, err := os.Open(securityPath("/sys/kernel/security/apparmor/profiles"))
	if err != nil {
		// Only readable by root
		return res, nil
	}
	defer file.Close()

	loaded, enforce, complain := 0, 0, 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		loaded++
		switch {
		case strings.HasSuffix(line, "(enforce)"):
			enforce++
		case strings.HasSuffix(line, "(complain)"):
			complain++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	res.ProfilesLoaded, res.ProfilesEnforce, res.ProfilesComplain = &loaded, &enforce, &complain
	return res, nil
}
