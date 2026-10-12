package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeSecurityTestFile(t *testing.T, root, path, content string) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func runSecurityCheck(t *testing.T, root string) map[string]interface{} {
	t.Helper()
	securityRootPath = root
	defer func() { securityRootPath = "/" }()

	r, err := (&CheckSecurity{}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	return r.(map[string]interface{})
}

func TestCheckSecuritySELinux(t *testing.T) {
	root := t.TempDir()
	writeSecurityTestFile(t, root, "/sys/fs/selinux/enforce", "0")
	writeSecurityTestFile(t, root, "/etc/selinux/config", "# This file controls the state of SELinux\nSELINUX=enforcing\nSELINUXTYPE=targeted\n")

	result := runSecurityCheck(t, root)
	selinux := result["selinux"].(*resultSELinux)
	if selinux.Mode != "permissive" || selinux.ConfigMode != "enforcing" || selinux.Policy != "targeted" {
		t.Errorf("unexpected SELinux result: %+v", selinux)
	}
	if apparmor := result["apparmor"].(*resultAppArmor); apparmor.Enabled {
		t.Errorf("AppArmor must not be enabled: %+v", apparmor)
	}

	writeSecurityTestFile(t, root, "/sys/fs/selinux/enforce", "1")
	if selinux = runSecurityCheck(t, root)["selinux"].(*resultSELinux); selinux.Mode != "enforcing" {
		t.Errorf("unexpected SELinux mode: %+v", selinux)
	}
}

func TestCheckSecurityAppArmor(t *testing.T) {
	root := t.TempDir()
	writeSecurityTestFile(t, root, "/sys/module/apparmor/parameters/enabled", "Y\n")

	// Profiles not readable
	result := runSecurityCheck(t, root)
	apparmor := result["apparmor"].(*resultAppArmor)
	if !apparmor.Enabled || apparmor.ProfilesLoaded != nil {
		t.Errorf("unexpected AppArmor result: %+v", apparmor)
	}
	if selinux := result["selinux"].(*resultSELinux); selinux.Mode != "disabled" || selinux.ConfigMode != "" {
		t.Errorf("SELinux must be disabled: %+v", selinux)
	}

	writeSecurityTestFile(t, root, "/sys/kernel/security/apparmor/profiles",
		"/usr/sbin/cupsd (enforce)\n/usr/bin/man (enforce)\nnvidia_modprobe (complain)\nunix-chkpwd (enforce)\n")
	apparmor = runSecurityCheck(t, root)["apparmor"].(*resultAppArmor)
	if *apparmor.ProfilesLoaded != 4 || *apparmor.ProfilesEnforce != 3 || *apparmor.ProfilesComplain != 1 {
		t.Errorf("unexpected profile counts: %d %d %d", *apparmor.ProfilesLoaded, *apparmor.ProfilesEnforce, *apparmor.ProfilesComplain)
	}

	writeSecurityTestFile(t, root, "/sys/module/apparmor/parameters/enabled", "N\n")
	if apparmor = runSecurityCheck(t, root)["apparmor"].(*resultAppArmor); apparmor.Enabled || apparmor.ProfilesLoaded != nil {
		t.Errorf("AppArmor must be disabled: %+v", apparmor)
	}
}
