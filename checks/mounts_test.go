//go:build linux || freebsd
// +build linux freebsd

package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const testFstab = `# /etc/fstab: static file system information.
UUID=4f3c2a1b-0000-4000-8000-000000000001 /               ext4    errors=remount-ro 0       1
UUID=4f3c2a1b-0000-4000-8000-000000000002 none            swap    sw              0       0
/dev/sdb1       /mnt/backup     ext4    defaults,nofail 0       2
nas:/export     /mnt/nas        nfs     defaults,_netdev 0      0
/dev/sdc1       /mnt/usb        vfat    noauto,user     0       0
//fileserver/share /mnt/my\040share cifs credentials=/root/.smb 0 0
tmpfs           /tmp/          tmpfs   defaults        0       0
/dev/sdd1       /srv/data      xfs     x-systemd.automount 0 0
/dev/md99       /mnt/freebsd   ufs     rw,failok       0       0
`

func TestParseFstab(t *testing.T) {
	entries := parseFstab([]byte(testFstab))
	byMountpoint := map[string]*resultFstabEntry{}
	for _, entry := range entries {
		byMountpoint[entry.Mountpoint] = entry
	}
	// swap and noauto are not expected to be mounted
	if len(entries) != 7 {
		t.Fatalf("expected 7 entries, got %d: %+v", len(entries), entries)
	}
	if e := byMountpoint["/mnt/freebsd"]; e == nil || !e.Nofail {
		t.Errorf("failok of FreeBSD is expected to be handled like nofail: %+v", e)
	}
	if e := byMountpoint["/mnt/backup"]; e == nil || !e.Nofail || e.Network || e.Fstype != "ext4" {
		t.Errorf("unexpected /mnt/backup: %+v", e)
	}
	if e := byMountpoint["/mnt/nas"]; e == nil || !e.Network || e.Device != "nas:/export" {
		t.Errorf("unexpected /mnt/nas: %+v", e)
	}
	if e := byMountpoint["/mnt/my share"]; e == nil || !e.Network || e.Fstype != "cifs" {
		t.Errorf("unexpected share with escaped space: %+v", e)
	}
	if e := byMountpoint["/tmp"]; e == nil {
		t.Error("the trailing slash of /tmp/ is expected to be removed")
	}
	if _, ok := byMountpoint["/mnt/usb"]; ok {
		t.Error("noauto entries are not expected to be mounted")
	}
}

func TestCheckMounts(t *testing.T) {
	dir := t.TempDir()
	fstab := filepath.Join(dir, "fstab")
	if err := os.WriteFile(fstab, []byte(testFstab), 0600); err != nil {
		t.Fatal(err)
	}
	check := &CheckMounts{
		fstab: fstab,
		mountpoints: func(ctx context.Context) ([]string, error) {
			// /srv/data is an automount, which is mounted as autofs until it gets accessed
			return []string{"/", "/tmp", "/mnt/backup/", "/srv/data", "/proc"}, nil
		},
	}
	r, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result := r.(*resultMounts)
	if result.Expected != 7 || len(result.Missing) != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Missing[0].Mountpoint != "/mnt/nas" || result.Missing[1].Mountpoint != "/mnt/my share" {
		t.Errorf("unexpected missing mounts: %+v %+v", result.Missing[0], result.Missing[1])
	}

	check.fstab = filepath.Join(dir, "missing")
	if _, err := check.Run(context.Background()); err == nil {
		t.Error("expected an error for a missing fstab")
	}
}

func TestUnescapeMountField(t *testing.T) {
	for input, expected := range map[string]string{
		`/mnt/my\040share`: "/mnt/my share",
		`/mnt/tab\011x`:    "/mnt/tab\tx",
		`/plain`:           "/plain",
		`/end\04`:          `/end\04`,
		`/back\134slash`:   `/back\slash`,
	} {
		if result := unescapeMountField(input); result != expected {
			t.Errorf("unescapeMountField(%q) = %q, expected %q", input, result, expected)
		}
	}
}
