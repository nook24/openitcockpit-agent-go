package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFileExists(t *testing.T) {
	path := "/etc/hosts"
	npath := "/sdfsdfdf"
	if runtime.GOOS == "windows" {
		path = `C:\Windows\explorer.exe`
		npath = `C:\sdfsfsdf`
	}
	if !FileExists(path) && FileNotExists(path) {
		t.Error("FileExists doesn't find existing file")
	}
	if FileExists(npath) && !FileNotExists(path) {
		t.Error("FileExists finds non existing file")
	}
}

func TestCreateParentDirectory(t *testing.T) {
	dir := t.TempDir()

	// Missing directories are created
	file := filepath.Join(dir, "autossl", "certs", "agent.crt")
	if err := CreateParentDirectory(file); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(file))
	if err != nil || !info.IsDir() {
		t.Fatalf("directory was not created: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		t.Errorf("expected the permissions 0700, got %v", info.Mode().Perm())
	}

	// An existing directory is fine
	if err := CreateParentDirectory(file); err != nil {
		t.Errorf("unexpected error for an existing directory: %s", err)
	}

	// A file name without directory is fine
	if err := CreateParentDirectory("agent.key"); err != nil {
		t.Errorf("unexpected error for a file name without directory: %s", err)
	}

	// The parent is a file
	parent := filepath.Join(dir, "file")
	if err := os.WriteFile(parent, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CreateParentDirectory(filepath.Join(parent, "agent.key")); err == nil || !strings.Contains(err.Error(), "a file with this name exists") {
		t.Errorf("expected an error, got: %v", err)
	}
}
