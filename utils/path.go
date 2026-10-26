package utils

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

func FileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func FileNotExists(path string) bool {
	return !FileExists(path)
}

// CreateParentDirectory creates the directory of the given file, if it does not exist.
// New directories are only accessible by the current user, as they may contain private keys.
func CreateParentDirectory(file string) error {
	dir := filepath.Dir(file)
	if dir == "." || dir == "" {
		return nil
	}

	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("could not create directory %s: a file with this name exists", dir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("could not access directory %s: %w", dir, err)
	}

	log.Infoln("Creating directory", dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("could not create directory %s: %w", dir, err)
	}
	return nil
}
