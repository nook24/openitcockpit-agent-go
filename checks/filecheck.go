package checks

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/openITCOCKPIT/openitcockpit-agent-go/config"
)

// fileCheckNow can be replaced by tests
var fileCheckNow = time.Now

// CheckFile monitors the existence, age and size of files and the content of directories
type CheckFile struct {
	definitions []*config.FileDefinition
}

// Name will be used in the response as check name
func (c *CheckFile) Name() string {
	return "files"
}

type resultFileInfo struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`     // Bytes
	Modified int64  `json:"modified"` // Unix timestamp of the last modification
	Age      int64  `json:"age"`      // Seconds since the last modification
}

type resultFileCheck struct {
	Type   string `json:"type"` // file or directory
	Path   string `json:"path"`
	Exists bool   `json:"exists"`

	// file: All files matching the path (glob)
	Files []*resultFileInfo `json:"files,omitempty"`

	// directory
	FileCount int64           `json:"file_count"`
	TotalSize int64           `json:"total_size"` // Bytes
	Newest    *resultFileInfo `json:"newest"`     // Most recently modified file, null if the directory is empty
	Oldest    *resultFileInfo `json:"oldest"`     // Least recently modified file, null if the directory is empty
	Truncated bool            `json:"truncated"`  // max_files reached, file_count and total_size are incomplete

	Warnings []string `json:"warnings"` // Non fatal problems, e.g. a sub directory was not readable
}

// Run the actual check
// if error != nil the check result will be nil
// ctx can be canceled and runs the timeout
// CheckResult will be serialized after the return and should not change until the next call to Run
func (c *CheckFile) Run(ctx context.Context) (interface{}, error) {
	result := make(map[string]interface{}, len(c.definitions))
	for _, definition := range c.definitions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if definition.ConfigError != "" {
			result[definition.Name] = map[string]string{"error": definition.ConfigError}
			continue
		}

		var res *resultFileCheck
		var err error
		if definition.Type == config.FileTypeDirectory {
			res, err = checkDirectory(ctx, definition)
		} else {
			res, err = checkFiles(definition)
		}
		if err != nil {
			result[definition.Name] = map[string]string{"error": err.Error()}
			continue
		}
		result[definition.Name] = res
	}
	return result, nil
}

// Configure the command or return false if the command was disabled
func (c *CheckFile) Configure(cfg *config.Configuration) (bool, error) {
	c.definitions = cfg.FileConfiguration
	return len(c.definitions) > 0, nil
}

func newFileInfo(path string, info fs.FileInfo, now time.Time) *resultFileInfo {
	return &resultFileInfo{
		Path:     path,
		Size:     info.Size(),
		Modified: info.ModTime().Unix(),
		Age:      int64(now.Sub(info.ModTime()).Seconds()),
	}
}

// checkFiles reports all files matching the path. A missing file is not an error, the receiver decides about the state
func checkFiles(d *config.FileDefinition) (*resultFileCheck, error) {
	paths, err := filepath.Glob(d.Path)
	if err != nil {
		return nil, fmt.Errorf("invalid path %s: %s", d.Path, err)
	}

	now := fileCheckNow()
	res := &resultFileCheck{
		Type:     d.Type,
		Path:     d.Path,
		Files:    []*resultFileInfo{},
		Warnings: []string{},
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %s", path, err))
			continue
		}
		if info.IsDir() {
			continue
		}
		res.Files = append(res.Files, newFileInfo(path, info, now))
	}
	res.Exists = len(res.Files) > 0
	return res, nil
}

func checkDirectory(ctx context.Context, d *config.FileDefinition) (*resultFileCheck, error) {
	res := &resultFileCheck{
		Type:     d.Type,
		Path:     d.Path,
		Warnings: []string{},
	}

	info, err := os.Stat(d.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The receiver decides about the state of a missing directory
			return res, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", d.Path)
	}
	res.Exists = true

	// WalkDir does not follow a root which is a symlink (e.g. /var/backups -> /data/backups),
	// so the resolved path is walked and the reported paths start with the configured path
	base := filepath.Clean(d.Path)
	root := base
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		root = resolved
	}

	now := fileCheckNow()
	errStop := errors.New("stop")
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if root != base {
			if rel, relErr := filepath.Rel(root, path); relErr == nil {
				path = filepath.Join(base, rel)
			}
		}
		if err != nil {
			if path == base {
				return err
			}
			// e.g. permission denied for a sub directory
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %s", path, err))
			return nil
		}
		if entry.IsDir() {
			if path != base && !d.Recursive {
				return filepath.SkipDir
			}
			return nil
		}
		// Symlinks and special files are ignored
		if !entry.Type().IsRegular() {
			return nil
		}
		if d.Pattern != "" {
			if match, _ := filepath.Match(d.Pattern, entry.Name()); !match {
				return nil
			}
		}

		if res.FileCount >= d.MaxFiles {
			res.Truncated = true
			return errStop
		}
		if res.FileCount%1000 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}

		fileInfo, err := entry.Info()
		if err != nil {
			// The file got deleted in the meantime
			return nil
		}

		file := newFileInfo(path, fileInfo, now)
		res.FileCount++
		res.TotalSize += file.Size
		if res.Newest == nil || file.Modified > res.Newest.Modified {
			res.Newest = file
		}
		if res.Oldest == nil || file.Modified < res.Oldest.Modified {
			res.Oldest = file
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return nil, err
	}
	if res.Truncated {
		res.Warnings = append(res.Warnings, fmt.Sprintf("stopped after %d files (max_files)", d.MaxFiles))
	}

	return res, nil
}
