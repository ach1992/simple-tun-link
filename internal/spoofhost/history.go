package spoofhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// A learned SourcePath is a successful authenticated observation local to one
// immutable Link, NOT a remote identity/secret/authorization. History remains
// useful after helper crashes, reboots and recurring route outages.
const historyVersion = 1

type sourceHistory struct {
	Version int                  `json:"schema_version"`
	LinkID  domain.LinkID        `json:"link_id"`
	Recent  []carrier.SourcePath `json:"recent_working_paths"`
}

func historyPath(root string, id domain.LinkID) (string, error) {
	path, err := MaterialFile(root, id)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "history.json"), nil
}

func readHistory(root string, id domain.LinkID) ([]carrier.SourcePath, error) {
	name, err := historyPath(root, id)
	if err != nil {
		return nil, err
	}
	// An absent file is normal for newly created Links and old installs.
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open original Spoof path history: %w", err)
	}
	f := os.NewFile(uintptr(fd), "Spoof history")
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("Spoof cached paths have untrusted file identity")
	}
	// History is owned by this privileged Link, and may legitimately contain
	// tens of thousands of previous source candidates; do not truncate it
	// to a fixed count or hide a malformed/partial JSON document.
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var history sourceHistory
	if err = decoder.Decode(&history); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF || history.Version != historyVersion || history.LinkID != id {
		return nil, errors.New("Spoof source history version/link identity invalid")
	}
	seen := map[carrier.SourcePath]bool{}
	for _, p := range history.Recent {
		if !p.Valid() || seen[p] {
			return nil, errors.New("Spoof cached history has invalid or duplicate Source/path")
		}
		seen[p] = true
	}
	return history.Recent, nil
}

func writeHistory(root string, id domain.LinkID, paths []carrier.SourcePath) error {
	filename, err := historyPath(root, id)
	if err != nil {
		return err
	}
	dir := filepath.Dir(filename)
	if err := requirePrivateDirectory(root); err != nil {
		return err
	}
	if err := requirePrivateDirectory(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := requirePrivateDirectory(dir); err != nil {
		return err
	}
	for _, p := range paths {
		if !p.Valid() {
			return errors.New("cannot persist invalid Spoof path")
		}
	}
	if info, err := os.Lstat(filename); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
			info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return errors.New("refusing to replace untrusted Spoof history file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(sourceHistory{Version: historyVersion, LinkID: id, Recent: paths})
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".spoof-history-*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, filename); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	return err
}

func rememberPath(paths []carrier.SourcePath, confirmed carrier.SourcePath) ([]carrier.SourcePath, bool) {
	if !confirmed.Valid() {
		return paths, false
	}
	if len(paths) > 0 && paths[0] == confirmed {
		return paths, false
	}
	filtered := make([]carrier.SourcePath, 0, len(paths)+1)
	filtered = append(filtered, confirmed)
	for _, p := range paths {
		if p != confirmed {
			filtered = append(filtered, p)
		}
	}
	return filtered, true
}
