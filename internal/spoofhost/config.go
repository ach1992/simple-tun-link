package spoofhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// Config contains only PUBLIC, confirmed per-Link topology. It exists before
// Engine Apply so the helper can start even if the remote endpoint is offline.
type Config struct {
	SchemaVersion int         `json:"schema_version"`
	Link          domain.Link `json:"link"`
}

const configVersion = 1

func normalizedConfig(link domain.Link) (Config, error) {
	if link.Backend != domain.BackendSpoof {
		return Config{}, errors.New("not a Spoof link")
	}
	if link.Spoof.Role == "creator" {
		link.Spoof.PeerPublicKey = ""
	} // first binding lives in Engine State
	if err := link.Validate(); err != nil {
		return Config{}, err
	}
	return Config{SchemaVersion: configVersion, Link: link}, nil
}
func configPath(root string, id domain.LinkID) (string, error) {
	filename, err := MaterialFile(root, id)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(filename), "link.json"), nil
}
func StatusPath(root string, id domain.LinkID) (string, error) {
	filename, err := MaterialFile(root, id)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(filename), "status.json"), nil
}
func (m Material) Digest() (string, error) {
	raw, err := m.encodeProtected()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func StageConfig(root string, link domain.Link) error {
	normalized, err := normalizedConfig(link)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	_, err = prepareDirectories(root, link.ID)
	if err != nil {
		return err
	}
	filename, err := configPath(root, link.ID)
	if err != nil {
		return err
	}
	existing, err := ReadConfig(root, link.ID)
	if err == nil {
		if existing.Link != normalized.Link {
			return errors.New("Spoof protected helper topology differs from original")
		}
		return nil
	}
	if _, statErr := os.Lstat(filename); statErr == nil {
		return fmt.Errorf("Spoof existing config cannot be trusted: %w", err)
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	failed := true
	defer func() {
		if failed {
			_ = os.Remove(filename)
		}
	}()
	if _, err = file.Write(raw); err != nil {
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
	dir, err := os.Open(filepath.Dir(filename))
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return err
	}
	failed = false
	return nil
}
func ReadConfig(root string, id domain.LinkID) (Config, error) {
	filename, err := configPath(root, id)
	if err != nil {
		return Config{}, err
	}
	fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Config{}, fmt.Errorf("Spoof protected Link config: %w", err)
	}
	file := os.NewFile(uintptr(fd), "spoof-link-config")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() > 8192 || info.Size() == 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return Config{}, errors.New("Spoof protected config has unsafe file identity")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 {
		return Config{}, errors.New("Spoof Link config invalid length")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var stored Config
	if decoder.Decode(&stored) != nil || stored.SchemaVersion != configVersion {
		return Config{}, errors.New("Spoof Link config schema mismatch")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Config{}, errors.New("Spoof Link config trailing data")
	}
	normalized, err := normalizedConfig(stored.Link)
	if err != nil || stored.Link.ID != id || normalized.Link != stored.Link {
		return Config{}, errors.New("Spoof Link config identity invalid")
	}
	expected, _ := json.Marshal(normalized)
	if !bytes.Equal(raw, expected) {
		return Config{}, errors.New("Spoof Link config noncanonical")
	}
	return stored, nil
}

// ConfigPath is derived solely from the canonical State root and Link ID;
// it never accepts an operator-controlled helper config basename.
func ConfigPath(root string, id domain.LinkID) (string, error) { return configPath(root, id) }
