package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const sharedMetadataVersion = 1

type SharedApplyResult struct {
	// Owned is true only when the shared host prerequisite is STL-owned and may
	// be removed after the final STL owner releases it.
	Owned bool
	// Rollback reverts the apply delta when this acquisition itself must roll
	// back before it commits. It is required whenever Owned is true.
	Rollback func(context.Context) error
}

type SharedApply func(context.Context) (SharedApplyResult, error)
type SharedRemove func(context.Context) error

type sharedMetadata struct {
	SchemaVersion int  `json:"schema_version"`
	Owned         bool `json:"owned"`
}

type SharedPrerequisites struct {
	root string
}

func NewSharedPrerequisites(root string) *SharedPrerequisites {
	return &SharedPrerequisites{root: filepath.Join(root, "shared")}
}

// Ensure serializes one shared prerequisite across processes, applies it only
// for the first owner, then durably records this Link's ownership. A
// prerequisite found to be externally owned is recorded as external and STL
// never removes it. Orphaned/corrupt metadata fails closed instead of silently
// re-applying host state whose ownership is uncertain.
func (m *SharedPrerequisites) Ensure(ctx context.Context, id domain.LinkID, key string, apply SharedApply, remove SharedRemove) (func(context.Context) error, bool, error) {
	if err := id.Validate(); err != nil {
		return nil, false, err
	}
	if err := validateSharedKey(key); err != nil {
		return nil, false, err
	}
	if apply == nil {
		return nil, false, fmt.Errorf("shared prerequisite apply function is required")
	}
	unlock, dir, marker, err := m.lock(ctx, id, key)
	if err != nil {
		return nil, false, err
	}
	defer unlock()

	markerExists, err := pathExists(marker)
	if err != nil {
		return nil, false, err
	}
	if markerExists {
		metadata, err := readSharedMetadata(dir)
		if err != nil {
			return nil, false, err
		}
		if metadata.Owned && remove == nil {
			return nil, false, fmt.Errorf("STL-owned shared prerequisite requires remove function")
		}
		return func(context.Context) error { return nil }, false, nil
	}

	owners, err := sharedOwners(dir)
	if err != nil {
		return nil, false, err
	}
	first := len(owners) == 0
	var applied SharedApplyResult
	var metadata sharedMetadata
	if first {
		metadataExists, err := pathExists(filepath.Join(dir, "metadata.json"))
		if err != nil {
			return nil, false, err
		}
		if metadataExists {
			return nil, false, fmt.Errorf("orphaned shared prerequisite metadata; refusing to re-apply uncertain host state")
		}

		applied, err = apply(ctx)
		if err != nil {
			return nil, false, err
		}
		if applied.Owned && applied.Rollback == nil {
			return nil, false, fmt.Errorf("STL-owned shared prerequisite requires rollback")
		}
		if applied.Owned && remove == nil {
			rollbackErr := applied.Rollback(context.WithoutCancel(ctx))
			return nil, false, errors.Join(fmt.Errorf("STL-owned shared prerequisite requires remove function"), rollbackErr)
		}
		metadata = sharedMetadata{SchemaVersion: sharedMetadataVersion, Owned: applied.Owned}
		if err := writeSharedMetadata(dir, metadata); err != nil {
			var rollbackErr error
			if applied.Rollback != nil {
				rollbackErr = applied.Rollback(context.WithoutCancel(ctx))
			}
			return nil, false, errors.Join(err, rollbackErr)
		}
	} else {
		metadata, err = readSharedMetadata(dir)
		if err != nil {
			return nil, false, err
		}
		if metadata.Owned && remove == nil {
			return nil, false, fmt.Errorf("STL-owned shared prerequisite requires remove function")
		}
	}

	if err := createOwnerMarker(marker); err != nil {
		if !first {
			return nil, false, err
		}
		var rollbackErr error
		if applied.Rollback != nil {
			rollbackErr = applied.Rollback(context.WithoutCancel(ctx))
		}
		if rollbackErr != nil {
			// Keep metadata as an orphan marker so a future Ensure fails closed
			// instead of re-applying uncertain host state.
			return nil, false, errors.Join(err, rollbackErr)
		}
		metadataErr := removeSharedMetadata(dir)
		return nil, false, errors.Join(err, metadataErr)
	}

	undo := func(undoCtx context.Context) error {
		undoUnlock, undoDir, undoMarker, err := m.lock(undoCtx, id, key)
		if err != nil {
			return err
		}
		defer undoUnlock()
		markerExists, err := pathExists(undoMarker)
		if err != nil {
			return err
		}
		if !markerExists {
			return nil
		}
		owners, err := sharedOwners(undoDir)
		if err != nil {
			return err
		}
		meta, err := readSharedMetadata(undoDir)
		if err != nil {
			return err
		}
		if len(owners) > 1 {
			return removeOwnerMarker(undoMarker)
		}
		if err := removeOwnerMarker(undoMarker); err != nil {
			return err
		}
		if meta.Owned {
			cleanup := remove
			if first && applied.Rollback != nil {
				cleanup = applied.Rollback
			}
			if cleanup == nil {
				markerErr := createOwnerMarker(undoMarker)
				return errors.Join(fmt.Errorf("STL-owned shared prerequisite has no cleanup function"), markerErr)
			}
			if err := cleanup(undoCtx); err != nil {
				markerErr := createOwnerMarker(undoMarker)
				return errors.Join(err, wrapIf(markerErr, "restore shared owner marker"))
			}
		}
		return removeSharedMetadata(undoDir)
	}
	return undo, true, nil
}

// Release removes one Link's shared ownership. The host prerequisite is removed
// only for the last owner and only when durable metadata proves it is STL-owned.
// A remove failure restores the owner marker so later repair remains possible.
func (m *SharedPrerequisites) Release(ctx context.Context, id domain.LinkID, key string, remove SharedRemove) (bool, error) {
	if err := id.Validate(); err != nil {
		return false, err
	}
	if err := validateSharedKey(key); err != nil {
		return false, err
	}
	unlock, dir, marker, err := m.lock(ctx, id, key)
	if err != nil {
		return false, err
	}
	defer unlock()
	markerExists, err := pathExists(marker)
	if err != nil {
		return false, err
	}
	if !markerExists {
		return false, nil
	}
	owners, err := sharedOwners(dir)
	if err != nil {
		return false, err
	}
	metadata, err := readSharedMetadata(dir)
	if err != nil {
		return false, err
	}
	if metadata.Owned && remove == nil {
		return false, fmt.Errorf("STL-owned shared prerequisite requires remove function")
	}
	if len(owners) > 1 {
		if err := removeOwnerMarker(marker); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := removeOwnerMarker(marker); err != nil {
		return false, err
	}
	if metadata.Owned {
		if err := remove(ctx); err != nil {
			markerErr := createOwnerMarker(marker)
			return false, errors.Join(err, wrapIf(markerErr, "restore shared owner marker"))
		}
	}
	if err := removeSharedMetadata(dir); err != nil {
		return false, err
	}
	return true, nil
}

func (m *SharedPrerequisites) Owners(ctx context.Context, key string) ([]domain.LinkID, error) {
	if err := validateSharedKey(key); err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(m.root); err != nil {
		return nil, err
	}
	hash := sharedKeyHash(key)
	lock, err := acquireFileLock(ctx, filepath.Join(m.root, ".locks", hash+".lock"))
	if err != nil {
		return nil, err
	}
	defer lock.release()
	return sharedOwners(filepath.Join(m.root, hash))
}

func (m *SharedPrerequisites) lock(ctx context.Context, id domain.LinkID, key string) (func() error, string, string, error) {
	if err := ensurePrivateDir(m.root); err != nil {
		return nil, "", "", err
	}
	hash := sharedKeyHash(key)
	lock, err := acquireFileLock(ctx, filepath.Join(m.root, ".locks", hash+".lock"))
	if err != nil {
		return nil, "", "", err
	}
	dir := filepath.Join(m.root, hash)
	if err := ensurePrivateDir(dir); err != nil {
		_ = lock.release()
		return nil, "", "", err
	}
	return lock.release, dir, filepath.Join(dir, "owner-"+string(id)), nil
}

func sharedOwners(dir string) ([]domain.LinkID, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	owners := make([]domain.LinkID, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "owner-") {
			continue
		}
		id := domain.LinkID(strings.TrimPrefix(entry.Name(), "owner-"))
		if err := id.Validate(); err != nil {
			return nil, fmt.Errorf("invalid shared prerequisite owner marker")
		}
		owners = append(owners, id)
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i] < owners[j] })
	return owners, nil
}

func createOwnerMarker(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncSharedDir(filepath.Dir(path))
}

func removeOwnerMarker(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncSharedDir(filepath.Dir(path))
}

func writeSharedMetadata(dir string, metadata sharedMetadata) error {
	if metadata.SchemaVersion != sharedMetadataVersion {
		return fmt.Errorf("unsupported shared metadata version")
	}
	tmp, err := os.CreateTemp(dir, ".shared-meta-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if err := json.NewEncoder(tmp).Encode(metadata); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	path := filepath.Join(dir, "metadata.json")
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return syncSharedDir(dir)
}

func readSharedMetadata(dir string) (sharedMetadata, error) {
	path := filepath.Join(dir, "metadata.json")
	file, err := os.Open(path)
	if err != nil {
		return sharedMetadata{}, fmt.Errorf("read shared prerequisite metadata: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return sharedMetadata{}, fmt.Errorf("stat shared prerequisite metadata: %w", err)
	}
	const maxSharedMetadataBytes = 4096
	if info.Size() > maxSharedMetadataBytes {
		return sharedMetadata{}, fmt.Errorf("shared prerequisite metadata exceeds %d bytes", maxSharedMetadataBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxSharedMetadataBytes+1))
	decoder.DisallowUnknownFields()
	var metadata sharedMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return sharedMetadata{}, fmt.Errorf("decode shared prerequisite metadata: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return sharedMetadata{}, fmt.Errorf("decode shared prerequisite metadata: multiple JSON values")
		}
		return sharedMetadata{}, fmt.Errorf("decode shared prerequisite metadata trailing data: %w", err)
	}
	if metadata.SchemaVersion != sharedMetadataVersion {
		return sharedMetadata{}, fmt.Errorf("unsupported shared prerequisite metadata version %d", metadata.SchemaVersion)
	}
	return metadata, nil
}

func removeSharedMetadata(dir string) error {
	path := filepath.Join(dir, "metadata.json")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncSharedDir(dir)
}

func syncSharedDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validateSharedKey(key string) error {
	if key == "" || len(key) > 512 || strings.TrimSpace(key) != key || strings.ContainsAny(key, "\r\n\x00") {
		return fmt.Errorf("invalid shared prerequisite key")
	}
	return nil
}

func sharedKeyHash(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func wrapIf(err error, operation string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
