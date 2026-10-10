package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const (
	SchemaVersion       = 2
	legacySchemaVersion = 1
	DefaultRoot         = "/var/lib/simple-tun-link"
)

var ErrNotFound = errors.New("link state not found")

// PublicationError means a state rename already succeeded, but subsequent
// durability/metadata work failed. The caller must not compensate blindly;
// the visible snapshot may already contain the new authoritative intent.
type PublicationError struct{ Cause error }

func (e *PublicationError) Error() string {
	return "desired-state publication outcome requires reconciliation"
}
func (e *PublicationError) Unwrap() error { return e.Cause }

type LinkRecord struct {
	Desired        domain.Link            `json:"desired"`
	OwnedResources []domain.ResourceClaim `json:"owned_resources,omitempty"`
}

type Snapshot struct {
	SchemaVersion int          `json:"schema_version"`
	Links         []LinkRecord `json:"links"`
}

func EmptySnapshot() Snapshot {
	return Snapshot{SchemaVersion: SchemaVersion, Links: []LinkRecord{}}
}

func (s Snapshot) Find(id domain.LinkID) (LinkRecord, bool) {
	for _, record := range s.Links {
		if record.Desired.ID == id {
			return record, true
		}
	}
	return LinkRecord{}, false
}

func (s *Snapshot) Upsert(record LinkRecord) {
	for i := range s.Links {
		if s.Links[i].Desired.ID == record.Desired.ID {
			s.Links[i] = cloneRecord(record)
			s.normalize()
			return
		}
	}
	s.Links = append(s.Links, cloneRecord(record))
	s.normalize()
}

func (s *Snapshot) Delete(id domain.LinkID) bool {
	for i := range s.Links {
		if s.Links[i].Desired.ID == id {
			copy(s.Links[i:], s.Links[i+1:])
			s.Links = s.Links[:len(s.Links)-1]
			s.normalize()
			return true
		}
	}
	return false
}

func (s *Snapshot) normalize() {
	if s.SchemaVersion == 0 {
		s.SchemaVersion = SchemaVersion
	}
	if s.Links == nil {
		s.Links = []LinkRecord{}
	}
	for i := range s.Links {
		s.Links[i].OwnedResources = normalizeClaims(s.Links[i].OwnedResources)
	}
	sort.Slice(s.Links, func(i, j int) bool {
		return s.Links[i].Desired.ID < s.Links[j].Desired.ID
	})
}

type Store interface {
	Load(context.Context) (Snapshot, error)
	Update(context.Context, func(*Snapshot) error) error
}

type FileStore struct {
	root      string
	statePath string
	lockPath  string
	// afterPublish injects a post-rename failure in isolated tests only.
	afterPublish func() error
}

func NewFileStore(root string) *FileStore {
	return &FileStore{
		root:      root,
		statePath: filepath.Join(root, "state.json"),
		lockPath:  filepath.Join(root, ".state.lock"),
	}
}

// HasCommittedState distinguishes a durable empty desired-state snapshot from
// absent state (for example an unavailable mount). Absence is never proof that
// an existing restore unit may safely be removed.
func (s *FileStore) HasCommittedState(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	info, err := os.Lstat(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("desired-state path is not a regular file")
	}
	return true, nil
}

func (s *FileStore) Load(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return s.loadUnlocked()
}

func (s *FileStore) Update(ctx context.Context, mutate func(*Snapshot) error) error {
	if mutate == nil {
		return fmt.Errorf("state mutate function is required")
	}
	if err := ensurePrivateDir(s.root); err != nil {
		return err
	}
	lock, err := acquireFileLock(ctx, s.lockPath)
	if err != nil {
		return err
	}
	defer lock.release()

	snapshot, err := s.loadUnlocked()
	if err != nil {
		return err
	}
	if err := mutate(&snapshot); err != nil {
		return err
	}
	snapshot.normalize()
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	return s.writeAtomic(snapshot)
}

func (s *FileStore) loadUnlocked() (Snapshot, error) {
	f, err := os.Open(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return EmptySnapshot(), nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return Snapshot{}, err
	}
	const maxStateBytes = 16 << 20
	if info.Size() > maxStateBytes {
		return Snapshot{}, fmt.Errorf("state file exceeds %d bytes", maxStateBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Snapshot{}, fmt.Errorf("decode state: multiple JSON values")
		}
		return Snapshot{}, fmt.Errorf("decode state trailing data: %w", err)
	}
	snapshot, err = migrateSnapshot(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.normalize()
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func migrateSnapshot(snapshot Snapshot) (Snapshot, error) {
	switch snapshot.SchemaVersion {
	case SchemaVersion:
		return snapshot, nil
	case legacySchemaVersion:
		for _, record := range snapshot.Links {
			link := record.Desired
			if link.GRE != (domain.GREOptions{}) {
				return Snapshot{}, fmt.Errorf("legacy state schema v1 cannot contain GRE backend options; regenerate the Link state")
			}
			if link.WireGuard != (domain.WireGuardOptions{}) {
				return Snapshot{}, fmt.Errorf("legacy state schema v1 cannot contain WireGuard backend options; regenerate the Link state")
			}
			if link.Backend == domain.BackendGRE && (link.Encapsulation == domain.EncapFOU || link.Encapsulation == domain.EncapGUE) {
				return Snapshot{}, fmt.Errorf("legacy GRE FOU/GUE state lacks the required UDP port; regenerate the Link state")
			}
		}
		snapshot.SchemaVersion = SchemaVersion
		return snapshot, nil
	default:
		return Snapshot{}, fmt.Errorf("unsupported state schema_version %d", snapshot.SchemaVersion)
	}
}

func (s *FileStore) writeAtomic(snapshot Snapshot) error {
	if err := ensurePrivateDir(s.root); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.root, ".state-*.tmp")
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
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snapshot); err != nil {
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
	if err := os.Rename(tmpName, s.statePath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if s.afterPublish != nil {
		if err := s.afterPublish(); err != nil {
			return &PublicationError{Cause: err}
		}
	}
	if err := os.Chmod(s.statePath, 0o600); err != nil {
		return &PublicationError{Cause: err}
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return &PublicationError{Cause: err}
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return &PublicationError{Cause: err}
	}
	return nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported state schema_version %d", snapshot.SchemaVersion)
	}
	seen := make(map[domain.LinkID]struct{}, len(snapshot.Links))
	for _, record := range snapshot.Links {
		if err := record.Desired.Validate(); err != nil {
			return fmt.Errorf("invalid desired Link %q: %w", record.Desired.ID, err)
		}
		if _, exists := seen[record.Desired.ID]; exists {
			return fmt.Errorf("duplicate Link ID %q", record.Desired.ID)
		}
		seen[record.Desired.ID] = struct{}{}
		for _, claim := range record.OwnedResources {
			if err := claim.Validate(); err != nil {
				return fmt.Errorf("invalid resource claim for %q: %w", record.Desired.ID, err)
			}
		}
	}
	return nil
}

func cloneRecord(record LinkRecord) LinkRecord {
	copyRecord := record
	copyRecord.OwnedResources = append([]domain.ResourceClaim(nil), record.OwnedResources...)
	return copyRecord
}

func normalizeClaims(claims []domain.ResourceClaim) []domain.ResourceClaim {
	if len(claims) == 0 {
		return nil
	}
	byKey := make(map[string]domain.ResourceClaim, len(claims))
	for _, claim := range claims {
		byKey[claim.Canonical()] = claim
	}
	out := make([]domain.ResourceClaim, 0, len(byKey))
	for _, claim := range byKey {
		out = append(out, claim)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Canonical() < out[j].Canonical() })
	return out
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}
