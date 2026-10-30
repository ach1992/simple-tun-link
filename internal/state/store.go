package state

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
)

const (
	SchemaVersion        = 5
	preQUICSchemaVersion = 4
	preWSSSchemaVersion  = 3
	legacySchemaVersion  = 1
	preMTUSchemaVersion  = 2
	DefaultRoot          = "/var/lib/simple-tun-link"
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
	QUICGeneration QUICGeneration         `json:"quic_generation,omitzero"`
	Desired        domain.Link            `json:"desired"`
	OwnedResources []domain.ResourceClaim `json:"owned_resources,omitempty"`
	WSSFiles       WSSFileIdentity        `json:"wss_file_digests,omitzero"`
	WSSOrigin      string                 `json:"wss_original_object_nonce,omitempty"`
	// Attested birth/current kernel generation of the original WSS object.
	// Empty values in pre-provenance or untrusted environments are readable,
	// but cannot authorize recreation or retirement from local absence.
	WSSKernelBootID     string `json:"wss_kernel_boot_id,omitempty"`
	WSSKernelBootSource string `json:"wss_kernel_boot_source,omitempty"`
	// A single-use, recovery-scoped old-kernel extinction witness from a
	// trusted manual Arm + Reconcile. It is NOT original birth provenance.
	WSSColdBootRestore WSSColdBootRestore `json:"wss_cold_boot_restore,omitzero"`
	// An explicit operator transition after independent replacement. This
	// retains the ORIGINAL committed State, ownership and private issuance,
	// but permanently bars automatic Restore and ordinary Ensure. Never
	// infer that an original kernel object was deleted from this marker.
	WSSSupersededBy domain.LinkID `json:"wss_superseded_by,omitempty"`
}

type Snapshot struct {
	SchemaVersion           int                      `json:"schema_version"`
	Links                   []LinkRecord             `json:"links"`
	PendingSenders          []PendingSender          `json:"pending_senders,omitempty"`
	PendingIPsec            []PendingIPsec           `json:"pending_ipsec,omitempty"`
	IPsecVICIOperations     []IPsecVICIOperation     `json:"ipsec_vici_operations,omitempty"`
	IPsecReapplyOperations  []IPsecReapplyOperation  `json:"ipsec_reapply_operations,omitempty"`
	IPsecRemoveOperations   []IPsecRemoveOperation   `json:"ipsec_remove_operations,omitempty"`
	IPsecXFRMOperations     []IPsecXFRMOperation     `json:"ipsec_xfrm_operations,omitempty"`
	IPsecRemovalReceipts    []IPsecRemovalReceipt    `json:"ipsec_removal_receipts,omitempty"`
	RemovalReceipts         []RemovalReceipt         `json:"removal_receipts,omitempty"`
	WSSCrashOperations      []WSSCrashOperation      `json:"wss_crash_operations,omitempty"`
	QUICCrashOperations     []QUICCrashOperation     `json:"quic_crash_operations,omitempty"`
	QUICAbandonmentReceipts []QUICAbandonmentReceipt `json:"quic_abandonment_receipts,omitempty"`
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
	sort.Slice(s.PendingSenders, func(i, j int) bool { return s.PendingSenders[i].Link.ID < s.PendingSenders[j].Link.ID })
	sort.Slice(s.PendingIPsec, func(i, j int) bool { return s.PendingIPsec[i].Link.ID < s.PendingIPsec[j].Link.ID })
	sort.Slice(s.IPsecVICIOperations, func(i, j int) bool {
		return s.IPsecVICIOperations[i].Intent.Link.ID < s.IPsecVICIOperations[j].Intent.Link.ID
	})
	sort.Slice(s.IPsecReapplyOperations, func(i, j int) bool {
		return s.IPsecReapplyOperations[i].Intent.ID < s.IPsecReapplyOperations[j].Intent.ID
	})
	sort.Slice(s.IPsecXFRMOperations, func(i, j int) bool {
		return s.IPsecXFRMOperations[i].Intent.ID < s.IPsecXFRMOperations[j].Intent.ID
	})
	sort.Slice(s.IPsecRemoveOperations, func(i, j int) bool {
		return s.IPsecRemoveOperations[i].Intent.ID < s.IPsecRemoveOperations[j].Intent.ID
	})
	sort.Slice(s.IPsecRemovalReceipts, func(i, j int) bool {
		return s.IPsecRemovalReceipts[i].LinkID < s.IPsecRemovalReceipts[j].LinkID
	})
	sort.Slice(s.RemovalReceipts, func(i, j int) bool { return s.RemovalReceipts[i].LinkID < s.RemovalReceipts[j].LinkID })
	sort.Slice(s.QUICAbandonmentReceipts, func(i, j int) bool {
		return s.QUICAbandonmentReceipts[i].Operation.Plan.Local.LinkID < s.QUICAbandonmentReceipts[j].Operation.Plan.Local.LinkID
	})
	for i := range s.WSSCrashOperations {
		s.WSSCrashOperations[i].Resources = normalizeClaims(s.WSSCrashOperations[i].Resources)
	}
	sort.Slice(s.WSSCrashOperations, func(i, j int) bool {
		return s.WSSCrashOperations[i].Intent.ID < s.WSSCrashOperations[j].Intent.ID
	})
	// Do not normalize away duplicate/trimmed QUIC claims: such journals
	// must fail validation instead of silently weakening their reservation.
	sort.Slice(s.QUICCrashOperations, func(i, j int) bool {
		return s.QUICCrashOperations[i].Plan.Local.LinkID < s.QUICCrashOperations[j].Plan.Local.LinkID
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

// RootDir is the exact configured State root, also used by protected
// per-Link credential storage. It is a path locator, not an ownership
// certificate; individual filesystem readers still enforce private access.
func (s *FileStore) RootDir() string { return s.root }

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
	// Already committed logical supersession is immutable for the life of
	// its original Link record. Another writer cannot silently reenable
	// automatic WSS resurrection by rewriting the marker.
	originalSupersessions := make(map[domain.LinkID]domain.LinkID)
	for _, record := range snapshot.Links {
		if record.WSSSupersededBy != "" {
			originalSupersessions[record.Desired.ID] = record.WSSSupersededBy
		}
	}
	// An unresolved QUIC pre-effect operation is immutable/quarantined
	// until a separately reviewed exact-ownership reconciliation exists.
	// Clone claim slices to detect in-place mutation by future Store callers.
	originalQUIC := make([]QUICCrashOperation, len(snapshot.QUICCrashOperations))
	for i, op := range snapshot.QUICCrashOperations {
		originalQUIC[i] = op
		originalQUIC[i].Resources = append([]domain.ResourceClaim(nil), op.Resources...)
		if op.Managed != nil {
			managed := *op.Managed
			originalQUIC[i].Managed = &managed
		}
	}
	originalQUICAbandonments := make([]QUICAbandonmentReceipt, len(snapshot.QUICAbandonmentReceipts))
	for i, r := range snapshot.QUICAbandonmentReceipts {
		originalQUICAbandonments[i] = cloneQUICAbandonment(r)
	}
	if err := mutate(&snapshot); err != nil {
		return err
	}
	snapshot.normalize()
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	if err := validateQUICAbandonmentTransition(originalQUICAbandonments, originalQUIC, snapshot); err != nil {
		return err
	}
	for _, old := range originalQUIC {
		current, found := snapshot.FindQUICCrashOperation(old.Plan.Local.LinkID)
		if found && reflect.DeepEqual(old, current) {
			continue
		}
		if !found && old.Managed != nil && validQUICManagedCompletion(old, snapshot) {
			continue
		}
		return fmt.Errorf("QUIC pre-effect journal cannot be altered or cleared without exact-owned reconciliation")
	}
	for id, replacement := range originalSupersessions {
		if retained, found := snapshot.Find(id); found {
			if retained.WSSSupersededBy != replacement {
				return fmt.Errorf("committed WSS supersession cannot be revoked or retargeted")
			}
		} else {
			// Removing the old original is allowed only through the existing
			// exact-provenance Engine Remove and its atomic retirement receipt.
			receipt, found := snapshot.FindRemovalReceipt(id)
			if !found || receipt.Backend != domain.BackendWireGuardWSS ||
				!ValidWSSOriginalTerminationProof(receipt.WSSOriginalTermination) {
				return fmt.Errorf("superseded WSS original removed without termination receipt")
			}
		}
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
	// Parse the exact same bounded bytes for strict decoding and legacy
	// version checks. A legacy document must not gain managed-host behavior
	// merely because the current domain.Link type now recognizes MTU.
	raw, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read state: %w", err)
	}
	if len(raw) > maxStateBytes {
		return Snapshot{}, fmt.Errorf("state file exceeds %d bytes", maxStateBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
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
	if snapshot.SchemaVersion <= preQUICSchemaVersion {
		if err := rejectLegacyQUICManagedFields(raw); err != nil {
			return Snapshot{}, err
		}
	}
	if snapshot.SchemaVersion <= preWSSSchemaVersion {
		if err := rejectLegacyWSSFields(raw); err != nil {
			return Snapshot{}, err
		}
	}
	if err := rejectLegacyMTUFields(raw, snapshot.SchemaVersion); err != nil {
		return Snapshot{}, err
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

// Older State schemas may not gain WSS or QUIC host effects through JSON
// whitespace, alternate key casing, or nested Link fields during migration.
// Detect keys via actual JSON structure instead of a fragile raw substring.
func rejectLegacyWSSFields(raw []byte) error {
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("inspect legacy WSS State: %w", err)
	}
	var contains func(any) bool
	contains = func(value any) bool {
		switch current := value.(type) {
		case map[string]any:
			for key, child := range current {
				if strings.EqualFold(key, "wss") ||
					strings.EqualFold(key, "wss_crash_operations") ||
					strings.EqualFold(key, "quic_crash_operations") {
					return true
				}
				if contains(child) {
					return true
				}
			}
		case []any:
			for _, child := range current {
				if contains(child) {
					return true
				}
			}
		}
		return false
	}
	if contains(document) {
		return fmt.Errorf("legacy State cannot carry WSS configuration or host effects")
	}
	return nil
}

// The v1/v2 state formats predate the endpoint-local MTU policy. Reject
// its presence anywhere in a legacy state document (including pending
// intents and journals), even with a null/empty value or alternate JSON
// key casing. This freezes the old shapes before any state is promoted.
func rejectLegacyMTUFields(raw []byte, version int) error {
	if version != legacySchemaVersion && version != preMTUSchemaVersion {
		return nil
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("inspect legacy state: %w", err)
	}
	if containsMTUField(document) {
		return fmt.Errorf("state schema_version %d cannot contain MTU policy; use a valid pre-MTU state document", version)
	}
	return nil
}

func containsMTUField(value any) bool {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if strings.EqualFold(key, "mtu") || containsMTUField(child) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if containsMTUField(child) {
				return true
			}
		}
	}
	return false
}

func migrateSnapshot(snapshot Snapshot) (Snapshot, error) {
	switch snapshot.SchemaVersion {
	case SchemaVersion:
		return snapshot, nil
	case preQUICSchemaVersion:
		snapshot.SchemaVersion = SchemaVersion
		return snapshot, nil
	case preWSSSchemaVersion:
		snapshot.SchemaVersion = SchemaVersion
		return snapshot, nil
	case preMTUSchemaVersion:
		snapshot.SchemaVersion = SchemaVersion
		return snapshot, nil
	case legacySchemaVersion:
		if len(snapshot.PendingSenders) > 0 || len(snapshot.PendingIPsec) > 0 ||
			len(snapshot.IPsecVICIOperations) > 0 || len(snapshot.IPsecReapplyOperations) > 0 ||
			len(snapshot.IPsecRemovalReceipts) > 0 || len(snapshot.IPsecRemoveOperations) > 0 ||
			len(snapshot.IPsecXFRMOperations) > 0 ||
			len(snapshot.RemovalReceipts) > 0 {
			return Snapshot{}, fmt.Errorf("legacy state cannot contain backend lifecycle records")
		}
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
		if record.Desired.Backend == domain.BackendWireGuardWSS {
			raw, nonceErr := hex.DecodeString(record.WSSOrigin)
			if nonceErr != nil || len(raw) != 16 || hex.EncodeToString(raw) != record.WSSOrigin {
				return fmt.Errorf("committed WSS Link lacks valid original host-object nonce")
			}
			if err := record.WSSFiles.VerifyLink(record.Desired); err != nil {
				return fmt.Errorf("committed WSS Link missing original credential fingerprints: %w", err)
			}
			if record.WSSKernelBootSource != "" && (record.WSSKernelBootSource != hostidentity.VerifiedHostBootSourceV1 ||
				!hostidentity.ValidBootID(record.WSSKernelBootID)) ||
				(record.WSSKernelBootSource == "" && record.WSSKernelBootID != "") {
				return fmt.Errorf("committed WSS Link has invalid trusted kernel generation provenance")
			}
			if err := record.WSSColdBootRestore.Validate(); err != nil {
				return fmt.Errorf("committed WSS Link has invalid manual cold-boot restore authorization: %w", err)
			}
			if record.WSSSupersededBy != "" &&
				(record.WSSSupersededBy.Validate() != nil || record.WSSSupersededBy == record.Desired.ID) {
				return fmt.Errorf("committed WSS Link has invalid supersession target")
			}
			if record.WSSColdBootRestore != (WSSColdBootRestore{}) && record.WSSKernelBootSource != "" {
				return fmt.Errorf("manual cold-boot restore proof cannot coexist with attested original birth")
			}
		} else if record.WSSFiles != (WSSFileIdentity{}) || record.WSSOrigin != "" ||
			record.WSSKernelBootID != "" || record.WSSKernelBootSource != "" ||
			record.WSSColdBootRestore != (WSSColdBootRestore{}) || record.WSSSupersededBy != "" {
			return fmt.Errorf("native Link cannot carry WSS credential or original host-object identity")
		}
		if record.Desired.Backend == domain.BackendWireGuardQUIC {
			if err := record.QUICGeneration.Validate(record.Desired); err != nil {
				return err
			}
		} else if record.QUICGeneration != (QUICGeneration{}) {
			return fmt.Errorf("non-QUIC Link carries managed QUIC provenance")
		}
		seen[record.Desired.ID] = struct{}{}
		for _, claim := range record.OwnedResources {
			if err := claim.Validate(); err != nil {
				return fmt.Errorf("invalid resource claim for %q: %w", record.Desired.ID, err)
			}
		}
	}
	if err := validateWireGuardLifecycle(snapshot); err != nil {
		return err
	}
	if err := validateIPsecLifecycle(snapshot); err != nil {
		return err
	}
	if err := validateIPsecVICIOperations(snapshot); err != nil {
		return err
	}
	if err := validateIPsecReapplyOperations(snapshot); err != nil {
		return err
	}
	if err := validateIPsecRemoveOperations(snapshot); err != nil {
		return err
	}
	if err := validateIPsecXFRMOperations(snapshot); err != nil {
		return err
	}
	if err := validateIPsecRemovalReceipts(snapshot); err != nil {
		return err
	}
	if err := validateWSSCrashOperations(snapshot); err != nil {
		return err
	}
	if err := validateQUICCrashOperations(snapshot); err != nil {
		return err
	}
	return validateQUICAbandonmentReceipts(snapshot)
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
