package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/app"
	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

const protectedMenuHandoffDir = "receiver-handoffs"

// Public --output is operator-owned, even if it deliberately points into
// STL's State root. The menu's private namespace is a separate ownership
// contract: only a fresh, confirmed guided Create may publish its exact ID
// there. This check must run before any new credential is generated.
func checkCreatorHandoffDestination(options *runtimeOptions, id domain.LinkID, output string) error {
	if err := checkSensitiveHandoffDestination(output); err != nil {
		return err
	}
	root := createStateRoot(options)
	if root == "" || id.Validate() != nil {
		return fmt.Errorf("cannot verify private receiver handoff ownership")
	}
	reserved := filepath.Join(root, protectedMenuHandoffDir)
	rel, err := filepath.Rel(reserved, output)
	if err != nil {
		return fmt.Errorf("cannot compare receiver handoff ownership")
	}
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		expected, pathErr := protectedMenuHandoffPath(options, id)
		if pathErr != nil || options == nil || options.menuHandoffID != id || output != expected {
			return fmt.Errorf("reserved receiver handoff directory is owned by guided Create, not CLI --output")
		}
	}
	return nil
}

// The scoped identity lives only on a copy passed to a guided Create
// after its own real-terminal confirmation and protected path preparation.
func menuHandoffCreationOptions(options *runtimeOptions, id domain.LinkID) *runtimeOptions {
	if options == nil {
		return &runtimeOptions{stateRoot: state.DefaultRoot, menuHandoffID: id}
	}
	scoped := *options
	scoped.menuHandoffID = id
	return &scoped
}

// Only the guided menu writes this nonsecret, owner-private origin receipt.
// Previous releases could let a public CLI choose the same pathname; such a
// file is not automatically menu-owned without this distinct proof.
func menuHandoffOriginPath(options *runtimeOptions, id domain.LinkID) (string, error) {
	path, err := protectedMenuHandoffPath(options, id)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(path, ".stl") + ".origin", nil
}

func menuHandoffOriginText(id domain.LinkID, original string, stat unix.Stat_t) string {
	digest := sha256.Sum256([]byte(original + "\n"))
	return fmt.Sprintf("stl-menu-origin-v1 %s %x %d %d %d %d %d %d",
		id, digest, stat.Dev, stat.Ino, stat.Ctim.Sec, stat.Ctim.Nsec,
		stat.Mtim.Sec, stat.Mtim.Nsec)
}

// Read only the exact original and its still-committed sender identity.
// Absence/mismatch never grants permission to synthesize a menu receipt.
func recordMenuHandoffOrigin(options *runtimeOptions, id domain.LinkID) error {
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	snapshot, err := state.NewFileStore(createStateRoot(options)).Load(ctx)
	if err != nil {
		return fmt.Errorf("saved Link unavailable for menu origin proof")
	}
	record, present := snapshot.Find(id)
	if !present {
		return fmt.Errorf("menu origin proof requires a committed Link")
	}
	original, err := validatedSavedProtectedMenuOffer(options, record.Desired)
	if err != nil {
		return fmt.Errorf("saved menu original cannot be validated")
	}
	filePath, err := protectedMenuHandoffPath(options, id)
	if err != nil {
		return err
	}
	readBack, stat, err := readPrivateHandoffFileWithStat(filePath)
	if err != nil || readBack != original {
		return fmt.Errorf("saved menu offer changed before provenance publication")
	}
	markerPath, err := menuHandoffOriginPath(options, id)
	if err != nil {
		return err
	}
	expected := menuHandoffOriginText(id, original, stat)
	current, err := readPrivateHandoffFile(markerPath)
	if err == nil {
		if current == expected {
			return nil // Confirmed idempotent original, not an adoption.
		}
		return fmt.Errorf("menu origin receipt already exists with different identity")
	}
	if !errors.Is(err, errProtectedMenuOfferMissing) {
		return fmt.Errorf("existing menu origin receipt cannot be verified")
	}
	return writeSensitiveHandoff(markerPath, []byte(expected+"\n"))
}

func verifiedMenuHandoffOrigin(options *runtimeOptions, id domain.LinkID, original string, stat unix.Stat_t) (string, [sha256.Size]byte, unix.Stat_t, error) {
	path, err := menuHandoffOriginPath(options, id)
	if err != nil {
		return "", [sha256.Size]byte{}, unix.Stat_t{}, err
	}
	actual, markerStat, err := readPrivateHandoffFileWithStat(path)
	if err != nil || actual != menuHandoffOriginText(id, original, stat) {
		return "", [sha256.Size]byte{}, unix.Stat_t{}, fmt.Errorf("saved receiver offer has no matching verified menu origin; preserve it for explicit inspection")
	}
	return path, sha256.Sum256([]byte(actual + "\n")), markerStat, nil
}

var errProtectedMenuOfferMissing = errors.New("original protected receiver Setup Link not saved here")

// The path is private, deterministic for each immutable Link ID, and never
// recorded in the public desired-state snapshot. A successful guided sender
// Create stores its exact original receiver offer here (not a regenerated key).
// Historical explicitly-named CLI handoffs remain at their old locations.
func protectedMenuHandoffPath(options *runtimeOptions, id domain.LinkID) (string, error) {
	if id.Validate() != nil {
		return "", fmt.Errorf("invalid protected handoff link identity")
	}
	root := createStateRoot(options)
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return "", fmt.Errorf("protected state root is unavailable")
	}
	return filepath.Join(root, protectedMenuHandoffDir, string(id)+".stl"), nil
}

// Called only AFTER a fresh, explicit Create confirmation. Never chmod,
// truncate, clobber, or adopt a directory created by another owner; the
// descriptor-relative handoff writer rechecks ownership and mode at publish.
func prepareProtectedMenuHandoff(options *runtimeOptions, id domain.LinkID) (string, error) {
	path, err := protectedMenuHandoffPath(options, id)
	if err != nil {
		return "", err
	}
	root := createStateRoot(options)
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("cannot create private STL state directory")
	}
	fd, err := openPrivateHandoffParent(root)
	if err != nil {
		return "", fmt.Errorf("STL state directory has unsafe ownership or permissions")
	}
	defer unix.Close(fd)
	if err := unix.Mkdirat(fd, protectedMenuHandoffDir, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return "", fmt.Errorf("cannot prepare owned protected Setup Link directory")
	}
	destDir, err := openPrivateHandoffParent(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("protected Setup Link directory is not trusted/private")
	}
	unix.Close(destDir)
	if err := checkSensitiveHandoffDestination(path); err != nil {
		return "", fmt.Errorf("saved receiver handoff path is already occupied or unsafe; inspect existing private files before retry")
	}
	return path, nil
}

// Safely read a single persisted, owner-private handoff using no-follow,
// private-ancestor checks. Never accept an arbitrary filename or even a
// regular file with extra hardlinks/incorrect ownership/mode.
func readPrivateHandoffFile(path string) (string, error) {
	raw, _, err := readPrivateHandoffFileWithStat(path)
	return raw, err
}

// Every validated read can also pin the original device/inode/metadata
// without ever returning secret material in logs or machine output.
func readPrivateHandoffFileWithStat(path string) (string, unix.Stat_t, error) {
	dir, err := openPrivateHandoffParent(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return "", unix.Stat_t{}, errProtectedMenuOfferMissing
	}
	if err != nil {
		return "", unix.Stat_t{}, fmt.Errorf("protected handoff directory not trusted")
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return "", unix.Stat_t{}, errProtectedMenuOfferMissing
	}
	if err != nil {
		return "", unix.Stat_t{}, fmt.Errorf("saved protected receiver handoff not available")
	}
	file := os.NewFile(uintptr(fd), "protected-receiver-handoff")
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != uint32(os.Geteuid()) || before.Mode&0o777 != 0o600 ||
		before.Nlink != 1 || before.Size < 1 || before.Size > int64(max(pairing.MaxLinkBytes, maxMASQUEOfferBytes)+1) {
		return "", unix.Stat_t{}, fmt.Errorf("receiver handoff file failed trusted identity/mode checks")
	}
	data, err := io.ReadAll(io.LimitReader(file, max(pairing.MaxLinkBytes, maxMASQUEOfferBytes)+2))
	if err != nil || len(data) != int(before.Size) {
		return "", unix.Stat_t{}, fmt.Errorf("cannot safely read exact receiver handoff")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil ||
		before.Ino != after.Ino || before.Dev != after.Dev || before.Size != after.Size ||
		before.Ctim != after.Ctim || before.Mtim != after.Mtim {
		return "", unix.Stat_t{}, fmt.Errorf("receiver handoff changed during the read")
	}
	if len(data) < 7 || data[len(data)-1] != '\n' {
		return "", unix.Stat_t{}, fmt.Errorf("saved handoff has invalid line framing")
	}
	data = data[:len(data)-1]
	if strings.IndexByte(string(data), '\n') >= 0 || strings.IndexByte(string(data), '\r') >= 0 {
		return "", unix.Stat_t{}, fmt.Errorf("saved handoff has invalid line framing")
	}
	return string(data), before, nil
}

func validatedSavedProtectedMenuOffer(options *runtimeOptions, selected domain.Link) (string, error) {
	if selected.Backend != domain.BackendWireGuard && selected.Backend != domain.BackendIPsec && selected.Backend != domain.BackendWireGuardWSS && selected.Backend != domain.BackendWireGuardQUIC && selected.Backend != domain.BackendMASQUE {
		return "", fmt.Errorf("this backend does not use protected handoff files")
	}
	root := createStateRoot(options)
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil {
		return "", fmt.Errorf("cannot verify current saved Link identity")
	}
	current, ok := snapshot.Find(selected.ID)
	if !ok || current.Desired != selected || current.WSSSupersededBy != "" {
		return "", fmt.Errorf("saved Link changed, was superseded or is no longer present")
	}
	if _, pending := snapshot.FindWSSCrashOperation(selected.ID); pending {
		return "", fmt.Errorf("WSS Link has an unresolved protected operation")
	}
	if _, pending := snapshot.FindQUICCrashOperation(selected.ID); pending {
		return "", fmt.Errorf("QUIC Link has an unresolved protected operation")
	}
	path, err := protectedMenuHandoffPath(options, selected.ID)
	if err != nil {
		return "", err
	}
	raw, err := readPrivateHandoffFile(path)
	if err != nil {
		return "", err
	}
	if selected.Backend == domain.BackendMASQUE {
		if _, pending := snapshot.FindMASQUEOperation(selected.ID); pending {
			return "", fmt.Errorf("original MASQUE Link has an unresolved host operation")
		}
		offer, private, err := decodeMASQUEOffer(strings.NewReader(raw), root)
		defer clear(private)
		if err != nil {
			return "", fmt.Errorf("original MASQUE handoff is invalid")
		}
		defer offer.Clear()
		if offer.Sender != selected {
			return "", fmt.Errorf("MASQUE handoff does not match the committed original sender Link")
		}
		return raw, nil
	}
	if selected.Backend == domain.BackendWireGuardQUIC {
		offer, decoded, err := decodeQUICOffer(strings.NewReader(raw))
		defer clear(decoded)
		if err != nil {
			return "", fmt.Errorf("stored QUIC handoff is invalid")
		}
		defer offer.clear()
		if !quicOfferMatchesSenderGeneration(offer, current) {
			return "", fmt.Errorf("stored QUIC handoff does not match the current sender generation")
		}
		return raw, nil
	}
	if selected.Backend == domain.BackendWireGuardWSS {
		offer, _, err := decodeWSSOffer(strings.NewReader(raw))
		if err != nil {
			return "", fmt.Errorf("stored WSS handoff is invalid")
		}
		defer offer.clear()
		if offer.Sender != selected {
			return "", fmt.Errorf("stored WSS handoff does not match the current sender Link")
		}
		return raw, nil
	}
	offer, err := pairing.DecodeSetupLink(raw)
	if err != nil {
		return "", fmt.Errorf("stored handoff is invalid or unsupported")
	}
	defer offer.ClearRecipientCredential()
	expected := selected
	expected.MTU = domain.MTUPolicy{}
	if !offer.IsSensitive() || offer.Link() != expected || offer.Mode() != pairing.ModeQuick {
		return "", fmt.Errorf("saved receiver handoff does not match the current Link")
	}
	preview := offer.Preview()
	if selected.Backend == domain.BackendWireGuard && (preview.SchemaVersion != pairing.WireGuardSchemaVersion || offer.CredentialKind() != pairing.CredentialWireGuardPrivateKey) ||
		selected.Backend == domain.BackendIPsec && (preview.SchemaVersion != pairing.SchemaVersion || offer.CredentialKind() != pairing.CredentialIPsecPSK) {
		return "", fmt.Errorf("saved receiver handoff has an unsupported credential kind")
	}
	if selected.Backend == domain.BackendIPsec {
		// An IPsec PSK has no public-key identity binding. Refuse a
		// same-ID/endpoint but DIFFERENT private PSK substituted in an
		// otherwise syntactically valid owner-only receiver handoff.
		// Verify it against the original protected local sender PSK,
		// never against normal desired State or an untrusted file alone.
		secret := offer.RecipientCredential()
		defer clear(secret)
		keys, keyErr := ipsecbackend.NewPSKStore(root)
		if len(secret) != 32 || keyErr != nil || keys.RequireExistingExact(selected.ID, secret) != nil {
			return "", fmt.Errorf("protected receiver PSK cannot be matched to the stored sender credential")
		}
	}
	return raw, nil
}

// A CLI-created WSS sender deliberately owns its original offer at the
// operator-selected --output filename, not at the menu's private path.
// Reading it requires an explicit TTY SHOW and the exact same sender/State
// identity and private-file trust checks; it never creates/reissues keys or
// copies the offer into another persistent location.
func validatedExternalWSSMenuOffer(options *runtimeOptions, selected domain.Link, privatePath string) (string, error) {
	if selected.Backend != domain.BackendWireGuardWSS || !filepath.IsAbs(privatePath) ||
		filepath.Clean(privatePath) != privatePath || privatePath == "/" {
		return "", fmt.Errorf("enter the original absolute private file path of the WSS sender")
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	snapshot, err := state.NewFileStore(createStateRoot(options)).Load(ctx)
	if err != nil {
		return "", fmt.Errorf("current WSS Link identity is unverified")
	}
	current, present := snapshot.Find(selected.ID)
	if !present || current.Desired != selected || current.WSSSupersededBy != "" {
		return "", fmt.Errorf("saved sender Link changed, was superseded or is missing")
	}
	if _, pending := snapshot.FindWSSCrashOperation(selected.ID); pending {
		return "", fmt.Errorf("original WSS Link has an unresolved operation")
	}
	raw, err := readPrivateHandoffFile(privatePath)
	if err != nil {
		return "", fmt.Errorf("original handoff is missing or failed private ownership/mode checks")
	}
	offer, _, err := decodeWSSOffer(strings.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("original file is not a versioned WSS receiver offer")
	}
	defer offer.clear()
	if offer.Sender != selected {
		return "", fmt.Errorf("private offer is not the original sender offer for this saved Link")
	}
	return raw, nil
}

// The token is shared only by the two original QUIC endpoints. Its public
// committed digest binds a private receiver offer to the original sender
// issuance; a syntactically valid replacement bundle is not a reissue right.
func quicOfferMatchesSenderGeneration(offer quicOffer, record state.LinkRecord) bool {
	if offer.Sender != record.Desired || record.QUICGeneration.Validate(record.Desired) != nil {
		return false
	}
	token := offer.ReceiverTLS["authorization-token"]
	if len(token) != 65 || token[64] != '\n' {
		return false
	}
	digest := sha256.Sum256(token[:64])
	if hex.EncodeToString(digest[:]) != record.QUICGeneration.Files.Authorization {
		return false
	}
	secret, present := offer.ReceiverTLS["obfs-secret"]
	if offer.Sender.QUIC.Obfuscation == "" {
		return !present && record.QUICGeneration.Files.ObfuscationSHA256 == ""
	}
	if len(secret) != 65 || secret[64] != '\n' {
		return false
	}
	digest = sha256.Sum256(secret[:64])
	return hex.EncodeToString(digest[:]) == record.QUICGeneration.Files.ObfuscationSHA256
}

// QUIC CLI handoffs use the same explicit private-file disclosure boundary.
func validatedExternalQUICMenuOffer(options *runtimeOptions, selected domain.Link, privatePath string) (string, error) {
	if selected.Backend != domain.BackendWireGuardQUIC || !filepath.IsAbs(privatePath) ||
		filepath.Clean(privatePath) != privatePath || privatePath == "/" {
		return "", fmt.Errorf("enter the original absolute private file path of the QUIC sender")
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	snapshot, err := state.NewFileStore(createStateRoot(options)).Load(ctx)
	if err != nil {
		return "", fmt.Errorf("current QUIC Link identity is unverified")
	}
	current, present := snapshot.Find(selected.ID)
	if !present || current.Desired != selected {
		return "", fmt.Errorf("saved sender Link changed, was superseded or is missing")
	}
	if _, pending := snapshot.FindQUICCrashOperation(selected.ID); pending {
		return "", fmt.Errorf("original QUIC Link has an unresolved operation")
	}
	raw, err := readPrivateHandoffFile(privatePath)
	if err != nil {
		return "", fmt.Errorf("original handoff is missing or failed private ownership/mode checks")
	}
	offer, decoded, err := decodeQUICOffer(strings.NewReader(raw))
	defer clear(decoded)
	if err != nil {
		return "", fmt.Errorf("original file is not a versioned QUIC receiver offer")
	}
	defer offer.clear()
	if !quicOfferMatchesSenderGeneration(offer, current) {
		return "", fmt.Errorf("private offer is not the original sender offer for this saved Link")
	}
	return raw, nil
}

// A CLI-created MASQUE Link has no menu-owned handoff. Only disclose the
// original trusted private file after explicit SHOW and exact State binding.
func validatedExternalMASQUEMenuOffer(options *runtimeOptions, selected domain.Link, path string) (string, error) {
	if selected.Backend != domain.BackendMASQUE || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return "", fmt.Errorf("MASQUE original file path must be canonical")
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	root := createStateRoot(options)
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil {
		return "", fmt.Errorf("MASQUE committed State unavailable")
	}
	current, present := snapshot.Find(selected.ID)
	if !present || current.Desired != selected {
		return "", fmt.Errorf("original MASQUE Link is not committed")
	}
	if _, pending := snapshot.FindMASQUEOperation(selected.ID); pending {
		return "", fmt.Errorf("original MASQUE operation remains unresolved")
	}
	raw, err := readPrivateHandoffFile(path)
	if err != nil {
		return "", fmt.Errorf("original MASQUE private handoff failed trusted owner/file checks")
	}
	offer, private, err := decodeMASQUEOffer(strings.NewReader(raw), root)
	defer clear(private)
	if err != nil {
		return "", fmt.Errorf("original MASQUE private handoff is invalid")
	}
	defer offer.Clear()
	if offer.Sender != selected {
		return "", fmt.Errorf("original MASQUE handoff belongs to a different credential generation")
	}
	return raw, nil
}

// A successful Remove deletes only the original menu-owned receiver offer.
// This is prepared while the Link is still committed, when its exact private
// generation can be validated against the authenticated sender State. CLI
// --output files are deliberately outside this ownership boundary.
type protectedHandoffRemoval struct {
	id               domain.LinkID
	originalDesired  domain.Link // prevents CLI Remove from retiring a changed sender generation
	path             string
	digest           [sha256.Size]byte
	originalStat     unix.Stat_t
	originPath       string
	originDigest     [sha256.Size]byte
	originStat       unix.Stat_t
	recoveryOriginal *domain.Link // only a journal-bound MASQUE Remove reconciliation
}

func prepareProtectedHandoffRemoval(options *runtimeOptions, id domain.LinkID) (*protectedHandoffRemoval, error) {
	root := createStateRoot(options)
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		return nil, fmt.Errorf("cannot inspect Link State before private handoff retirement")
	}
	record, present := snapshot.Find(id)
	if !present {
		return nil, nil // The canonical Engine reports an unknown Link itself.
	}
	switch record.Desired.Backend {
	case domain.BackendWireGuard, domain.BackendIPsec, domain.BackendWireGuardWSS,
		domain.BackendWireGuardQUIC, domain.BackendMASQUE:
	default:
		return nil, nil
	}
	path, err := protectedMenuHandoffPath(options, id)
	if err != nil {
		return nil, err
	}
	original, err := validatedSavedProtectedMenuOffer(options, record.Desired)
	if errors.Is(err, errProtectedMenuOfferMissing) {
		return nil, nil // Receiver/imported or CLI-created Links own no menu offer.
	}
	if err != nil {
		return nil, fmt.Errorf("original menu-owned receiver offer could not be verified")
	}
	// Pin the exact validated bytes and inode before the destructive Engine
	// Remove. Identical bytes copied into a different inode are not owned.
	readBack, originalStat, err := readPrivateHandoffFileWithStat(path)
	if err != nil || readBack != original {
		return nil, fmt.Errorf("original receiver offer identity changed before removal")
	}
	originPath, originDigest, originStat, err := verifiedMenuHandoffOrigin(options, id, original, originalStat)
	if err != nil {
		return nil, err
	}
	return &protectedHandoffRemoval{id: id, originalDesired: record.Desired, path: path, digest: sha256.Sum256([]byte(original + "\n")),
		originalStat: originalStat, originPath: originPath, originDigest: originDigest, originStat: originStat}, nil
}

// The normal private offer validator rightly rejects a pending MASQUE host
// operation. Reconcile is different: an exact, committed sender and the
// matching durable interrupted-Remove journal authorize *preparation only*.
// Host absence and successful committed recovery still gate actual deletion.
func prepareProtectedHandoffForMASQUERecovery(options *runtimeOptions, id domain.LinkID) (*protectedHandoffRemoval, error) {
	root := createStateRoot(options)
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		return nil, fmt.Errorf("cannot inspect MASQUE recovery State before private cleanup")
	}
	pending, exists := snapshot.FindMASQUEOperation(id)
	if !exists || pending.Operation != "remove" || !pending.HadCommittedLink {
		return nil, nil // No committed interrupted Remove can retire a menu offer.
	}
	record, present := snapshot.Find(id)
	if !present || record.Desired != pending.Intent || record.Desired.Backend != domain.BackendMASQUE {
		return nil, fmt.Errorf("MASQUE pending Remove does not match the committed sender")
	}
	path, err := protectedMenuHandoffPath(options, id)
	if err != nil {
		return nil, err
	}
	original, originalStat, err := readPrivateHandoffFileWithStat(path)
	if errors.Is(err, errProtectedMenuOfferMissing) {
		return nil, nil // An importing receiver or independent CLI sender.
	}
	if err != nil {
		return nil, fmt.Errorf("pending MASQUE original menu offer cannot be verified")
	}
	offer, private, err := decodeMASQUEOffer(strings.NewReader(original), root)
	defer clear(private)
	if err != nil {
		return nil, fmt.Errorf("pending MASQUE original receiver offer is invalid")
	}
	defer offer.Clear()
	if offer.Sender != pending.Intent {
		return nil, fmt.Errorf("pending MASQUE private offer does not match the original sender generation")
	}
	originPath, originDigest, originStat, err := verifiedMenuHandoffOrigin(options, id, original, originalStat)
	if err != nil {
		return nil, err
	}
	expected := pending.Intent
	return &protectedHandoffRemoval{id: id, originalDesired: expected, path: path,
		digest: sha256.Sum256([]byte(original + "\n")), originalStat: originalStat,
		originPath: originPath, originDigest: originDigest, originStat: originStat,
		recoveryOriginal: &expected}, nil
}

func (prepared *protectedHandoffRemoval) retireAfterRemove(options *runtimeOptions) error {
	if prepared == nil {
		return nil
	}
	root := createStateRoot(options)
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	// The Engine releases its Link lock on return. Reacquire that SAME lock
	// across the final State read AND file unlink, so another authorized
	// Ensure/Remove/Recovery cannot change this Link between them.
	release, err := state.NewLockManager(root).Acquire(ctx, []domain.ResourceClaim{app.LinkLockClaim(prepared.id)})
	if err != nil {
		return fmt.Errorf("cannot lock Link for original receiver-offer cleanup")
	}
	defer release()
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil {
		return fmt.Errorf("cannot verify absent Link after committed removal")
	}
	if _, present := snapshot.Find(prepared.id); present {
		return fmt.Errorf("Link identity changed after removal; private offer preserved")
	}
	if _, pending := snapshot.FindMASQUEOperation(prepared.id); pending {
		return fmt.Errorf("MASQUE original operation remains unresolved; private offer preserved")
	}
	if _, pending := snapshot.FindQUICCrashOperation(prepared.id); pending {
		return fmt.Errorf("QUIC original operation remains unresolved; private offer preserved")
	}
	if _, pending := snapshot.FindPendingSender(prepared.id); pending {
		return fmt.Errorf("original sender reservation remains unresolved; private offer preserved")
	}
	if prepared.recoveryOriginal != nil {
		receipt, found := snapshot.FindMASQUERemovalReceipt(prepared.id)
		if !found || receipt.Link != *prepared.recoveryOriginal ||
			receipt.Purpose != "removed" || !receipt.Retired {
			return fmt.Errorf("MASQUE recovered removal receipt is not the verified original; private offer preserved")
		}
	}
	if err := unlinkMatchingProtectedHandoffBound(prepared.path, prepared.digest, &prepared.originalStat); err != nil {
		return err
	}
	// Origin receipt is now obsolete. A mismatch is a committed cleanup
	// failure, not permission to unlink an unverified replacement.
	return unlinkMatchingProtectedHandoffBound(prepared.originPath, prepared.originDigest, &prepared.originStat)
}

// The same bounded descriptor-relative deletion is used by the optional
// explicit DELETE action and automatic post-Remove cleanup. An offered path,
// hardlink, symlink, substituted content or altered inode cannot authorize
// removal of someone else's private file.
func unlinkMatchingProtectedHandoff(path string, expected [sha256.Size]byte) error {
	return unlinkMatchingProtectedHandoffBound(path, expected, nil)
}

func unlinkMatchingProtectedHandoffBound(path string, expected [sha256.Size]byte, original *unix.Stat_t) error {
	dir, err := openPrivateHandoffParent(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil // The owned private directory is already gone.
	}
	if err != nil {
		return fmt.Errorf("protected handoff directory changed")
	}
	defer unix.Close(dir)
	name := filepath.Base(path)
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil // The verified offer was already removed.
	}
	if err != nil {
		return fmt.Errorf("protected handoff file is no longer trusted")
	}
	file := os.NewFile(uintptr(fd), "retiring-protected-handoff")
	defer file.Close()
	var before, after, entry unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&0o777 != 0o600 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 ||
		before.Size < 1 || before.Size > int64(max(pairing.MaxLinkBytes, maxMASQUEOfferBytes)+1) {
		return fmt.Errorf("protected handoff file ownership or length cannot be verified")
	}
	if original != nil && (before.Dev != original.Dev || before.Ino != original.Ino ||
		before.Size != original.Size || before.Ctim != original.Ctim || before.Mtim != original.Mtim) {
		return fmt.Errorf("original protected receiver handoff inode changed; no deletion")
	}
	data, err := io.ReadAll(io.LimitReader(file, max(pairing.MaxLinkBytes, maxMASQUEOfferBytes)+2))
	defer clear(data)
	if err != nil || len(data) != int(before.Size) || sha256.Sum256(data) != expected {
		return fmt.Errorf("protected handoff no longer matches the original Link; no deletion")
	}
	if err := unix.Fstat(fd, &after); err != nil || before.Ino != after.Ino ||
		before.Dev != after.Dev || before.Size != after.Size || before.Mtim != after.Mtim ||
		before.Ctim != after.Ctim || before.Nlink != after.Nlink {
		return fmt.Errorf("protected handoff changed during identity verification")
	}
	if err := unix.Fstatat(dir, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		entry.Ino != before.Ino || entry.Dev != before.Dev || entry.Size != before.Size ||
		entry.Ctim != before.Ctim || entry.Mtim != before.Mtim {
		return fmt.Errorf("protected handoff path changed; no deletion")
	}
	if err := unix.Unlinkat(dir, name, 0); err != nil {
		return fmt.Errorf("cannot delete verified protected handoff")
	}
	if err := unix.Fsync(dir); err != nil {
		return fmt.Errorf("handoff was unlinked but directory durability is unverified")
	}
	return nil
}

func secureDeleteProtectedMenuHandoff(options *runtimeOptions, selected domain.Link) error {
	original, err := validatedSavedProtectedMenuOffer(options, selected)
	if err != nil {
		return err
	}
	path, err := protectedMenuHandoffPath(options, selected.ID)
	if err != nil {
		return err
	}
	readBack, stat, err := readPrivateHandoffFileWithStat(path)
	if err != nil || readBack != original {
		return fmt.Errorf("saved original changed before explicit deletion")
	}
	markerPath, markerDigest, markerStat, markerErr := verifiedMenuHandoffOrigin(options, selected.ID, original, stat)
	if markerErr != nil {
		// Fresh TTY DELETE explicitly authorizes removal of a legacy
		// menu original without an origin receipt. Refuse altered receipts.
		path, pathErr := menuHandoffOriginPath(options, selected.ID)
		if pathErr != nil {
			return pathErr
		}
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("unverified menu origin receipt blocks explicit deletion")
		}
	}
	if err := unlinkMatchingProtectedHandoffBound(path, sha256.Sum256([]byte(original+"\n")), &stat); err != nil {
		return err
	}
	if markerErr == nil {
		return unlinkMatchingProtectedHandoffBound(markerPath, markerDigest, &markerStat)
	}
	return nil
}

func menuSensitiveHandoffAction(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	options *runtimeOptions, selected domain.Link, deleteSaved bool) int {
	stdin, stdinOK := input.(*os.File)
	stdout, stdoutOK := out.(*os.File)
	if !stdinOK || !stdoutOK || !terminalIsInteractive(stdin) || !terminalIsInteractive(stdout) {
		fmt.Fprintln(errOut, "Protected Setup Links require a real interactive terminal. No credential disclosed or deleted.")
		return 2
	}
	if selected.Backend != domain.BackendWireGuard && selected.Backend != domain.BackendIPsec && selected.Backend != domain.BackendWireGuardWSS && selected.Backend != domain.BackendWireGuardQUIC && selected.Backend != domain.BackendMASQUE {
		return 2
	}
	if deleteSaved {
		menuActionSection(out, "Delete saved private Setup Link / preview", "DELETE")
		menuProse(out, "Delete ONLY the saved private receiver Setup Link for this tunnel?")
		menuProse(out, "The ACTIVE tunnel and its current keys remain unchanged, but this same receiver offer")
		fmt.Fprintln(out, "cannot be regenerated after deletion. Keep your own offline copy if needed.")
	} else {
		menuActionSection(out, "Protected Setup Link / private credential", "SHOW")
		fmt.Fprintln(out, "The receiver Setup Link contains a PRIVATE credential.")
		menuProse(out, "Displaying it is intentional: anyone viewing your terminal/screen/history can copy it.")
		fmt.Fprintln(out, "Only display on a private terminal; it is not printed by Status or Diagnostics.")
	}
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "Cannot clear previously queued terminal input. No secret disclosed or deleted.")
		return 2
	}
	requested := "SHOW"
	if deleteSaved {
		requested = "DELETE"
	}
	fmt.Fprintf(out, "Type %s to confirm (Enter cancels): ", menuActionToken(out, requested))
	value, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || err == nil && value != requested {
		fmt.Fprintln(out, "Cancelled. Nothing changed or disclosed.")
		return 0
	}
	if err != nil {
		fmt.Fprintln(errOut, "Invalid protected handoff confirmation.")
		return 2
	}
	if deleteSaved {
		if selected.Backend == domain.BackendWireGuardWSS || selected.Backend == domain.BackendWireGuardQUIC || selected.Backend == domain.BackendMASQUE {
			if _, err := validatedSavedProtectedMenuOffer(options, selected); errors.Is(err, errProtectedMenuOfferMissing) {
				menuNotice(out, "INFO", "No original receiver offer was saved by the menu on this host; nothing to delete. Tunnel and keys unchanged.")
				return 0
			}
		}
		if err := secureDeleteProtectedMenuHandoff(options, selected); err != nil {
			fmt.Fprintln(errOut, "Protected handoff deletion could not be confirmed: "+err.Error())
			return 1
		}
		menuNotice(out, "OK", "Protected Setup Link deleted; the tunnel and its local credentials were NOT changed.")
		return 0
	}
	encoded, err := validatedSavedProtectedMenuOffer(options, selected)
	if errors.Is(err, errProtectedMenuOfferMissing) && (selected.Backend == domain.BackendWireGuardWSS || selected.Backend == domain.BackendWireGuardQUIC || selected.Backend == domain.BackendMASQUE) {
		menuNotice(out, "INFO", "No original receiver offer is saved in this menu on this server.")
		command := "create-wss"
		if selected.Backend == domain.BackendWireGuardQUIC {
			command = "create-quic"
		}
		if selected.Backend == domain.BackendMASQUE {
			command = "create-masque"
		}
		menuProse(out, "If YOU created this Link using CLI "+command+", provide its original --output file.")
		menuProse(out, "If you IMPORTED the Link, request the original offer from its creator. No keys can be regenerated here.")
		if err := clearQueuedMenuConfirmation(input, reader); err != nil {
			menuNotice(out, "WARNING", "Cannot safely read a fresh private file path; no credential displayed.")
			return 2
		}
		fmt.Fprint(out, "Original sender-private file path (Enter=back): ")
		path, readErr := readMenuAnswer(reader)
		if errors.Is(readErr, io.EOF) || readErr == nil && path == "" {
			menuNotice(out, "INFO", "No original offer selected. Tunnel remains unchanged.")
			return 0
		}
		if readErr != nil {
			menuNotice(out, "WARNING", "Invalid private file path; nothing disclosed.")
			return 2
		}
		switch selected.Backend {
		case domain.BackendWireGuardQUIC:
			encoded, err = validatedExternalQUICMenuOffer(options, selected, path)
		case domain.BackendMASQUE:
			encoded, err = validatedExternalMASQUEMenuOffer(options, selected, path)
		default:
			encoded, err = validatedExternalWSSMenuOffer(options, selected, path)
		}
	}
	if err != nil {
		menuNotice(out, "WARNING", "Protected Setup Link could not be verified; nothing disclosed.")
		menuField(out, "Reason", err.Error())
		menuProse(out, "Keep the original private handoff; never regenerate an active Link's credentials just to share it.")
		return 1
	}
	menuScreen(out, "Sensitive Setup Link / handle privately")
	menuNotice(out, "WARNING", "SENSITIVE Setup Link; the COMPLETE line below contains secret credentials. Share only privately.")
	if _, err := io.WriteString(out, encoded+"\n"); err != nil {
		fmt.Fprintln(errOut, "Could not display the complete protected Setup Link.")
		return 1
	}
	fmt.Fprintln(out, "Keep this credential private. DELETE or verified Remove retires this saved original if cleanup succeeds.")
	return 0
}

// A freshly confirmed, successful Create is already an explicit owner choice
// to prepare the other server. Show the exact saved offer in that SAME real
// interactive terminal result screen so pairing does not require a second
// trip through Manage/Share. Redirected output, error streams and automation
// never receive credentials. Subsequent sharing keeps its own SHOW gate.
func menuShowNewProtectedHandoff(input io.Reader, out io.Writer, options *runtimeOptions, id domain.LinkID) {
	// Publication is menu-scoped even when no TTY is available for display.
	// Never upgrade an unknown legacy CLI file into menu-owned provenance.
	if err := recordMenuHandoffOrigin(options, id); err != nil {
		menuNotice(out, "WARNING", "Saved private receiver offer cannot be verified as menu-owned for automatic removal; preserve it for explicit inspection.")
	}
	in, inputOK := input.(*os.File)
	_, outputOK := menuTerminal(out)
	if !inputOK || !terminalIsInteractive(in) || !outputOK {
		menuProse(out, "Copy receiver Setup Link later: My tunnels -> choose tunnel -> Share Setup Link -> SHOW.")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	snapshot, err := state.NewFileStore(createStateRoot(options)).Load(ctx)
	if err != nil {
		menuNotice(out, "WARNING", "Local tunnel was saved, but its receiver link could not be verified for display.")
		fmt.Fprintln(out, "Try My tunnels -> Share Setup Link after reviewing saved tunnel state.")
		return
	}
	record, present := snapshot.Find(id)
	if !present {
		menuNotice(out, "WARNING", "Cannot verify the newly saved tunnel identity; receiver link was not shown.")
		return
	}
	encoded, err := validatedSavedProtectedMenuOffer(options, record.Desired)
	if err != nil {
		menuNotice(out, "WARNING", "Saved receiver credentials could not be safely verified; nothing was displayed.")
		fmt.Fprintln(out, "Review My tunnels -> Share Setup Link. No new credentials were generated.")
		return
	}
	menuSection(out, "Copy receiver Setup Link")
	menuNotice(out, "WARNING", "The full line below contains a private credential. Copy it to the other server privately.")
	// NEVER use wrapping, logs or a generic printf of decoded credentials.
	if _, err := io.WriteString(out, "\n"+encoded+"\n"); err != nil {
		menuNotice(out, "WARNING", "Could not display the complete receiver link; open My tunnels -> Share to retry.")
		return
	}
	fmt.Fprintln(out, "\nOTHER server: Import setup link -> select matching backend -> private paste -> review -> YES.")
	fmt.Fprintln(out, "This same link stays in private storage until DELETE or verified Remove (if cleanup succeeds).")
}
