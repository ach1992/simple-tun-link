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

	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

const protectedMenuHandoffDir = "receiver-handoffs"

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
	dir, err := openPrivateHandoffParent(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return "", errProtectedMenuOfferMissing
	}
	if err != nil {
		return "", fmt.Errorf("protected handoff directory not trusted")
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return "", errProtectedMenuOfferMissing
	}
	if err != nil {
		return "", fmt.Errorf("saved protected receiver handoff not available")
	}
	file := os.NewFile(uintptr(fd), "protected-receiver-handoff")
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != uint32(os.Geteuid()) || before.Mode&0o777 != 0o600 ||
		before.Nlink != 1 || before.Size < 1 || before.Size > int64(pairing.MaxLinkBytes+1) {
		return "", fmt.Errorf("receiver handoff file failed trusted identity/mode checks")
	}
	data, err := io.ReadAll(io.LimitReader(file, pairing.MaxLinkBytes+2))
	if err != nil || len(data) != int(before.Size) {
		return "", fmt.Errorf("cannot safely read exact receiver handoff")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil ||
		before.Ino != after.Ino || before.Dev != after.Dev || before.Size != after.Size ||
		before.Ctim != after.Ctim || before.Mtim != after.Mtim {
		return "", fmt.Errorf("receiver handoff changed during the read")
	}
	if len(data) < 7 || data[len(data)-1] != '\n' {
		return "", fmt.Errorf("saved handoff has invalid line framing")
	}
	data = data[:len(data)-1]
	if strings.IndexByte(string(data), '\n') >= 0 || strings.IndexByte(string(data), '\r') >= 0 {
		return "", fmt.Errorf("saved handoff has invalid line framing")
	}
	return string(data), nil
}

func validatedSavedProtectedMenuOffer(options *runtimeOptions, selected domain.Link) (string, error) {
	if selected.Backend != domain.BackendWireGuard && selected.Backend != domain.BackendIPsec && selected.Backend != domain.BackendWireGuardWSS && selected.Backend != domain.BackendWireGuardQUIC {
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
	return hex.EncodeToString(digest[:]) == record.QUICGeneration.Files.Authorization
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

func secureDeleteProtectedMenuHandoff(options *runtimeOptions, selected domain.Link) error {
	if _, err := validatedSavedProtectedMenuOffer(options, selected); err != nil {
		return err
	}
	path, err := protectedMenuHandoffPath(options, selected.ID)
	if err != nil {
		return err
	}
	dir, err := openPrivateHandoffParent(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("protected handoff directory changed")
	}
	defer unix.Close(dir)
	name := filepath.Base(path)
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("protected handoff file is no longer available")
	}
	defer unix.Close(fd)
	var current, entry unix.Stat_t
	if err := unix.Fstat(fd, &current); err != nil || current.Mode&unix.S_IFMT != unix.S_IFREG ||
		current.Mode&0o777 != 0o600 || current.Uid != uint32(os.Geteuid()) || current.Nlink != 1 {
		return fmt.Errorf("protected handoff file ownership cannot be verified")
	}
	if err := unix.Fstatat(dir, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		entry.Ino != current.Ino || entry.Dev != current.Dev || entry.Size != current.Size {
		return fmt.Errorf("protected handoff file changed; no deletion attempted")
	}
	if err := unix.Unlinkat(dir, name, 0); err != nil {
		return fmt.Errorf("cannot delete the verified protected handoff")
	}
	if err := unix.Fsync(dir); err != nil {
		return fmt.Errorf("handoff deleted but directory durability uncertain")
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
	if selected.Backend != domain.BackendWireGuard && selected.Backend != domain.BackendIPsec && selected.Backend != domain.BackendWireGuardWSS && selected.Backend != domain.BackendWireGuardQUIC {
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
		if selected.Backend == domain.BackendWireGuardWSS || selected.Backend == domain.BackendWireGuardQUIC {
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
	if errors.Is(err, errProtectedMenuOfferMissing) && (selected.Backend == domain.BackendWireGuardWSS || selected.Backend == domain.BackendWireGuardQUIC) {
		menuNotice(out, "INFO", "No original receiver offer is saved in this menu on this server.")
		command := "create-wss"
		if selected.Backend == domain.BackendWireGuardQUIC {
			command = "create-quic"
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
		if selected.Backend == domain.BackendWireGuardQUIC {
			encoded, err = validatedExternalQUICMenuOffer(options, selected, path)
		} else {
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
	fmt.Fprintln(out, "Keep this credential private. It will remain saved until you explicitly delete it.")
	return 0
}

// A freshly confirmed, successful Create is already an explicit owner choice
// to prepare the other server. Show the exact saved offer in that SAME real
// interactive terminal result screen so pairing does not require a second
// trip through Manage/Share. Redirected output, error streams and automation
// never receive credentials. Subsequent sharing keeps its own SHOW gate.
func menuShowNewProtectedHandoff(input io.Reader, out io.Writer, options *runtimeOptions, id domain.LinkID) {
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
	fmt.Fprintln(out, "This same link stays in private storage until you explicitly delete it.")
}
