package main

import (
	"bufio"
	"context"
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
	if err != nil {
		return "", fmt.Errorf("protected handoff directory not trusted")
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
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
	if selected.Backend != domain.BackendWireGuard && selected.Backend != domain.BackendIPsec {
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
	if !ok || current.Desired != selected {
		return "", fmt.Errorf("saved Link changed or is no longer present")
	}
	path, err := protectedMenuHandoffPath(options, selected.ID)
	if err != nil {
		return "", err
	}
	raw, err := readPrivateHandoffFile(path)
	if err != nil {
		return "", err
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
	if selected.Backend != domain.BackendWireGuard && selected.Backend != domain.BackendIPsec {
		return 2
	}
	if deleteSaved {
		fmt.Fprintln(out, "\nDelete ONLY the saved private receiver Setup Link for this tunnel?")
		fmt.Fprintln(out, "The ACTIVE tunnel and its current keys remain unchanged, but this same receiver offer")
		fmt.Fprintln(out, "cannot be regenerated after deletion. Keep your own offline copy if needed.")
	} else {
		menuSection(out, "Protected Setup Link / private credential")
		fmt.Fprintln(out, "The receiver Setup Link contains a PRIVATE credential.")
		fmt.Fprintln(out, "Displaying it is intentional: anyone viewing your terminal/screen/history can copy it.")
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
	fmt.Fprintf(out, "Type %s to confirm (Enter cancels): ", requested)
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
		if err := secureDeleteProtectedMenuHandoff(options, selected); err != nil {
			fmt.Fprintln(errOut, "Protected handoff deletion could not be confirmed: "+err.Error())
			return 1
		}
		menuNotice(out, "OK", "Protected Setup Link deleted; the tunnel and its local credentials were NOT changed.")
		return 0
	}
	encoded, err := validatedSavedProtectedMenuOffer(options, selected)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot show the protected Setup Link: "+err.Error())
		fmt.Fprintln(out, "If this Link was created in an older version, use its original private handoff file. No new credentials were generated.")
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
