package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// These tests deliberately use artificial secrets. Normal status, inventory,
// JSON and errors must NEVER expose even a synthetic receiver credential.
func guidedSavedWireGuardFixture(t *testing.T) (*runtimeOptions, domain.Link, string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	fake := &wireGuardCreatorFake{newLifecycleFake()}
	opts := &runtimeOptions{
		stateRoot: root, backends: []backend.Backend{fake}, probeRunner: &guidedTestRunner{},
		mtuManager: guidedMTUFake{}, createLinkID: func() (domain.LinkID, error) { return createTestID, nil },
		packagePreview: readyGuidedPackagePreview,
	}
	script := "1\n2\n192.0.2.20\n\n51871\n51872\nn\nYES\n8\n"
	var out, errs bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader(script), &out, &errs, opts)
	if code != 0 || errs.Len() != 0 || !strings.Contains(out.String(), "locally ensured") {
		t.Fatalf("guided sender did not finish: exit=%d err=%q", code, errs.String())
	}
	snap, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snap.Links) != 1 {
		t.Fatalf("missing sender Link after guided creation: %v", err)
	}
	link := snap.Links[0].Desired
	path, err := protectedMenuHandoffPath(opts, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := readPrivateHandoffFile(path)
	if err != nil || !strings.HasPrefix(secret, "stl://") {
		t.Fatalf("expected protected retained handoff from real sender Engine: %v", err)
	}
	validated, err := validatedSavedProtectedMenuOffer(opts, link)
	if err != nil || validated != secret {
		t.Fatalf("sender saved wrong original receiver offer: %v", err)
	}
	if strings.Contains(out.String(), secret) || strings.Contains(out.String(), "stl://") {
		t.Fatal("guided creation disclosed a private receiver offer without SHOW")
	}
	return opts, link, path, secret
}

func TestMenuProtectedHandoffSavedAcrossSessionAndShowOnlyWithFreshTTYConsent(t *testing.T) {
	opts, link, path, secret := guidedSavedWireGuardFixture(t)
	original, err := os.Stat(path)
	if err != nil || original.Mode().Perm() != 0o600 {
		t.Fatal("private file not mode 0600")
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatal("private directory not mode 0700")
	}
	before, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	if strings.Contains(tty.all, secret) {
		t.Fatal("secret printed by ordinary inventory")
	}
	tty.send("3")
	tty.expect("Type SHOW to confirm")
	if strings.Contains(tty.all, secret) {
		t.Fatal("secret displayed before consent")
	}
	tty.send("NO")
	tty.expect("Cancelled. Nothing changed or disclosed.")
	if strings.Contains(tty.all, secret) {
		t.Fatal("cancel exposed receiver credential")
	}
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("3")
	tty.expect("Type SHOW to confirm")
	tty.send("SHOW")
	tty.expect("SENSITIVE Setup Link")
	tty.expect("Keep this credential private.")
	if !strings.Contains(tty.all, secret) {
		t.Fatal("exact original receiver offer not re-shown")
	}
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("0")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	after, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(after.Links) != 1 || after.Links[0].Desired != link || before.Links[0].Desired != after.Links[0].Desired {
		t.Fatal("show/cancel mutated saved tunnel")
	}
	still, err := readPrivateHandoffFile(path)
	if err != nil || still != secret {
		t.Fatal("retrieval did not retain identical secret bytes")
	}
}

func TestMenuProtectedHandoffDeniesScriptedOrQueuedDisclosure(t *testing.T) {
	opts, _, path, secret := guidedSavedWireGuardFixture(t)
	code, out, errs := scriptedManage(opts, "3\n1\n3\nSHOW\n0\n8\n")
	if code != 0 || !strings.Contains(errs, "real interactive terminal") ||
		strings.Contains(out+errs, secret) {
		t.Fatal("nonTTY menu disclosed protected URL")
	}
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	// One pasted two-line command BEFORE the preview must be discarded,
	// even if the attacker guesses the correct SHOW confirmation.
	if _, err := io.WriteString(tty.master, "3\nSHOW\n"); err != nil {
		t.Fatal(err)
	}
	tty.expect("Type SHOW to confirm")
	tty.send("")
	tty.expect("Cancelled. Nothing changed or disclosed.")
	if strings.Contains(tty.all, secret) {
		t.Fatal("queued terminal text bypassed fresh consent")
	}
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("0")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if _, err := os.Stat(path); err != nil {
		t.Fatal("queued show deleted saved handoff")
	}
}

func TestMenuProtectedHandoffDeleteOnlyReceiverFileWithFreshConfirmation(t *testing.T) {
	opts, link, path, secret := guidedSavedWireGuardFixture(t)
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("6")
	tty.expect("Type DELETE to confirm")
	tty.send("NO")
	tty.expect("Cancelled. Nothing changed or disclosed.")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("cancel destroyed protected file")
	}
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("6")
	tty.expect("Type DELETE to confirm")
	tty.send("DELETE")
	tty.expect("Protected Setup Link deleted; the tunnel and its local credentials were NOT changed.")
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("3")
	tty.expect("Type SHOW to confirm")
	tty.send("SHOW")
	tty.expect("Protected Setup Link could not be verified")
	if strings.Contains(tty.all, secret) {
		t.Fatal("deleted handoff displayed despite missing file")
	}
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("0")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("protected handoff not removed")
	}
	snap, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(snap.Links) != 1 || snap.Links[0].Desired != link {
		t.Fatal("deleting receiver file changed active local desired Link")
	}
}

func TestMenuProtectedHandoffRejectsSymlinkModeHardlinkWrongLinkAndStaleSavedState(t *testing.T) {
	t.Run("wrong identity", func(t *testing.T) {
		opts, link, path, secret := guidedSavedWireGuardFixture(t)
		original, err := pairing.DecodeSetupLink(secret)
		if err != nil {
			t.Fatal(err)
		}
		defer original.ClearRecipientCredential()
		fake := original.Link()
		fake.ID = domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		offer, err := pairing.NewQuickOffer(fake, original.RecipientCredential())
		if err != nil {
			t.Fatal(err)
		}
		defer offer.ClearRecipientCredential()
		poisoned, err := offer.EncodeSetupLink()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := writeSensitiveHandoff(path, []byte(poisoned+"\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := validatedSavedProtectedMenuOffer(opts, link); err == nil {
			t.Fatal("valid sensitive file for a DIFFERENT Link was disclosed")
		}
		if err := secureDeleteProtectedMenuHandoff(opts, link); err == nil {
			t.Fatal("mismatched Link allowed delete")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		opts, link, path, _ := guidedSavedWireGuardFixture(t)
		alt := filepath.Join(filepath.Dir(path), "trusted-target")
		if err := os.Rename(path, alt); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(alt, path); err != nil {
			t.Fatal(err)
		}
		if _, err := validatedSavedProtectedMenuOffer(opts, link); err == nil {
			t.Fatal("symlink was followed during secret reveal")
		}
		if err := secureDeleteProtectedMenuHandoff(opts, link); err == nil {
			t.Fatal("symlink path was deleted")
		}
		if _, err := os.Stat(alt); err != nil {
			t.Fatal("symlink rejection touched target", err)
		}
	})
	t.Run("world readable", func(t *testing.T) {
		opts, link, path, _ := guidedSavedWireGuardFixture(t)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := validatedSavedProtectedMenuOffer(opts, link); err == nil {
			t.Fatal("non-private mode was disclosed")
		}
		if err := secureDeleteProtectedMenuHandoff(opts, link); err == nil {
			t.Fatal("non-private mode was deleted")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		opts, link, path, _ := guidedSavedWireGuardFixture(t)
		if err := os.Link(path, path+"-alias"); err != nil {
			t.Fatal(err)
		}
		if _, err := validatedSavedProtectedMenuOffer(opts, link); err == nil {
			t.Fatal("multiply-linked receiver file was disclosed")
		}
	})
	t.Run("no committed identity", func(t *testing.T) {
		opts, link, path, _ := guidedSavedWireGuardFixture(t)
		if err := state.NewFileStore(opts.stateRoot).Update(context.Background(), func(s *state.Snapshot) error {
			// Avoid invoking the kernel lifecycle; state-only fixture.
			s.Links = nil
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := validatedSavedProtectedMenuOffer(opts, link); err == nil {
			t.Fatal("orphaned secret disclosed without matching saved Link")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal("root-owned private file unexpectedly destroyed")
		}
	})
}

func TestMenuProtectedHandoffIPsecOriginalPSKRetainedBySavedIntent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	opts := &runtimeOptions{stateRoot: root}
	link, _ := makeLifecycleDesired(t, "a", "10.70.11.0/31")
	link.Backend, link.Encapsulation = domain.BackendIPsec, domain.EncapNATT
	link.GRE = domain.GREOptions{}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err != nil {
		t.Fatalf("cannot prepare saved IPsec intent fixture: %v", err)
	}
	key := bytes.Repeat([]byte{0x4b}, 32)
	store, err := ipsecbackend.NewPSKStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutNew(link.ID, key); err != nil {
		t.Fatal(err)
	}
	offer, err := pairing.NewQuickOffer(link, key)
	if err != nil {
		t.Fatal(err)
	}
	defer offer.ClearRecipientCredential()
	encoded, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	path, err := prepareProtectedMenuHandoff(opts, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSensitiveHandoff(path, []byte(encoded+"\n")); err != nil {
		t.Fatal(err)
	}
	recovered, err := validatedSavedProtectedMenuOffer(opts, link)
	if err != nil || recovered != encoded {
		t.Fatal("IPsec saved protected handoff was not reused", err)
	}
	// The same identity-checked immediate-copy renderer is shared by
	// WireGuard and IPsec. Its output exists only on a real owner TTY.
	master, slave := openMenuPTY(t)
	menuShowNewProtectedHandoff(slave, slave, opts, link.ID)
	shown := readMenuPTYUntil(t, master, "COPY RECEIVER SETUP LINK", "This same link stays in private storage")
	if !strings.Contains(shown, encoded) {
		t.Fatal("IPsec original PSK handoff was not copyable on the terminal")
	}
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("3")
	tty.expect("Type SHOW to confirm")
	if strings.Contains(tty.all, encoded) {
		t.Fatal("IPsec PSK offer disclosed without consent")
	}
	tty.send("SHOW")
	tty.expect("Keep this credential private.")
	if !strings.Contains(tty.all, encoded) {
		t.Fatal("IPsec original PSK offer not shown on consent")
	}
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("0")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if v, err := readPrivateHandoffFile(path); err != nil || v != encoded {
		t.Fatal("saved IPsec PSK offer lost")
	}
}

func TestMenuProtectedHandoffIPsecRejectsSameLinkDifferentPSK(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	opts := &runtimeOptions{stateRoot: root}
	link, _ := makeLifecycleDesired(t, "a", "10.70.11.0/31")
	link.Backend, link.Encapsulation = domain.BackendIPsec, domain.EncapESP
	link.GRE = domain.GREOptions{}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store, err := ipsecbackend.NewPSKStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutNew(link.ID, bytes.Repeat([]byte{'A'}, 32)); err != nil {
		t.Fatal(err)
	}
	// This forged private file is fully valid as a Setup Link and has
	// exactly the SAME sender ID and endpoints, but uses a different PSK.
	forged, err := pairing.NewQuickOffer(link, bytes.Repeat([]byte{'B'}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer forged.ClearRecipientCredential()
	text, err := forged.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	path, err := prepareProtectedMenuHandoff(opts, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSensitiveHandoff(path, []byte(text+"\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedSavedProtectedMenuOffer(opts, link); err == nil {
		t.Fatal("same-Link substituted IPsec PSK could be shown as authentic receiver handoff")
	}
	if err := secureDeleteProtectedMenuHandoff(opts, link); err == nil {
		t.Fatal("different IPsec PSK could be silently deleted as original")
	}
}

func TestMenuProtectedHandoffRejectsPreexistingFileAndSymlinkDirectory(t *testing.T) {
	t.Run("old file no clobber", func(t *testing.T) {
		opts, link, path, original := guidedSavedWireGuardFixture(t)
		if _, err := prepareProtectedMenuHandoff(opts, link.ID); err == nil {
			t.Fatal("existing per-Link handoff could be replaced by another Create")
		}
		after, err := readPrivateHandoffFile(path)
		if err != nil || after != original {
			t.Fatal("failed no-clobber attempt damaged original receiver credential")
		}
	})
	t.Run("symlinked private directory", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "state")
		opts := &runtimeOptions{stateRoot: root}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		foreign := filepath.Join(t.TempDir(), "foreign")
		if err := os.Mkdir(foreign, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(foreign, filepath.Join(root, protectedMenuHandoffDir)); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareProtectedMenuHandoff(opts, createTestID); err == nil {
			t.Fatal("guided creator accepted symlinked protected handoff directory")
		}
		entries, err := os.ReadDir(foreign)
		if err != nil || len(entries) != 0 {
			t.Fatal("symlink rejection wrote into foreign directory")
		}
	})
}

func TestMenuProtectedHandoffDeleteRequiresFreshRealTTY(t *testing.T) {
	opts, _, path, secret := guidedSavedWireGuardFixture(t)
	code, out, errs := scriptedManage(opts, "3\n1\n6\nDELETE\n0\n8\n")
	if code != 0 || !strings.Contains(errs, "real interactive terminal") ||
		strings.Contains(out+errs, secret) {
		t.Fatal("nonTTY scripted menu used DELETE to bypass protected file confirmation")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("nonTTY delete destroyed private handoff")
	}
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	if _, err := io.WriteString(tty.master, "6\nDELETE\n"); err != nil {
		t.Fatal(err)
	}
	tty.expect("Type DELETE to confirm")
	tty.send("")
	tty.expect("Cancelled. Nothing changed or disclosed.")
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("0")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if _, err := os.Stat(path); err != nil {
		t.Fatal("queued DELETE deleted protected file")
	}
}

// The accepted new UX reuses the fresh Create YES to display the exact saved
// receiver offer on a real TTY. Non-TTY/script/JSON paths still hide it.
func TestGuidedWireGuardRealTTYShowsOriginalProtectedSetupImmediatelyAfterCreate(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	root := filepath.Join(t.TempDir(), "state")
	fake := &wireGuardCreatorFake{newLifecycleFake()}
	opts := &runtimeOptions{
		stateRoot: root, backends: []backend.Backend{fake},
		probeRunner: &guidedTestRunner{}, mtuManager: guidedMTUFake{},
		createLinkID:   func() (domain.LinkID, error) { return createTestID, nil },
		packagePreview: readyGuidedPackagePreview,
	}
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("1")
	tty.expect("Tunnel type [1]: ")
	tty.send("2")
	tty.expect("Other server's IPv4 address (peer may be offline")
	tty.send("192.0.2.20")
	tty.expect("Tunnel IP on THIS server")
	tty.send("")
	tty.expect("UDP port on THIS server")
	tty.send("51871")
	tty.expect("UDP port on OTHER server")
	tty.send("51872")
	tty.expect("Change advanced keepalive")
	tty.send("n")
	tty.expect("Create the encrypted tunnel and private handoff file?")
	if strings.Contains(tty.all, "stl://") {
		t.Fatal("receiver credential disclosed before fresh Create YES")
	}
	tty.send("YES")
	tty.expect("COPY RECEIVER SETUP LINK")
	tty.expect("stl://")
	tty.expect("This same link stays in private storage")
	file, err := protectedMenuHandoffPath(opts, createTestID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := readPrivateHandoffFile(file)
	if err != nil || !strings.HasPrefix(original, "stl://") || !strings.Contains(tty.all, original) {
		t.Fatalf("PTY did not show exact retained original receiver offer: %v", err)
	}
	tty.expect("Press Enter to continue...")
	tty.send("")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	after, err := readPrivateHandoffFile(file)
	if err != nil || after != original {
		t.Fatalf("shown offer was changed or deleted: %v", err)
	}
}

// Remove is shared by CLI and the interactive menu. Retire only the exact
// original sender offer after the canonical Engine has committed removal.
func TestRemoveRetiresOnlyVerifiedMenuOwnedReceiverHandoff(t *testing.T) {
	opts, link, path, secret := guidedSavedWireGuardFixture(t)
	// A private CLI --output file explicitly chosen by the operator is not
	// the STL menu-managed handoff and must survive even a confirmed Remove.
	externalDir := filepath.Join(t.TempDir(), "external")
	if err := os.Mkdir(externalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	externalPath := filepath.Join(externalDir, "cli-output.stl")
	if err := writeSensitiveHandoff(externalPath, []byte(secret+"\n")); err != nil {
		t.Fatal(err)
	}
	otherID := domain.LinkID("lnk_dddddddddddddddddddddddddddddddd")
	otherPath, err := protectedMenuHandoffPath(opts, otherID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSensitiveHandoff(otherPath, []byte("unrelated-owner-only-file\n")); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := executeLinkMutation("link_remove", domain.Link{}, link.ID, true, &out, &errOut, opts)
	if code != 0 || errOut.Len() != 0 {
		t.Fatalf("confirmed Remove failed: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	var result lifecycleResultResponse
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.Removed || result.LinkID != link.ID {
		t.Fatalf("inaccurate Remove response: %+v %v", result, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful Engine Remove retained its exact saved receiver offer", err)
	}
	if contents, err := os.ReadFile(otherPath); err != nil || string(contents) != "unrelated-owner-only-file\n" {
		t.Fatal("removal touched another Link's unrelated protected file", err)
	}
	if retained, err := readPrivateHandoffFile(externalPath); err != nil || retained != secret {
		t.Fatal("automatic removal damaged an independently chosen CLI output file", err)
	}
	if strings.Contains(out.String()+errOut.String(), secret) {
		t.Fatal("Remove disclosed the original receiver secret")
	}
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(snapshot.Links) != 0 {
		t.Fatal("removed Link remains committed", err)
	}
}

func TestRemoveLeavesPrivateHandoffWhenLinkRemovalFailsOrCancelled(t *testing.T) {
	opts, link, path, secret := guidedSavedWireGuardFixture(t)
	fake := opts.backends[0].(*wireGuardCreatorFake)
	fake.failApply = true
	var out, errOut bytes.Buffer
	code := executeLinkMutation("link_remove", domain.Link{}, link.ID, true, &out, &errOut, opts)
	if code == 0 {
		t.Fatal("failed Engine removal claimed success")
	}
	if actual, err := readPrivateHandoffFile(path); err != nil || actual != secret {
		t.Fatal("uncommitted removal discarded receiver offer", err)
	}
	if strings.Contains(out.String()+errOut.String(), secret) {
		t.Fatal("failed Remove leaked receiver offer")
	}
	fake.failApply = false
	// A missing original offer, as on the recipient, must not prevent
	// deleting the locally owned Link or create new handoff directories.
	if err := secureDeleteProtectedMenuHandoff(opts, link); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	code = executeLinkMutation("link_remove", domain.Link{}, link.ID, true, &out, &errOut, opts)
	if code != 0 || errOut.Len() != 0 {
		t.Fatalf("missing receiver offer blocked local Remove: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestRemoveReportsCommittedCleanupIncompleteWithoutDeletingMismatchedFile(t *testing.T) {
	opts, link, path, secret := guidedSavedWireGuardFixture(t)
	// Another owner has substituted an unreadable/wrong-identity file at
	// exactly the expected name; native Link removal must remain possible.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	const unknown = "not-the-original-receiver-credential\n"
	if err := writeSensitiveHandoff(path, []byte(unknown)); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := executeLinkMutation("link_remove", domain.Link{}, link.ID, true, &out, &errOut, opts)
	if code == 0 {
		t.Fatal("cleanup failure falsely marked completed removal as fully clean")
	}
	var failure lifecycleFailureResponse
	if err := json.Unmarshal(out.Bytes(), &failure); err != nil {
		t.Fatal("invalid structured partial cleanup result", err)
	}
	if failure.Outcome != "removed_cleanup_incomplete" || failure.Error == nil ||
		failure.Error.ReasonCode != "protected_handoff_cleanup_incomplete" ||
		failure.PartialResult == nil || !failure.PartialResult.Removed || failure.PartialResult.LinkID != link.ID {
		t.Fatalf("missing committed-remove cleanup evidence: %+v", failure)
	}
	if strings.Contains(out.String()+errOut.String(), unknown) || strings.Contains(out.String()+errOut.String(), secret) {
		t.Fatal("incomplete cleanup disclosed a protected value")
	}
	if contents, err := os.ReadFile(path); err != nil || string(contents) != unknown {
		t.Fatal("unverified private file was deleted or modified", err)
	}
	if snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background()); err != nil || len(snapshot.Links) != 0 {
		t.Fatal("safe local Link Remove was blocked by unrelated private file", err)
	}
}

func TestMenuRemoveAutoRetiresVerifiedProtectedHandoff(t *testing.T) {
	opts, _, path, secret := guidedSavedWireGuardFixture(t)
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("5")
	tty.expect("To permanently REMOVE this tunnel")
	tty.send("REMOVE")
	tty.expect("removed via canonical Engine")
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("menu removed Link but left its original private receiver offer", err)
	}
	if strings.Contains(tty.all, secret) {
		t.Fatal("menu Remove disclosed private receiver credential")
	}
	if snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background()); err != nil || len(snapshot.Links) != 0 {
		t.Fatal("menu Remove did not remove exact Link State", err)
	}
}

func TestPostRemoveHandoffCleanupRefusesChangedGeneration(t *testing.T) {
	opts, link, path, _ := guidedSavedWireGuardFixture(t)
	prepared, err := prepareProtectedHandoffRemoval(opts, link.ID)
	if err != nil || prepared == nil {
		t.Fatal("cannot prepare exact original handoff for removal", err)
	}
	// A privileged independent writer replaces the original filename with a
	// different 0600 regular file between the initial validation and final
	// unlink; the cleanup must never delete this unverified generation.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := writeSensitiveHandoff(path, []byte("changed-private-generation\n")); err != nil {
		t.Fatal(err)
	}
	if err := state.NewFileStore(opts.stateRoot).Update(context.Background(), func(s *state.Snapshot) error {
		if !s.Delete(link.ID) {
			return errors.New("test fixture lost Link")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := prepared.retireAfterRemove(opts); err == nil {
		t.Fatal("different private file was accepted as the original generation")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "changed-private-generation\n" {
		t.Fatal("replaced private file changed during cleanup", err)
	}
}
