//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func manageFixture(t *testing.T, count int) (*runtimeOptions, *guidedTestBackend, []domain.Link) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}}
	var links []domain.Link
	for i := 0; i < count; i++ {
		subnet := "10.70.20.0/31"
		name := "a"
		if i > 0 {
			subnet, name = "10.70.21.0/31", "b"
		}
		link, raw := makeLifecycleDesired(t, name, subnet)
		var out, errs bytes.Buffer
		code := runWithRuntimeInput([]string{"link", "ensure", "--stdin"}, strings.NewReader(raw), &out, &errs, opts)
		if code != 0 || errs.Len() != 0 {
			t.Fatalf("fixture failed to ensure Link: code=%d error=%q", code, errs.String())
		}
		links = append(links, link)
	}
	return opts, fake, links
}

func scriptedManage(options *runtimeOptions, input string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader(input), &out, &errOut, options)
	return code, out.String(), errOut.String()
}

func TestMenuManageStatusDoesNotRemoveOrExposeDisplayName(t *testing.T) {
	opts, fake, links := manageFixture(t, 2)
	applyCount := len(fake.applies)
	code, output, errText := scriptedManage(opts, "3\n1\n1\n0\n8\n")
	if code != 0 || errText != "" || !strings.Contains(output, "interface verified") ||
		!strings.Contains(output, "SAVED TUNNELS / NOT A CONNECTION TEST") ||
		!strings.Contains(output, links[1].Addresses.Local.Addr().String()) ||
		strings.Contains(output, links[0].DisplayName) {
		t.Fatalf("Manage status did not safely use canonical live inspection: code=%d output=%q err=%q", code, output, errText)
	}
	if len(fake.applies) != applyCount || !fake.present[links[0].ID] || !fake.present[links[1].ID] {
		t.Fatal("read-only Manage changed one or more Links")
	}
}

func TestMenuManageNonterminalCannotRemoveEvenWithPrewrittenConfirmation(t *testing.T) {
	opts, fake, links := manageFixture(t, 1)
	count := len(fake.applies)
	code, output, errText := scriptedManage(opts, "3\n1\n5\nREMOVE\n8\n")
	if code != 0 || !strings.Contains(errText, "requires an interactive terminal") ||
		strings.Contains(output+errText, links[0].DisplayName) {
		t.Fatalf("scripted menu bypassed removal TTY boundary: code=%d out=%q err=%q", code, output, errText)
	}
	if len(fake.applies) != count || !fake.present[links[0].ID] {
		t.Fatal("scripted removal modified a Link")
	}
}

func TestMenuManageInvalidSelectionAndActionNeverMutate(t *testing.T) {
	opts, fake, links := manageFixture(t, 1)
	for _, tc := range []struct {
		name  string
		input string
		code  int
	}{
		{"invalid selection", "3\nPRIVATE-NOT-TO-ECHO\n0\n8\n", 0},
		{"unknown id", "3\nlnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n0\n8\n", 0},
		{"invalid action", "3\n1\nPRIVATE-NOT-TO-ECHO\n0\n8\n", 0},
		{"back", "3\n1\n0\n8\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(fake.applies)
			code, out, errOut := scriptedManage(opts, tc.input)
			if code != tc.code || strings.Contains(out+errOut, "PRIVATE-NOT-TO-ECHO") ||
				strings.Contains(out+errOut, links[0].DisplayName) {
				t.Fatalf("invalid selection leaked input or mutated: code=%d out=%q err=%q", code, out, errOut)
			}
			if len(fake.applies) != before || !fake.present[links[0].ID] {
				t.Fatal("invalid/cancelled Manage changed saved Link")
			}
		})
	}
}

type manageTTY struct {
	t       *testing.T
	master  *os.File
	chunks  <-chan string
	pending string
	all     string
}

func startManageTTY(t *testing.T, opts *runtimeOptions) (*manageTTY, <-chan int) {
	t.Helper()
	master, slave := openMenuPTY(t)
	done := make(chan int, 1)
	go func() { done <- runWithRuntimeInput([]string{"menu"}, slave, slave, slave, opts) }()
	chunks := make(chan string, 64)
	go func() {
		var data [2048]byte
		for {
			n, err := master.Read(data[:])
			if n > 0 {
				chunks <- string(data[:n])
			}
			if err != nil {
				close(chunks)
				return
			}
		}
	}()
	return &manageTTY{t: t, master: master, chunks: chunks}, done
}

// Even synthetic receiver credentials should not end up in CI failure logs.
func sanitizedMenuTestTranscript(value string) string {
	return regexp.MustCompile(`stl://[^[:space:]]+`).ReplaceAllString(value, "stl://[REDACTED]")
}

func (p *manageTTY) expect(marker string) {
	p.t.Helper()
	deadline := time.After(5 * time.Second)
	for !strings.Contains(p.pending, marker) {
		select {
		case chunk, ok := <-p.chunks:
			if !ok {
				p.t.Fatalf("PTY closed before %q; transcript=%q", marker, sanitizedMenuTestTranscript(p.all))
			}
			p.pending += chunk
			p.all += chunk
		case <-deadline:
			p.t.Fatalf("PTY did not display %q; transcript=%q", marker, sanitizedMenuTestTranscript(p.all))
		}
	}
	p.pending = p.pending[strings.Index(p.pending, marker)+len(marker):]
}

func (p *manageTTY) send(s string) {
	p.t.Helper()
	if _, err := io.WriteString(p.master, s+"\n"); err != nil {
		p.t.Fatal(err)
	}
}

func manageTTYDone(t *testing.T, done <-chan int, want int) {
	t.Helper()
	select {
	case code := <-done:
		if code != want {
			t.Fatalf("TTY menu returned %d; want %d", code, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PTY menu did not terminate")
	}
}

func TestMenuManagePTYRemoveOnlySelectedSamePeerLink(t *testing.T) {
	opts, fake, links := manageFixture(t, 2)
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("5")
	tty.expect("PREVIEW ONLY")
	tty.expect("To permanently REMOVE this tunnel")
	tty.send("REMOVE")
	tty.expect("removed via canonical Engine")
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 || snapshot.Links[0].Desired.ID != links[1].ID ||
		fake.present[links[0].ID] || !fake.present[links[1].ID] ||
		len(fake.operations) != 3 || fake.operations[2] != backend.OperationRemove ||
		strings.Contains(tty.all, links[0].DisplayName) {
		t.Fatalf("selected removal failed isolation or secret-safe output: state=%+v err=%v operations=%v", snapshot, err, fake.operations)
	}
}

func TestMenuManagePTYQueuedConfirmationCannotRemove(t *testing.T) {
	opts, fake, links := manageFixture(t, 1)
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	// Pre-paste an exact Link ID before the preview and confirmation prompt.
	if _, err := io.WriteString(tty.master, "5\nREMOVE\n"); err != nil {
		t.Fatal(err)
	}
	tty.expect("To permanently REMOVE this tunnel")
	tty.send("")
	tty.expect("Removal cancelled")
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if len(fake.applies) != 1 || !fake.present[links[0].ID] {
		t.Fatal("queued confirmation caused unapproved removal")
	}
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 {
		t.Fatal("prequeued input removed saved Link", err)
	}
}

func TestMenuManagePTYRemoveFailureDoesNotClaimSuccess(t *testing.T) {
	opts, fake, links := manageFixture(t, 1)
	fake.failApply = true
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("5")
	tty.expect("To permanently REMOVE this tunnel")
	tty.send("REMOVE")
	tty.expect("did not complete successfully")
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if strings.Contains(tty.all, "VERY_SECRET_NOT_FOR_OUTPUT") ||
		strings.Contains(tty.all, "removed via canonical Engine") || !fake.present[links[0].ID] {
		t.Fatalf("failed removal claimed success or leaked secret: %q", tty.all)
	}
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 {
		t.Fatal("failed removal erased saved Link", err)
	}
}

func TestMenuManageNoSelectionReturnsWithoutStateCreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	code, _, errOut := scriptedManage(&runtimeOptions{stateRoot: root}, "3\n\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("empty Manage unexpectedly failed: code=%d err=%q", code, errOut)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only Manage created state root: %v", err)
	}
}

func TestMenuManagePTYChangedDesiredStateRejectsStalePreview(t *testing.T) {
	opts, fake, links := manageFixture(t, 1)
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("5")
	tty.expect("To permanently REMOVE this tunnel")
	// Another writer changed the stable Link's desired configuration while
	// the operator considered the old preview. The stale choice is not valid.
	if err := state.NewFileStore(opts.stateRoot).Update(context.Background(), func(s *state.Snapshot) error {
		record, ok := s.Find(links[0].ID)
		if !ok {
			t.Fatal("missing fixture Link")
		}
		record.Desired.DisplayName = "NEW-PRIVATE-DESIRED-NAME"
		s.Upsert(record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	tty.send("REMOVE")
	tty.expect("Saved Link changed since preview")
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if len(fake.applies) != 1 || !fake.present[links[0].ID] ||
		strings.Contains(tty.all, "NEW-PRIVATE-DESIRED-NAME") {
		t.Fatalf("stale preview removed or leaked a reconfigured Link: %q", tty.all)
	}
}

func TestMenuManagePTYShowsCopyableConnectionDetailsAndReexportsSavedSetup(t *testing.T) {
	opts, fake, links := manageFixture(t, 1)
	applyCount := len(fake.applies)
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("4")
	tty.expect("TWO-SERVER CONNECTION DETAILS")
	tty.expect("Local endpoint")
	tty.expect("Remote tunnel IP")
	tty.expect("OTHER server menu: Create tunnel -> 4 Manual -> 1 GRE Native")
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("3")
	tty.expect("stl://")
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("0")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if len(fake.applies) != applyCount ||
		strings.Contains(tty.all, links[0].DisplayName) {
		t.Fatal("Manage Details/Share caused mutation or leaked untrusted display name")
	}
}
