//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openMenuPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		t.Skip("no disposable PTY device")
	}
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(mfd), "test-pty-master")
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	index, err := unix.IoctlGetInt(mfd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	sfd, err := unix.Open(fmt.Sprintf("/dev/pts/%d", index), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	slave := os.NewFile(uintptr(sfd), "test-pty-slave")
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func TestMenuTerminalSuppressedEchoAndRestored(t *testing.T) {
	master, slave := openMenuPTY(t)
	fd := int(slave.Fd())
	state, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	original := *state
	state.Lflag |= unix.ECHO | unix.ICANON
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, state); err != nil {
		t.Fatal(err)
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, &original)

	type result struct {
		url string
		err error
	}
	done := make(chan result, 1)
	go func() {
		url, err := readPrivateMenuURL(slave, bufio.NewReader(slave))
		done <- result{url, err}
	}()

	// Observe the terminal's real echo state; do not race input against the
	// moment the reader disables it. This tests the actual Linux PTY ioctl.
	deadline := time.Now().Add(2 * time.Second)
	for {
		current, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if current.Lflag&unix.ECHO == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("secret input did not disable terminal echo")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := io.WriteString(master, "private-setup-payload\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.url != "private-setup-payload" {
			t.Fatalf("private PTY reader: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("private PTY reader did not finish")
	}
	restored, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil || restored.Lflag&unix.ECHO == 0 {
		t.Fatalf("terminal echo was not restored: %v", err)
	}
	// Read only immediately available PTY output; a correct hidden input
	// should not have echoed any part of the test payload to its master.
	if err := unix.SetNonblock(int(master.Fd()), true); err != nil {
		t.Fatal(err)
	}
	var buf [128]byte
	n, readErr := unix.Read(int(master.Fd()), buf[:])
	if n > 0 || (readErr != nil && !errors.Is(readErr, unix.EAGAIN)) {
		t.Fatalf("private setup input was echoed: bytes=%d error=%v", n, readErr)
	}
}

func TestMenuConfirmationDiscardsQueuedTerminalInput(t *testing.T) {
	master, slave := openMenuPTY(t)
	if _, err := io.WriteString(master, "pretyped-answer\n"); err != nil {
		t.Fatal(err)
	}
	if err := clearQueuedMenuConfirmation(slave, bufio.NewReader(slave)); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(int(slave.Fd()), true); err != nil {
		t.Fatal(err)
	}
	var buf [32]byte
	n, err := unix.Read(int(slave.Fd()), buf[:])
	if n > 0 || !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("queued terminal answer was not discarded: n=%d err=%v", n, err)
	}
}

// The terminal, not just a strings.Reader fixture, must deliver exact
// bracketed paste bytes through hidden input without echo or credential loss.
func TestMenuRealPTYHiddenBracketedPasteIsNormalized(t *testing.T) {
	master, slave := openMenuPTY(t)
	fd := int(slave.Fd())
	before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	restored := *before
	restored.Lflag |= unix.ECHO | unix.ICANON
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &restored); err != nil {
		t.Fatal(err)
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, before)
	type outcome struct {
		value string
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		value, readErr := readPrivateMenuURL(slave, bufio.NewReader(slave))
		done <- outcome{value, readErr}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		now, e := unix.IoctlGetTermios(fd, unix.TCGETS)
		if e != nil {
			t.Fatal(e)
		}
		if now.Lflag&unix.ECHO == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal echo not disabled")
		}
		time.Sleep(time.Millisecond)
	}
	const token = "stl://2.synthetic-credential-only.synthetic-hash"
	if _, err := io.WriteString(master, "\x1b[200~Setup link: "+token+"\x1b[201~\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		value, valid := normalizeMenuSetupPaste(got.value)
		if got.err != nil || !valid || value != token {
			t.Fatal("PTY bracketed paste not normalized safely")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PTY protected input did not finish")
	}
	after, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil || after.Lflag&unix.ECHO == 0 {
		t.Fatal("terminal ECHO not restored")
	}
	if err := unix.SetNonblock(int(master.Fd()), true); err != nil {
		t.Fatal(err)
	}
	var received [512]byte
	n, e := unix.Read(int(master.Fd()), received[:])
	if n > 0 || (e != nil && !errors.Is(e, unix.EAGAIN)) {
		t.Fatal("protected Setup Link bytes were echoed")
	}
}
