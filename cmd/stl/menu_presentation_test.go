package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMenuPresentationPlaintextAndSemanticColumns(t *testing.T) {
	var out bytes.Buffer
	menuScreen(&out, "Main")
	menuField(&out, "Local tunnel IP", "10.235.1.1/30")
	menuOption(&out, "1", "GRE", "Not encrypted")
	menuOption(&out, "2", "WireGuard", "Encrypted")
	menuNotice(&out, "FAILED", "The selected operation was not confirmed.")
	menuNotice(&out, "OK", "Operation confirmed.")
	text := out.String()
	if strings.Contains(text, "\x1b[") || !strings.Contains(text, "[FAILED]") ||
		!strings.Contains(text, "[OK]") || !strings.Contains(text, "10.235.1.1/30") ||
		!strings.Contains(text, "Not encrypted") {
		t.Fatalf("human content became unparseable or contained ANSI in redirected output: %q", text)
	}
	lines := strings.Split(text, "\n")
	var positions []int
	for _, line := range lines {
		if strings.Contains(line, "Not encrypted") {
			positions = append(positions, strings.Index(line, "Not encrypted"))
		}
		if strings.Contains(line, "Encrypted") {
			positions = append(positions, strings.Index(line, "Encrypted"))
		}
	}
	if len(positions) != 2 || positions[0] != positions[1] {
		t.Fatalf("menu descriptions do not align in a common column: %v", positions)
	}
}

func TestMenuActionSemanticsAndExactCopyableTokens(t *testing.T) {
	_, slave := openMenuPTY(t)
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("CLICOLOR", "1")
	old, present := os.LookupEnv("NO_COLOR")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv("NO_COLOR", old)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	})
	for _, test := range []struct {
		word, code string
	}{
		{"REMOVE", menuRed}, {"DELETE", menuRed},
		{"PREPARE", menuYellow}, {"UPDATE", menuYellow},
		{"YES", menuGreen}, {"SHOW", menuBlue},
	} {
		got := menuActionPrompt(slave, test.word, "Type "+test.word+" to confirm: ")
		want := "\x1b[" + test.code + "m" + test.word + "\x1b[0m"
		if !strings.Contains(got, want) {
			t.Fatalf("semantic action %s missing exact color/bold token: %q", test.word, got)
		}
	}
	for _, test := range []struct {
		action, role string
	}{
		{"REMOVE", menuRed}, {"DELETE", menuRed},
		{"UNINSTALL", menuRed}, {"INSTALL", menuYellow},
		{"UPDATE", menuYellow}, {"SHOW", menuBlue},
	} {
		if got := menuActionRole(test.action); got != test.role {
			t.Fatalf("%s: want %s, got %s", test.action, test.role, got)
		}
	}
	// Display wording never grants the styling or intent of an action.
	// A descriptive option that happens to mention "Delete" is still neutral.
	if got := menuActionRole("NOT_AN_ACTION"); got != menuCyan {
		t.Fatalf("unknown action was promoted to a privileged semantic: %q", got)
	}
	if got := menuActionPrompt(slave, "PREPARE", "Why an update can delete stale links"); strings.Contains(got, "\x1b["+menuRed+"m") {
		t.Fatalf("descriptive text inferred a destructive action: %q", got)
	}
	for _, literal := range []string{
		"stl://receiver-sensitive-sequence", "sudo stl link show --json",
		"https://example.invalid/query?a=1",
	} {
		if got := menuFieldValue(slave, "Copy", literal); got != literal {
			t.Fatalf("copyable token was decorated or changed: %q", got)
		}
	}
	if got := menuFieldValue(slave, "Status", "Verified"); !strings.Contains(got, "\x1b["+menuGreen+"m") {
		t.Fatalf("verified status did not use the success palette: %q", got)
	}
	if got := menuFieldValue(slave, "Status", "Unavailable"); !strings.Contains(got, "\x1b["+menuCyan+"m") {
		t.Fatalf("unavailable state did not use the distinct unavailable palette: %q", got)
	}
	if got := menuFieldValue(slave, "Status", "Unknown"); !strings.Contains(got, "\x1b["+menuDim+"m") {
		t.Fatalf("unknown state did not use the distinct unknown palette: %q", got)
	}
	t.Setenv("NO_COLOR", "")
	if got := menuActionPrompt(slave, "DELETE", "Type DELETE or YES: "); got != "Type DELETE or YES: " {
		t.Fatalf("NO_COLOR decorated action tokens: %q", got)
	}
	if got := menuFieldValue(slave, "Status", "Unavailable"); got != "Unavailable" {
		t.Fatalf("NO_COLOR decorated status: %q", got)
	}
}

func TestMenuPresentationTermAndColorGates(t *testing.T) {
	_, slave := openMenuPTY(t)
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("STL_NO_CLEAR", "0")
	// Presence of NO_COLOR, even empty, must disable semantic color but
	// not remove clear/formatting from an otherwise capable terminal.
	t.Setenv("NO_COLOR", "")
	if menuColorEnabled(slave) || !menuEscapeCapable(slave) {
		t.Fatal("NO_COLOR disabled terminal capability or failed to disable colors")
	}
	if got := menuPaint(slave, menuRed, "FAILED"); got != "FAILED" {
		t.Fatalf("NO_COLOR produced ANSI: %q", got)
	}
	t.Setenv("TERM", "dumb")
	if menuEscapeCapable(slave) || menuColorEnabled(slave) {
		t.Fatal("TERM=dumb must forbid screen control and color")
	}
}

func TestMenuInteractiveClearsBeforeAndAfterResultAcknowledgement(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("CLICOLOR", "1")
	t.Setenv("STL_NO_CLEAR", "0")
	// t.Setenv cannot unset a variable; save/restore env state without
	// leaking global modifications to later tests.
	old, present := os.LookupEnv("NO_COLOR")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv("NO_COLOR", old)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	})
	opts := &runtimeOptions{stateRoot: t.TempDir()}
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("4")
	tty.expect("No saved tunnels")
	tty.expect("Press Enter to continue...")
	// Returning to main must wait for a fresh human action.
	if strings.Count(tty.all, "\x1b[2J\x1b[H") < 2 {
		t.Fatalf("terminal was not cleared on the action transition: %q", tty.all)
	}
	tty.send("")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if strings.Count(tty.all, "\x1b[2J\x1b[H") < 3 ||
		!strings.Contains(tty.all, "\x1b[1;34m") {
		t.Fatalf("no clean redraw / semantic color in real TTY: %q", tty.all)
	}
}

func TestNarrowTerminalKeepsMenuChoicesReadable(t *testing.T) {
	master, slave := openMenuPTY(t)
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Row: 24, Col: 48}); err != nil {
		t.Fatal(err)
	}
	menuOption(slave, "2", "WireGuard / UDP", "Encrypted; needs a peer")
	menuSection(slave, "Preview")
	got := readMenuPTYUntil(t, master, "WireGuard / UDP", "Encrypted; needs a peer", strings.Repeat("-", 44))
	if !strings.Contains(got, "WireGuard / UDP") ||
		!strings.Contains(got, "\r\n      Encrypted; needs a peer") ||
		!strings.Contains(got, strings.Repeat("-", 44)) ||
		strings.Contains(got, strings.Repeat("-", 55)) {
		t.Fatalf("narrow terminal did not wrap the option in readable rows: %q", got)
	}
}

// A PTY may split one synchronous write into several master-side reads,
// especially on GitHub-hosted runners. Wait for the complete bounded
// transcript instead of mistaking a partial frame for a failed renderer.
func readMenuPTYUntil(t *testing.T, master *os.File, required ...string) string {
	t.Helper()
	if err := unix.SetNonblock(int(master.Fd()), true); err != nil {
		t.Fatal(err)
	}
	var transcript strings.Builder
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var chunk [1024]byte
		n, err := unix.Read(int(master.Fd()), chunk[:])
		if n > 0 {
			transcript.Write(chunk[:n])
		}
		complete := true
		for _, marker := range required {
			if !strings.Contains(transcript.String(), marker) {
				complete = false
				break
			}
		}
		if complete {
			return transcript.String()
		}
		if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			t.Fatalf("PTY failed before complete output: %v, got %q", err, transcript.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("PTY did not produce %v: %q", required, transcript.String())
	return ""
}
