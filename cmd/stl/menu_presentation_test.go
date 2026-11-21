package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
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

func TestSemanticStatusPaletteUsedByNoticesAndHealth(t *testing.T) {
	master, slave := openMenuPTY(t)
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("CLICOLOR", "1")
	old, had := os.LookupEnv("NO_COLOR")
	_ = os.Unsetenv("NO_COLOR")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("NO_COLOR", old)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	})
	for _, item := range []struct{ kind, color string }{
		{"OK", menuGreen}, {"INFO", menuBlue}, {"WARNING", menuYellow},
		{"FAILED", menuRed}, {"UNKNOWN", menuDim}, {"UNAVAILABLE", menuCyan},
	} {
		if role := menuStatusRole(item.kind); role != item.color {
			t.Fatalf("status %s: %q, want %q", item.kind, role, item.color)
		}
	}
	var plain bytes.Buffer
	menuHealthLine(&plain, "Probe", "UNKNOWN", "Not observed")
	menuNotice(&plain, "UNAVAILABLE", "Not installed")
	if strings.Contains(plain.String(), "\x1b[") ||
		!strings.Contains(plain.String(), "[UNKNOWN]") ||
		!strings.Contains(plain.String(), "[UNAVAILABLE]") {
		t.Fatalf("plain-text status lost its explicit labels: %q", plain.String())
	}
	menuHealthLine(slave, "Probe", "UNKNOWN", "Not observed")
	menuNotice(slave, "UNAVAILABLE", "Not installed")
	got := readMenuPTYUntil(t, master, "[UNKNOWN]", "[UNAVAILABLE]")
	if !strings.Contains(got, "\x1b["+menuDim+"m") ||
		!strings.Contains(got, "\x1b["+menuCyan+"m") {
		t.Fatalf("health/notice did not share semantic status palette: %q", got)
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
	master, slave := openMenuPTY(t)
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("STL_NO_CLEAR", "0")
	// NO_COLOR suppresses styling, not the terminal's ability to replace
	// the previous menu frame with a clean full-screen redraw.
	t.Setenv("NO_COLOR", "")
	if menuColorEnabled(slave) || !menuEscapeCapable(slave) {
		t.Fatal("NO_COLOR suppressed terminal redraw or allowed semantic color")
	}
	menuScreen(slave, "Monochrome")
	if seen := readMenuPTYUntil(t, master, "MONOCHROME"); !strings.Contains(seen, "\x1b[2J\x1b[H") || strings.Contains(seen, "\x1b[1;") {
		t.Fatalf("NO_COLOR did not redraw a monochrome menu: %q", seen)
	}
	if got := menuPaint(slave, menuRed, "FAILED"); got != "FAILED" {
		t.Fatalf("NO_COLOR produced styling: %q", got)
	}
	t.Setenv("TERM", "dumb")
	if menuEscapeCapable(slave) || menuColorEnabled(slave) {
		t.Fatal("TERM=dumb must forbid screen control and color")
	}
	t.Setenv("TERM", "")
	if !menuEscapeCapable(slave) || menuColorEnabled(slave) {
		t.Fatal("unset TERM on a real TTY must redraw without NO_COLOR styling")
	}
	menuScreen(slave, "Unset TERM")
	if seen := readMenuPTYUntil(t, master, "UNSET TERM"); !strings.Contains(seen, "\x1b[2J\x1b[H") {
		t.Fatalf("unset TERM did not redraw a physical TTY: %q", seen)
	}
	// Prove unknown TERM is monochrome even when NO_COLOR is completely
	// absent, rather than letting NO_COLOR mask an accidental SGR fallback.
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	if !menuEscapeCapable(slave) || menuColorEnabled(slave) {
		t.Fatal("unknown TERM must permit redraw but not enable color")
	}
	menuScreen(slave, "Unknown TERM, color unset")
	if seen := readMenuPTYUntil(t, master, "UNKNOWN TERM, COLOR UNSET"); !strings.Contains(seen, "\x1b[2J\x1b[H") || strings.Count(seen, "\x1b[") != 2 {
		t.Fatalf("unknown TERM emitted non-redraw ANSI or failed to clear: %q", seen)
	}
	// The explicit append-only preference must override a known color-
	// capable interactive terminal without disabling readable menu text.
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("STL_NO_CLEAR", "1")
	menuScreen(slave, "Append only")
	if seen := readMenuPTYUntil(t, master, "APPEND ONLY"); strings.Contains(seen, "\x1b[2J\x1b[H") {
		t.Fatalf("STL_NO_CLEAR=1 did not suppress screen redraw: %q", seen)
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

func TestMenuDescriptionWrapAndCopyableURLPreservation(t *testing.T) {
	master, slave := openMenuPTY(t)
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Row: 24, Col: 60}); err != nil {
		t.Fatal(err)
	}
	long := "Remove only the selected local tunnel resources and keep all other saved tunnels unchanged"
	menuActionOption(slave, "5", "Remove this tunnel", long, "REMOVE")
	original := "https://example.invalid/a/very/long/path/to/an/exact/recovery/guide"
	menuOption(slave, "u", "Help URL", original)
	got := readMenuPTYUntil(t, master, "Remove this tunnel", "resources and", original)
	if !strings.Contains(got, "resources and\r\n      ") {
		t.Fatalf("long prose did not wrap on a narrow screen: %q", got)
	}
	if !strings.Contains(got, original) {
		t.Fatalf("exact copyable URL was changed or interrupted: %q", got)
	}
}

func TestMenuSemanticOptionsAtSixtyEightyAndWideColumns(t *testing.T) {
	for _, width := range []uint16{60, 80, 120} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			master, slave := openMenuPTY(t)
			if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
				&unix.Winsize{Row: 24, Col: width}); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TERM", "xterm-256color")
			t.Setenv("CLICOLOR", "1")
			old, present := os.LookupEnv("NO_COLOR")
			_ = os.Unsetenv("NO_COLOR")
			t.Cleanup(func() {
				if present {
					_ = os.Setenv("NO_COLOR", old)
				} else {
					_ = os.Unsetenv("NO_COLOR")
				}
			})
			menuActionOption(slave, "5", "Remove this tunnel", "Scoped owned Link only", "REMOVE")
			menuOption(slave, "6", "Update information", "Read only")
			menuSection(slave, "Review")
			out := readMenuPTYUntil(t, master, "Remove this tunnel", "Scoped owned Link only",
				"Update information", strings.Repeat("-", menuRuleWidth(slave)))
			if !strings.Contains(out, "\x1b["+menuRed+"m") {
				t.Fatal("explicit REMOVE intent lacked red/bold TTY rendering")
			}
			if width == 60 && !strings.Contains(out, "\r\n      \x1b[2mScoped owned Link only") {
				t.Fatalf("60-column description not placed below action: %q", out)
			}
			if width >= 80 && strings.Contains(out, "\r\n      \x1b[2mScoped owned Link only") {
				t.Fatalf("%d-column action needlessly stacked: %q", width, out)
			}
			if strings.Contains(out, "\x1b["+menuYellow+"mUpdate information") {
				t.Fatal("descriptive UPDATE wording was incorrectly treated as an action")
			}
		})
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

// The observed 24-column regression comes from human labels, not exact
// copyable Link IDs. Exercise actual PTY winsize with semantic ANSI enabled
// and disabled; no ordinary heading/option/status may overrun its columns.
var terminalColorSequence = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

func TestTwentyFourColumnTerminalReflowsHumanMenuText(t *testing.T) {
	for _, monochrome := range []bool{false, true} {
		t.Run(fmt.Sprintf("no_color=%t", monochrome), func(t *testing.T) {
			master, slave := openMenuPTY(t)
			if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
				&unix.Winsize{Row: 35, Col: 24}); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TERM", "xterm-256color")
			t.Setenv("CLICOLOR", "1")
			previous, had := os.LookupEnv("NO_COLOR")
			_ = os.Unsetenv("NO_COLOR")
			t.Cleanup(func() {
				if had {
					_ = os.Setenv("NO_COLOR", previous)
				} else {
					_ = os.Unsetenv("NO_COLOR")
				}
			})
			if monochrome {
				t.Setenv("NO_COLOR", "1")
			}
			menuSection(slave, "Saved tunnels / not a connection test")
			menuActionOption(slave, "7", "Uninstall", "Verify and remove installed STL", "UNINSTALL")
			menuTunnelOption(slave, "7", "WireGuard / QUIC + TLS",
				"Encrypted UDP Carrier (optional pinned Hysteria)", nil, tunnelOption{})
			menuField(slave, "Saved tunnels", "0 (not a connection test)")
			menuNotice(slave, "WARNING", "Uninstall removes only selected STL-owned executable, alias and record.")
			fmt.Fprintln(slave, "END-24")
			got := readMenuPTYUntil(t, master, "END-24")
			raw := got
			plain := strings.ReplaceAll(terminalColorSequence.ReplaceAllString(raw, ""), "\r", "")
			for _, line := range strings.Split(plain, "\n") {
				if len(line) > 24 {
					t.Fatalf("24-column human text exceeded PTY width: len=%d line=%q\nraw=%q", len(line), line, raw)
				}
			}
			if !strings.Contains(plain, "Uninstall") || !strings.Contains(plain, "[WARNING]") {
				t.Fatalf("plain status or action meaning missing: %q", plain)
			}
			hasSGR := strings.Contains(raw, "\x1b["+menuYellow+"m")
			if hasSGR == monochrome {
				t.Fatalf("semantic color choice ignored NO_COLOR=%t: %q", monochrome, raw)
			}
		})
	}
}

func TestTwentyFourColumnRealMenuManageNavigation(t *testing.T) {
	for _, noColor := range []bool{false, true} {
		t.Run(fmt.Sprintf("no_color=%t", noColor), func(t *testing.T) {
			t.Setenv("TERM", "xterm-256color")
			t.Setenv("CLICOLOR", "1")
			old, present := os.LookupEnv("NO_COLOR")
			_ = os.Unsetenv("NO_COLOR")
			t.Cleanup(func() {
				if present {
					_ = os.Setenv("NO_COLOR", old)
				} else {
					_ = os.Unsetenv("NO_COLOR")
				}
			})
			if noColor {
				t.Setenv("NO_COLOR", "1")
			}
			opts, backend, links := manageFixture(t, 1)
			tty, done := startManageTTY(t, opts, 24)
			tty.expect("Choose a task: ")
			tty.send("3")
			tty.expect("Choose tunnel number: ")
			tty.send("1")
			tty.expect("Choose an action: ")
			tty.send("0")
			tty.expect("Choose a task: ")
			tty.send("8")
			manageTTYDone(t, done, 0)
			raw := tty.all
			plain := strings.ReplaceAll(terminalColorSequence.ReplaceAllString(raw, ""), "\r", "")
			var wide []string
			for _, line := range strings.Split(plain, "\n") {
				// An exact ID or copyable address is allowed to remain
				// unsplit; user-facing explanatory prose is not.
				if len(line) > 24 &&
					!strings.Contains(line, "lnk_") &&
					!strings.Contains(line, links[0].Addresses.Local.Addr().String()) &&
					!strings.Contains(line, links[0].Addresses.Peer.Addr().String()) {
					wide = append(wide, line)
				}
			}
			if len(wide) != 0 {
				t.Fatalf("real 24-column Manage prose overflows (%d rows), examples=%q", len(wide), wide[:min(len(wide), 5)])
			}
			if !backend.present[links[0].ID] {
				t.Fatal("read-only Manage traversal modified saved Link")
			}
		})
	}
}
