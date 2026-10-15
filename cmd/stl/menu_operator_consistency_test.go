package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/linux"
	"golang.org/x/sys/unix"
)

// A complete help page on a narrow PTY must convey shared causes and next
// checks without accidental wrapping, invisible status colors, or the
// previous prompt bleeding into the new screen.
func TestOperatorNarrowAvailabilityDetailsReadableAndGrouped(t *testing.T) {
	master, slave := openMenuPTY(t)
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("STL_NO_CLEAR", "1")
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Col: 52, Row: 28}); err != nil {
		t.Fatal(err)
	}
	report := linux.CapabilityReport{
		linux.CapabilityGRENative: {Available: true},
		linux.CapabilityGREFOU:    {ReasonCode: "fou_probe_unconfirmed", Reason: "FOU query failed, but permanent incompatibility has not been proven"},
		linux.CapabilityGREGUE:    {ReasonCode: "fou_probe_unconfirmed", Reason: "FOU query failed, but permanent incompatibility has not been proven"},
		linux.CapabilityIPIPFOU:   {ReasonCode: "fou_probe_unconfirmed", Reason: "FOU query failed, but permanent incompatibility has not been proven"},
		linux.CapabilityIPIPGUE:   {ReasonCode: "fou_probe_unconfirmed", Reason: "FOU query failed, but permanent incompatibility has not been proven"},
		linux.CapabilityIPsecXFRM: {ReasonCode: "swanctl_probe_unconfirmed", Reason: "strongSwan swanctl tool query did not succeed"},
	}
	done := make(chan struct{})
	go func() {
		menuCapabilityHelp(slave, report)
		close(done)
	}()
	seen := readMenuPTYUntil(t, master, "AVAILABILITY / EXPLANATION",
		"FOU/GUE x4", "ip fou show", "stl doctor ipsec --json",
		"NOT changed.")
	<-done
	if strings.Count(seen, "FOU query failed") != 1 ||
		strings.Contains(seen, "Choose a type:") ||
		strings.Contains(seen, "\x1b[") {
		t.Fatalf("availability page is repetitive or ANSI/previous-screen contaminated: %q", seen)
	}
	for _, line := range strings.Split(seen, "\r\n") {
		if len(line) > 52 {
			t.Fatalf("operator help exceeded narrow terminal columns: %q", line)
		}
	}
}

func TestOperatorProseWrapsOnlyExplanationsAndNeverCopyableData(t *testing.T) {
	master, slave := openMenuPTY(t)
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "xterm-256color")
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Col: 48, Row: 25}); err != nil {
		t.Fatal(err)
	}
	msg := "A long helpful explanation about unknown host prerequisites and safe next steps after this read-only attempt."
	menuProse(slave, msg)
	seen := readMenuPTYUntil(t, master, "safe next steps", "read-only attempt.")
	if !strings.Contains(seen, "\r\n  ") {
		t.Fatalf("narrow prose did not use deliberate indentation: %q", seen)
	}
	for _, line := range strings.Split(seen, "\r\n") {
		if len(line) > 48 {
			t.Fatalf("narrow prose exceeded terminal columns: %q", line)
		}
	}

	// Helpers must not mangle the bytes of an opaque copyable Setup Link.
	sensitive := "stl://" + strings.Repeat("ABC123def_", 21)
	var out bytes.Buffer
	menuProse(&out, sensitive)
	menuField(&out, "Setup", sensitive)
	if strings.Count(out.String(), sensitive) != 2 {
		t.Fatal("Setup Link was wrapped or changed")
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Fatal("redirected output gained ANSI control bytes")
	}
}

func TestOperatorReleaseHelpDoesNotStartInstallerOnRedirectedInput(t *testing.T) {
	// Root status on the test host, if any, must never be used as proof
	// that a redirected/scripted conversation can run a privileged update.
	if menuCanUpdateNow(strings.NewReader("UPDATE\n"), &bytes.Buffer{}) {
		t.Fatal("non-TTY update was considered privileged/confirmed")
	}
	var out, errOut bytes.Buffer
	if err := menuRunCanonicalUpdate(nil, menuOfficialRelease{TagName: "v0.1.0;touch /tmp/side-effect"}, &out, &errOut); err == nil {
		t.Fatal("unsafe tag accepted by canonical-updater delegate")
	}
}
