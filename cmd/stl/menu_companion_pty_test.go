//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"golang.org/x/sys/unix"
)

// Exercise actual first-use prompts over a 38-column Linux PTY, never running
// an installed binary, downloader or real canonical installer.
func TestCompanionFirstUseNarrowPTYConsentAndLocalRecovery(t *testing.T) {
	for _, kind := range []menuCompanionKind{menuCompanionWSS, menuCompanionQUIC} {
		for _, scenario := range []string{"cancel", "online_failure_then_local"} {
			t.Run(string(kind)+"/"+scenario, func(t *testing.T) {
				t.Setenv("TERM", "xterm")
				t.Setenv("STL_NO_CLEAR", "0")
				t.Setenv("NO_COLOR", "1")
				master, slave := openMenuPTY(t)
				if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
					&unix.Winsize{Col: 38, Row: 24}); err != nil {
					t.Fatal(err)
				}
				spec, data, ready, ops, installs := testMenuCompanion(t)
				approved, ok := menuPinnedCompanion(kind, runtime.GOARCH)
				if !ok {
					t.Skip("unsupported companion architecture")
				}
				spec.label, spec.version, spec.asset = approved.label, approved.version, approved.asset
				spec.url, spec.action, spec.argument = approved.url, approved.action, approved.argument
				// Keep the synthetic digest/data from testMenuCompanion, so
				// the fake installer still verifies exactly the staged bytes.
				downloads, localCopies := 0, 0
				ops.download = func(context.Context, menuCompanionSpec, string) error {
					downloads++
					return menuCompanionNetworkError
				}
				copyLocal := ops.copyLocal
				ops.copyLocal = func(s menuCompanionSpec, from, to string) error {
					localCopies++
					return copyLocal(s, from, to)
				}
				ops.install = func(_ context.Context, _, _ io.Writer, args ...string) error {
					*installs++
					if len(args) != 3 || args[0] != spec.action ||
						args[1] != spec.argument || filepath.Base(args[2]) != spec.asset {
						return fmt.Errorf("unexpected fake canonical installer invocation")
					}
					got, err := os.ReadFile(args[2])
					if err != nil || !bytes.Equal(got, data) {
						return fmt.Errorf("fake canonical installer got unverified staged asset: %v", err)
					}
					*ready = true
					return nil
				}
				done := make(chan bool, 1)
				go func() {
					done <- menuEnsureCompanion(slave, bufio.NewReader(slave), slave, spec, ops)
				}()
				first := readMenuPTYUntil(t, master, "Companion setup [1]:")
				if !strings.Contains(first, "Install online") || !strings.Contains(first, "Install local") ||
					strings.Contains(first, "\x1b[") {
					t.Fatalf("missing readable narrow PTY setup/no-color: %q", first)
				}
				send := func(line string) {
					t.Helper()
					if _, err := io.WriteString(master, line+"\n"); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "cancel" {
					send("2")
					review := readMenuPTYUntil(t, master, "to install this companion")
					if !strings.Contains(review, "INSTALL") || !strings.Contains(review, "Local verified file") {
						t.Fatalf("missing local INSTALL review: %q", review)
					}
					send("")
					message := readMenuPTYUntil(t, master, "download or host changes")
					if strings.Contains(message, "installed and verified") {
						t.Fatalf("false completion after cancellation: %q", message)
					}
				} else {
					send("1")
					_ = readMenuPTYUntil(t, master, "to install this companion")
					send("INSTALL")
					recovery := readMenuPTYUntil(t, master, "Companion setup [1]:")
					if !strings.Contains(recovery, "official_download_unreachable") ||
						!strings.Contains(recovery, "Install local") {
						t.Fatalf("online failure did not offer readable local recovery: %q", recovery)
					}
					send("2")
					review := readMenuPTYUntil(t, master, "to install this companion")
					if !strings.Contains(review, "Local verified file") {
						t.Fatalf("missing local verification review: %q", review)
					}
					send("INSTALL")
					_ = readMenuPTYUntil(t, master, "Create wizard.")
				}
				select {
				case got := <-done:
					expected := scenario == "online_failure_then_local"
					if got != expected || *ready != expected {
						t.Fatalf("unexpected setup completion: got=%v ready=%v", got, *ready)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("true PTY setup did not complete")
				}
				if scenario == "cancel" && (downloads != 0 || localCopies != 0 || *installs != 0) {
					t.Fatalf("cancellation performed host effects: downloads=%d local=%d installs=%d", downloads, localCopies, *installs)
				}
				if scenario != "cancel" && (downloads != 1 || localCopies != 1 || *installs != 1) {
					t.Fatalf("offline recovery did not use exactly one method/consent per attempt: downloads=%d local=%d installs=%d", downloads, localCopies, *installs)
				}
			})
		}
	}
}

// Both Create screens must replace, not append beneath, the tunnel selector.
// Test the real ANSI clear and the NO_COLOR contract through a true PTY.
func TestWSSAndQUICCreateScreensUseSameClearContract(t *testing.T) {
	for _, disableColor := range []bool{false, true} {
		for _, method := range []string{"WSS", "QUIC"} {
			t.Run(method+"-NoColor-"+map[bool]string{true: "yes", false: "no"}[disableColor], func(t *testing.T) {
				t.Setenv("TERM", "xterm")
				t.Setenv("STL_NO_CLEAR", "0")
				_, wasPresent := os.LookupEnv("NO_COLOR")
				old := os.Getenv("NO_COLOR")
				if disableColor {
					t.Setenv("NO_COLOR", "1")
				} else {
					if err := os.Unsetenv("NO_COLOR"); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if wasPresent {
							_ = os.Setenv("NO_COLOR", old)
						} else {
							_ = os.Unsetenv("NO_COLOR")
						}
					})
				}
				master, slave := openMenuPTY(t)
				if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: 38, Row: 24}); err != nil {
					t.Fatal(err)
				}
				done := make(chan int, 1)
				r := bufio.NewReader(slave)
				opts := &runtimeOptions{stateRoot: filepath.Join(t.TempDir(), "absent")}
				if method == "WSS" {
					h := wss.Host{Binary: filepath.Join(t.TempDir(), "missing"), SHA256: strings.Repeat("0", 64)}
					go func() { done <- menuCreateWSSWithHost(slave, r, slave, slave, opts, h) }()
				} else {
					go func() {
						done <- menuCreateQUICWithExecutable(slave, r, slave, slave, opts, filepath.Join(t.TempDir(), "missing"))
					}()
				}
				seen := readMenuPTYUntil(t, master, "Next")
				if !strings.Contains(seen, "WIREGUARD OVER "+method) {
					t.Fatalf("missing full-screen method header: %q", seen)
				}
				hasClear := strings.Contains(seen, "\x1b[2J\x1b[H")
				if hasClear == disableColor || disableColor && strings.Contains(seen, "\x1b") {
					t.Fatalf("clear/NO_COLOR mismatch: noColor=%v content=%q", disableColor, seen)
				}
				select {
				case code := <-done:
					if code != 4 {
						t.Fatalf("unexpected unavailable helper status: %d", code)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("screen flow did not complete")
				}
				_, _ = io.WriteString(master, "")
			})
		}
	}
}
