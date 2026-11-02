//go:build linux

package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"golang.org/x/sys/unix"
)

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
