package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCarrierRoleSuggestionIsEndpointSymmetric(t *testing.T) {
	cases := []struct {
		name, a, b string
		role       string
	}{
		{"both-public", "198.51.100.5", "203.0.113.8", "listen"},
		{"actual-field-address-order", "193.111.235.101", "91.107.246.220", "dial"},
		{"both-private", "10.0.1.80", "10.0.1.5", "dial"},
		{"public-local", "198.51.100.5", "10.0.1.80", "listen"},
		{"public-peer", "10.0.1.80", "198.51.100.5", "dial"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			a, b := netip.MustParseAddr(tt.a), netip.MustParseAddr(tt.b)
			role, reason := recommendCarrierRole(a, b)
			other, reverseReason := recommendCarrierRole(b, a)
			if role != tt.role || reason == "" || reverseReason == "" || role == other {
				t.Fatalf("%s->%s: role=%q, reverse=%q, reason=%q / %q", a, b, role, other, reason, reverseReason)
			}
		})
	}
}

func TestCarrierRoleGuidedSuggestionAndSamePromptOverride(t *testing.T) {
	const local, peer = "10.0.1.80", "198.51.100.5"
	tests := []struct {
		name, input, wantRole, wantSource string
		wantError                         bool
	}{
		{"default-no-choice", "\n", "dial", "suggested (unverified)", false},
		{"manual-listen", "1\n", "listen", "manual override", false},
		{"manual-dial", "2\n", "dial", "manual override", false},
		{"invalid-then-listen", "x\n1\n", "listen", "manual override", false},
		{"invalid-legacy-then-default", "m\n\n", "dial", "suggested (unverified)", false},
		{"operator-cancel", "q\n", "", "", true},
	}
	for _, carrier := range []string{"WSS", "QUIC"} {
		for _, tt := range tests {
			t.Run(carrier+"/"+tt.name, func(t *testing.T) {
				reader := strings.NewReader(tt.input)
				var output bytes.Buffer
				role, origin, err := askCarrierRole(createPrompts{reader: bufio.NewReader(reader), out: &output}, carrier,
					netip.MustParseAddr(local), netip.MustParseAddr(peer))
				if (err != nil) != tt.wantError || role != tt.wantRole || origin != tt.wantSource {
					t.Fatalf("got role=%q origin=%q err=%v; output=%q", role, origin, err, output.String())
				}
				if !strings.Contains(output.String(), "Unverified default: no WAN test") ||
					!strings.Contains(output.String(), "Unverified default: no WAN test") ||
					!strings.Contains(output.String(), "Direction [Enter=suggested; 1=listen; 2=dial]") ||
					!strings.Contains(output.String(), carrier+" / PUBLIC CONNECTION DIRECTION") {
					t.Fatalf("single-prompt suggestion / override not discoverable: %q", output.String())
				}
			})
		}
	}
}

// Real PTY input tests the exact rendered single-step interaction, including
// repeat prompt after invalid input and readable narrow/wide terminal output.
func TestCarrierRoleRealPTYDefaultOverrideAndRetry(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, carrier := range []string{"WSS", "QUIC"} {
		for _, columns := range []uint16{38, 100} {
			for _, tc := range []struct {
				name, input, role, source string
				invalidFirst              bool
			}{
				{"enter-default", "\n", "dial", "suggested (unverified)", false},
				{"manual-listen", "1\n", "listen", "manual override", false},
				{"manual-dial", "2\n", "dial", "manual override", false},
				{"invalid-retry", "1\n", "listen", "manual override", true},
			} {
				t.Run(carrier+"/"+tc.name+"/"+fmt.Sprint(columns), func(t *testing.T) {
					master, slave := openMenuPTY(t)
					if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
						&unix.Winsize{Row: 24, Col: columns}); err != nil {
						t.Fatal(err)
					}
					type result struct {
						role, source string
						err          error
					}
					done := make(chan result, 1)
					go func() {
						role, source, err := askCarrierRole(createPrompts{reader: bufio.NewReader(slave), out: slave}, carrier,
							netip.MustParseAddr("193.111.235.101"), netip.MustParseAddr("91.107.246.220"))
						done <- result{role, source, err}
					}()
					printed := readMenuPTYUntil(t, master, "Direction [Enter=suggested; 1=listen; 2=dial]: ")
					if !strings.Contains(printed, "Unverified default: no WAN test") ||
						!strings.Contains(printed, "server as Listen.") ||
						strings.Contains(printed, "\x1b") {
						t.Fatalf("bad actual %d-column prompt: %q", columns, printed)
					}
					if tc.invalidFirst {
						if _, err := io.WriteString(master, "x\n"); err != nil {
							t.Fatal(err)
						}
						feedback := readMenuPTYUntil(t, master, "Choose Enter, 1", "Direction [Enter=suggested; 1=listen; 2=dial]: ")
						if strings.Contains(feedback, "\x1b") {
							t.Fatal("NO_COLOR retry included ANSI")
						}
					}
					if _, err := io.WriteString(master, tc.input); err != nil {
						t.Fatal(err)
					}
					select {
					case got := <-done:
						if got.err != nil || got.role != tc.role || got.source != tc.source {
							t.Fatalf("role=%q source=%q err=%v", got.role, got.source, got.err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("PTY role prompt did not return")
					}
				})
			}
		}
	}
}

func TestCarrierRoleReviewIdentifiesActualPublicListener(t *testing.T) {
	a, b := netip.MustParseAddr("193.111.235.101"), netip.MustParseAddr("91.107.246.220")
	for _, tc := range []struct {
		role, protocol, wantListener, wantPeer string
	}{
		{"listen", "TCP", "193.111.235.101:443/TCP", "91.107.246.220 (dial)"},
		{"dial", "UDP", "91.107.246.220:443/UDP", "91.107.246.220 (listen)"},
	} {
		var output bytes.Buffer
		showCarrierDirectionReview(&output, a, b, tc.role, "manual override", tc.protocol, 443)
		for _, want := range []string{a.String() + " (" + tc.role + ")", tc.wantPeer, tc.wantListener,
			"Public reachability is unverified", "No automatic role switch."} {
			if !strings.Contains(output.String(), want) {
				t.Fatalf("role %s missing %q: %q", tc.role, want, output.String())
			}
		}
	}
}
