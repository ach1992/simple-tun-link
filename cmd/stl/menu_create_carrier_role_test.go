package main

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"
	"testing"
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
		{"invalid-direction", "x\n", "", "", true},
		{"invalid-legacy-submenu", "m\n", "", "", true},
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
				if !strings.Contains(output.String(), "unverified suggestion") ||
					!strings.Contains(output.String(), "Direction [Enter=suggested; 1=listen; 2=dial]") ||
					!strings.Contains(output.String(), carrier+" / PUBLIC CONNECTION DIRECTION") {
					t.Fatalf("single-prompt suggestion / override not discoverable: %q", output.String())
				}
			})
		}
	}
}
