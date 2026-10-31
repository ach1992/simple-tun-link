package main

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

// WSS public TCP, QUIC public UDP, and kernel WireGuard UDP share one
// validated prompt. Rejecting a bad port must never mislabel WSS as UDP.
func TestGuidedPortValidationIsProtocolNeutralAndRetries(t *testing.T) {
	for _, tc := range []struct {
		name, prompt string
		fallback     uint16
	}{
		{"WSS TCP", "Public WSS/TLS TCP port [443]: ", 443},
		{"QUIC UDP", "Public QUIC/TLS UDP port [443]: ", 443},
		{"WG UDP", "Kernel WG UDP port on THIS server [51821]: ", 51821},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			p := createPrompts{reader: bufio.NewReader(strings.NewReader("0\n65536\ninvalid\n-1\n65535\n")), out: &out}
			port, err := askPortDefault(p, tc.prompt, tc.fallback)
			if err != nil || port != 65535 {
				t.Fatalf("last valid port not accepted: port=%d err=%v", port, err)
			}
			if got := strings.Count(out.String(), "Use a port number between 1 and 65535."); got != 4 {
				t.Fatalf("expected four actionable retries, got %d: %q", got, out.String())
			}
			if got := strings.Count(out.String(), tc.prompt); got != 5 {
				t.Fatalf("expected five attempts at original prompt, got %d: %q", got, out.String())
			}
			if strings.Contains(out.String(), "Use a UDP port number") {
				t.Fatalf("transport-specific port diagnostic resurfaced: %q", out.String())
			}

			out.Reset()
			defaultPort, err := askPortDefault(createPrompts{
				reader: bufio.NewReader(strings.NewReader("\n")), out: &out,
			}, tc.prompt, tc.fallback)
			if err != nil || defaultPort != tc.fallback || strings.Contains(out.String(), "Use a port number") {
				t.Fatalf("default changed: port=%d err=%v output=%q", defaultPort, err, out.String())
			}

			out.Reset()
			_, err = askPortDefault(createPrompts{
				reader: bufio.NewReader(strings.NewReader("q\n")), out: &out,
			}, tc.prompt, tc.fallback)
			if !errors.Is(err, errCreateCancelled) {
				t.Fatalf("cancel was not preserved: err=%v", err)
			}
		})
	}
}
