package main

import (
	"bufio"
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/composition"
)

// WSS public TCP, QUIC public UDP, and kernel WireGuard UDP share one
// validated prompt. Rejecting a bad port must never mislabel WSS as UDP.
// The actual WSS and QUIC admission predicates govern guided SAN input.
func TestTLSCertificateSANCarrierAdmissionAndSameFieldRetry(t *testing.T) {
	listener := netip.MustParseAddr("192.0.2.20")
	for _, carrier := range []composition.Kind{composition.WSS, composition.QUIC} {
		t.Run(string(carrier), func(t *testing.T) {
			var out bytes.Buffer
			p := createPrompts{reader: bufio.NewReader(strings.NewReader(
				"bad@name\nbad:name\nBAD.EXAMPLE\n192.0.2.33\nvalid.example\n")), out: &out}
			name, err := askTLSCertificateSAN(p, carrier, listener)
			if err != nil || name != "valid.example" ||
				strings.Count(out.String(), "TLS certificate SAN") != 5 ||
				!strings.Contains(out.String(), "IP SAN must match") {
				t.Fatalf("invalid SAN survived retry or valid DNS rejected: %q %v %q", name, err, out.String())
			}
			out.Reset()
			name, err = askTLSCertificateSAN(createPrompts{
				reader: bufio.NewReader(strings.NewReader("\n")), out: &out}, carrier, listener)
			if err != nil || name != "" || strings.Contains(out.String(), "Try again") {
				t.Fatalf("default listener IP changed: %q %v %q", name, err, out.String())
			}
			out.Reset()
			name, err = askTLSCertificateSAN(createPrompts{
				reader: bufio.NewReader(strings.NewReader("192.0.2.20\n")), out: &out}, carrier, listener)
			if err != nil || name != listener.String() {
				t.Fatalf("matching listener IP rejected: %q %v", name, err)
			}
			out.Reset()
			_, err = askTLSCertificateSAN(createPrompts{
				reader: bufio.NewReader(strings.NewReader("bad@name\nq\n")), out: &out}, carrier, listener)
			if !errors.Is(err, errCreateCancelled) || strings.Count(out.String(), "TLS certificate SAN") != 2 {
				t.Fatalf("q after rejected SAN did not cancel: %v %q", err, out.String())
			}
		})
	}
	for _, tc := range []struct {
		carrier composition.Kind
		want    string
		prompts int
	}{
		{composition.WSS, "singlelabel", 1},
		{composition.QUIC, "valid.example", 2},
	} {
		var out bytes.Buffer
		p := createPrompts{reader: bufio.NewReader(strings.NewReader("singlelabel\nvalid.example\n")), out: &out}
		name, err := askTLSCertificateSAN(p, tc.carrier, listener)
		if err != nil || name != tc.want || strings.Count(out.String(), "TLS certificate SAN") != tc.prompts {
			t.Fatalf("carrier-specific DNS admission changed: %s, %q %v %q", tc.carrier, name, err, out.String())
		}
	}
}

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

func TestKeepalivePromptsRetryAndCancelWithoutChangingOtherFields(t *testing.T) {
	var out bytes.Buffer
	p := createPrompts{reader: bufio.NewReader(strings.NewReader("invalid\n65536\n-1\n0\n")), out: &out}
	value, err := askKeepalive(p, "Keepalive seconds: ")
	if err != nil || value != 0 || strings.Count(out.String(), "Keepalive seconds: ") != 4 {
		t.Fatalf("keepalive retry failed: %d, %v, %q", value, err, out.String())
	}
	out.Reset()
	p = createPrompts{reader: bufio.NewReader(strings.NewReader("y\n65535\nwrong\n12\n")), out: &out}
	local, peer, err := askCarrierKeepalives(p)
	if err != nil || local != 65535 || peer != 12 || strings.Count(out.String(), "Keepalive seconds on OTHER server") != 2 {
		t.Fatalf("endpoint-local keepalive choices lost: %d/%d, %v, %q", local, peer, err, out.String())
	}
	out.Reset()
	p = createPrompts{reader: bufio.NewReader(strings.NewReader("n\n")), out: &out}
	local, peer, err = askCarrierKeepalives(p)
	if err != nil || local != 25 || peer != 25 {
		t.Fatalf("guided default changed: %d/%d %v", local, peer, err)
	}
	out.Reset()
	p = createPrompts{reader: bufio.NewReader(strings.NewReader("y\nq\n")), out: &out}
	_, _, err = askCarrierKeepalives(p)
	if !errors.Is(err, errCreateCancelled) {
		t.Fatalf("cancel did not propagate: %v", err)
	}
}

func TestOptionalTLSNamesAndModesRetryAtSamePrompt(t *testing.T) {
	var out bytes.Buffer
	p := createPrompts{reader: bufio.NewReader(strings.NewReader("bad/name\nvalid.example\n")), out: &out}
	name, err := askTLSCertificateSAN(p, composition.WSS, netip.MustParseAddr("192.0.2.20"))
	if err != nil || name != "valid.example" || strings.Count(out.String(), "TLS certificate SAN") != 2 {
		t.Fatalf("TLS name did not retry: %q %v %q", name, err, out.String())
	}
	out.Reset()
	p = createPrompts{reader: bufio.NewReader(strings.NewReader("wrong\n2\n")), out: &out}
	public, err := askWSSPublicTLS(p)
	if err != nil || !public || strings.Count(out.String(), "WSS TLS mode [1]") != 2 {
		t.Fatalf("WSS mode did not retry: %v %v %q", public, err, out.String())
	}
	out.Reset()
	p = createPrompts{reader: bufio.NewReader(strings.NewReader("wrong\n3\n")), out: &out}
	mode, http3, err := askQUICMode(p)
	if err != nil || mode != "" || !http3 || strings.Count(out.String(), "QUIC mode [1]") != 2 {
		t.Fatalf("QUIC mode did not retry: %q %v %v %q", mode, http3, err, out.String())
	}
	out.Reset()
	p = createPrompts{reader: bufio.NewReader(strings.NewReader("q\n")), out: &out}
	_, err = askTLSCertificateSAN(p, composition.QUIC, netip.MustParseAddr("192.0.2.20"))
	if !errors.Is(err, errCreateCancelled) {
		t.Fatalf("TLS name cancel was lost: %v", err)
	}
}
