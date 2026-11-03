package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type greReceiverProbe struct {
	inventory string
	err       error
	calls     int
}

func (p *greReceiverProbe) Run(context.Context, string, ...string) (linux.CommandResult, error) {
	return linux.CommandResult{}, errors.New("unexpected unbounded local observation")
}

func (p *greReceiverProbe) RunBounded(_ context.Context, limits linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	p.calls++
	if name != "ip" || !slices.Equal(args, []string{"-json", "address", "show"}) ||
		limits.Stdout <= 0 || limits.Stderr <= 0 {
		return linux.CommandResult{}, errors.New("unexpected local inventory command or unbounded capture")
	}
	if p.err != nil {
		return linux.CommandResult{}, p.err
	}
	return linux.CommandResult{Stdout: []byte(p.inventory)}, nil
}

func greReceiverInventory(iface, ip string) string {
	return fmt.Sprintf(`[{"ifname":%q,"addr_info":[{"family":"inet","local":%q}]}]`, iface, ip)
}

func runGREImportReceiverReview(t *testing.T, source domain.Link, probe *greReceiverProbe, confirm string) (string, string, *lifecycleFakeBackend) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "never-committed")
	fake := newLifecycleFake()
	offer := testQuickSetupLink(t, source, nil)
	var output, errOut bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"},
		strings.NewReader("2\n1\n"+offer+"\n"+confirm+"\n8\n"),
		&output, &errOut, &runtimeOptions{
			stateRoot: root, backends: []backend.Backend{fake},
			probeRunner: probe,
		})
	if code != 0 {
		t.Fatalf("menu code=%d output=%q stderr=%q", code, output.String(), errOut.String())
	}
	for _, forbidden := range []string{offer, source.DisplayName, setupLinkConfirmation(offer), "UNTRUSTED_PRIVATE_HOST_SECRET"} {
		if strings.Contains(output.String()+errOut.String(), forbidden) {
			t.Fatalf("receiver review leaked untrusted input %q", forbidden)
		}
	}
	if len(fake.applies) == 0 {
		if _, err := os.Lstat(filepath.Join(root, "state.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected/cancelled import persisted State: %v", err)
		}
	}
	return output.String(), errOut.String(), fake
}

func TestGREImportReceiverReviewAgainstBoundedHostInventory(t *testing.T) {
	source, _ := makeLifecycleDesired(t, "a", "10.70.170.0/31")
	receiver := source.Underlay.Peer.String()
	for _, tc := range []struct {
		name, inventory, want, mustNot string
		probeErr                       error
		confirm                        string
		wantApplies                    int
	}{
		{
			name:      "assigned receiver still requires explicit confirmation",
			inventory: greReceiverInventory("eth0", receiver),
			want:      "assigned to exactly one local interface",
			confirm:   "YES", wantApplies: 1,
		},
		{
			name:      "wrong receiving host rejects without confirmation",
			inventory: greReceiverInventory("eth0", "203.0.113.197"),
			want:      "not assigned to THIS server",
			mustNot:   "Import this tunnel?",
			confirm:   "0",
		},
		{
			name:      "stale pretyped YES cannot override local mismatch",
			inventory: greReceiverInventory("eth0", "203.0.113.197"),
			want:      "not assigned to THIS server",
			mustNot:   "Import this tunnel?",
			confirm:   "YES",
		},
		{
			name: "ambiguous receiver cannot be admitted",
			inventory: strings.TrimSuffix(greReceiverInventory("eth0", receiver), "]") +
				"," + strings.TrimPrefix(greReceiverInventory("eth1", receiver), "["),
			want:    "multiple local interfaces",
			mustNot: "Import this tunnel?",
			confirm: "0",
		},
		{
			name:      "malformed inventory is not a proven recipient mismatch",
			inventory: "[bad-json-with-UNTRUSTED_PRIVATE_HOST_SECRET]",
			want:      "could not be verified",
			mustNot:   "not assigned to THIS server",
			confirm:   "0",
		},
		{
			name:      "complete empty inventory has no local receiver",
			inventory: "[]",
			want:      "not assigned to THIS server",
			mustNot:   "Import this tunnel?",
			confirm:   "0",
		},
		{
			name:     "inventory error is unverified not wrong recipient",
			probeErr: errors.New("UNTRUSTED_PRIVATE_HOST_SECRET"),
			want:     "could not be verified",
			mustNot:  "not assigned to THIS server",
			confirm:  "0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &greReceiverProbe{inventory: tc.inventory, err: tc.probeErr}
			out, errOut, fake := runGREImportReceiverReview(t, source, probe, tc.confirm)
			if !strings.Contains(out, tc.want) || (tc.mustNot != "" && strings.Contains(out, tc.mustNot)) {
				t.Fatalf("review did not classify local evidence: out=%q err=%q", out, errOut)
			}
			if tc.wantApplies == 0 && strings.Contains(out, "Import this tunnel?") {
				t.Fatal("non-admitted recipient was offered a host mutation confirmation")
			}
			if probe.calls != 1 {
				t.Fatalf("expected exactly one bounded local inventory read, got %d", probe.calls)
			}
			if len(fake.applies) != tc.wantApplies {
				t.Fatalf("backend Apply count=%d want=%d; out=%q", len(fake.applies), tc.wantApplies, out)
			}
		})
	}
}

func TestGREImportNoRemoteRecipientInferenceWhenSenderCannotBeObserved(t *testing.T) {
	source, _ := makeLifecycleDesired(t, "b", "10.70.172.0/31")
	probe := &greReceiverProbe{inventory: greReceiverInventory("eth0", source.Underlay.Peer.String())}
	out, _, fake := runGREImportReceiverReview(t, source, probe, "")
	if !strings.Contains(out, "does not verify the sender's endpoint") ||
		!strings.Contains(out, "Import cancelled") || len(fake.applies) != 0 {
		t.Fatalf("receiver address observation falsely authenticated the sender or bypassed consent: %q", out)
	}
}

// Shared recipient checks apply to every Setup Link family. A verified local
// match is still not proof of the sender's intended recipient. IPsec is
// deliberately advisory when NAT-T could explain an absent public endpoint.
func TestAllImportBackendsShareReceiverReviewAndNATAwareGuidance(t *testing.T) {
	backends := []domain.Backend{
		domain.BackendGRE, domain.BackendIPIP, domain.BackendL2TPv3,
		domain.BackendWireGuard, domain.BackendWireGuardWSS,
		domain.BackendWireGuardQUIC, domain.BackendIPsec,
	}
	const receiver = "192.0.2.20"
	cases := []struct {
		name, inventory, want string
		err                   error
		status                bool
		natStatus             bool
	}{
		{"assigned", greReceiverInventory("eth0", receiver), "does not verify the sender's endpoint", nil, true, true},
		{"other receiver", greReceiverInventory("eth0", "203.0.113.197"), "not assigned to THIS server", nil, false, true},
		{"multiple assignments", strings.TrimSuffix(greReceiverInventory("eth0", receiver), "]") +
			"," + strings.TrimPrefix(greReceiverInventory("eth1", receiver), "["), "multiple local interfaces", nil, false, false},
		{"malformed inventory", "[bad-json-with-UNTRUSTED_PRIVATE_HOST_SECRET]", "could not be verified", nil, false, true},
		{"failed capture", "", "could not be verified", errors.New("UNTRUSTED_PRIVATE_HOST_SECRET"), false, true},
	}
	for _, kind := range backends {
		for _, tc := range cases {
			t.Run(string(kind)+"/"+tc.name, func(t *testing.T) {
				probe := &greReceiverProbe{inventory: tc.inventory, err: tc.err}
				var out bytes.Buffer
				encap := domain.EncapNative
				if kind == domain.BackendIPsec {
					encap = domain.EncapNATT
				}
				allowed := reviewImportReceiver(&out, probe, receiver, kind, encap)
				wantAllowed := tc.status
				if kind == domain.BackendIPsec {
					wantAllowed = tc.natStatus
				}
				if allowed != wantAllowed || probe.calls != 1 || !strings.Contains(out.String(), tc.want) ||
					strings.Contains(out.String(), "UNTRUSTED_PRIVATE_HOST_SECRET") {
					t.Fatalf("incorrect shared receiver guidance: backend=%s allowed=%t want=%t observed=%q calls=%d",
						kind, allowed, wantAllowed, out.String(), probe.calls)
				}
				if kind == domain.BackendIPsec && tc.name == "other receiver" {
					if !strings.Contains(out.String(), "NAT") || !strings.Contains(out.String(), "BEFORE confirming") {
						t.Fatal("IPsec missing endpoint was treated as proven wrong recipient")
					}
				}
			})
		}
	}
}

// The actual versioned Quick Link menu shares the same refusal for every
// non-NAT tunnel kind, including protected native WireGuard and IPsec ESP.
// A stale pretyped YES must not bypass the first recipient check.
func TestQuickLinkMenuRejectsOtherReceiverForAllNonNATBackends(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend domain.Backend
		encap   domain.Encapsulation
		mode    string
	}{
		{"gre", domain.BackendGRE, domain.EncapNative, "1"},
		{"ipip", domain.BackendIPIP, domain.EncapNative, "1"},
		{"l2tpv3", domain.BackendL2TPv3, domain.EncapNative, "1"},
		{"wireguard", domain.BackendWireGuard, domain.EncapUDP, "2"},
		{"ipsec-esp", domain.BackendIPsec, domain.EncapESP, "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link, _ := makeLifecycleDesired(t, "b", "10.70.178.0/31")
			link.Backend, link.Encapsulation = tc.backend, tc.encap
			var credential []byte
			if tc.backend == domain.BackendWireGuard {
				key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
				completeWireGuardFixture(t, &link, key)
				credential = []byte(key)
			}
			if tc.backend == domain.BackendIPsec {
				credential = bytes.Repeat([]byte{0x59}, 32)
			}
			offer := testQuickSetupLink(t, link, credential)
			root := filepath.Join(t.TempDir(), "no-state")
			fake := newLifecycleFake()
			probe := &greReceiverProbe{inventory: greReceiverInventory("eth0", "203.0.113.197")}
			var out, errOut bytes.Buffer
			rc := runWithRuntimeInput([]string{"menu"},
				strings.NewReader("2\n"+tc.mode+"\n"+offer+"\nYES\n8\n"),
				&out, &errOut, &runtimeOptions{
					stateRoot: root, backends: []backend.Backend{fake},
					probeRunner: probe,
				})
			if rc != 0 || probe.calls != 1 ||
				!strings.Contains(out.String(), "not assigned to THIS server") ||
				strings.Contains(out.String(), "Import this tunnel?") ||
				strings.Contains(out.String()+errOut.String(), offer) ||
				strings.Contains(out.String()+errOut.String(), link.DisplayName) ||
				len(fake.applies) != 0 {
				t.Fatalf("%s wrong-host Quick Link was admitted: code=%d out=%q err=%q calls=%d",
					tc.name, rc, out.String(), errOut.String(), probe.calls)
			}
			if _, err := os.Lstat(filepath.Join(root, "state.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("wrong-host Quick Link committed state: %v", err)
			}
		})
	}
}
