//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type localWSSHealthRunner struct {
	addr, peer, iface, pubkey string
	listenPort                uint16
	probes                    int
}

func (r *localWSSHealthRunner) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	cmd := name + " " + strings.Join(args, " ")
	switch {
	case cmd == "wg show "+r.iface+" public-key":
		return linux.CommandResult{Stdout: []byte(r.pubkey + "\n")}, nil
	case cmd == "wg show "+r.iface+" listen-port":
		return linux.CommandResult{Stdout: []byte(fmt.Sprintf("%d\n", r.listenPort))}, nil
	case cmd == "ip -4 -json address show dev "+r.iface:
		return linux.CommandResult{Stdout: []byte(fmt.Sprintf(`[{"ifindex":33,"ifname":%q,"mtu":1420,"flags":["UP"],"addr_info":[{"family":"inet","local":%q,"prefixlen":30}]}]`, r.iface, r.addr))}, nil
	case cmd == "ip -4 -json route get "+r.peer:
		return linux.CommandResult{Stdout: []byte(fmt.Sprintf(`[{"dst":%q,"dev":%q,"prefsrc":%q}]`, r.peer, r.iface, r.addr))}, nil
	case name == "env":
		if !strings.Contains(cmd, "-s 56") ||
			!strings.Contains(cmd, "-I "+r.iface+" -I "+r.addr+" "+r.peer) {
			return linux.CommandResult{}, fmt.Errorf("unscoped or non-small WSS ping")
		}
		r.probes++
		return linux.CommandResult{Stdout: []byte(fmt.Sprintf("64 bytes from %s: icmp_seq=1 ttl=64 time=86.5 ms\n1 packets transmitted, 1 received, 0%% packet loss\n", r.peer))}, nil
	default:
		return linux.CommandResult{}, fmt.Errorf("unexpected command %s", cmd)
	}
}
func (r *localWSSHealthRunner) RunBounded(ctx context.Context, _ linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	return r.Run(ctx, name, args...)
}
func TestWSSStatusAndMenuFivePingUseSameCanonicalActiveDiagnostics(t *testing.T) {
	opts, sender, _, _, secret := savedExternalWSSFixture(t)
	iface, _ := wgbackend.InterfaceName(sender.ID)
	r := &localWSSHealthRunner{addr: sender.Addresses.Local.Addr().String(), peer: sender.Addresses.Peer.Addr().String(), iface: iface, pubkey: sender.WireGuard.LocalPublicKey, listenPort: sender.WireGuard.ListenPort}
	opts.probeRunner = r
	observation := WSSLinkDiagnostics{SchemaVersion: 1, LinkID: sender.ID,
		Carrier: "wss-tls", Role: sender.WSS.Role, WSSHelperActive: true,
		WGIngressGuardActive: true, KernelWireGuardPresent: true,
		WireGuardHandshakeObserved: true, LastHandshakeUnix: 1800000000, RXBytes: 120, TXBytes: 345}
	opts.wssObserver = func(_ context.Context, _ string, _ linux.BoundedRunner, link domain.Link) (WSSLinkDiagnostics, error) {
		if link != sender {
			t.Fatal("WSS identity drifted")
		}
		return observation, nil
	}
	run := func(args ...string) (int, string, string) {
		var out, stderr bytes.Buffer
		code := runWithRuntime(args, &out, &stderr, opts)
		if strings.Contains(out.String()+stderr.String(), secret) ||
			strings.Contains(out.String()+stderr.String(), "receiver_tls") ||
			strings.Contains(out.String()+stderr.String(), "private_key") {
			t.Fatal("secret disclosure in WSS status/diagnosis")
		}
		return code, out.String(), stderr.String()
	}
	code, statusRaw, statusErr := run("link", "status", string(sender.ID), "--json")
	var status linkStatusResponse
	if code != 0 || statusErr != "" || json.Unmarshal([]byte(statusRaw), &status) != nil ||
		!status.InterfaceVerified || status.Link.ID != sender.ID || status.Connectivity != "not_measured" ||
		status.WSSState == nil || !status.WSSState.WSSHelperActive || status.WSSState.RXBytes != 120 ||
		status.WireGuardState != nil || r.probes != 0 {
		t.Fatalf("WSS read-only local status failed: code=%d status=%+v error=%q", code, status, statusErr)
	}
	code, raw, errText := run("link", "diagnose", string(sender.ID), "--mtu", "1280", "--json")
	var manualUnsupported linkReadErrorResponse
	if code != 4 || json.Unmarshal([]byte(raw), &manualUnsupported) != nil ||
		manualUnsupported.Error == nil || manualUnsupported.Error.ReasonCode != "wss_mtu_measurement_unavailable" ||
		r.probes != 0 {
		t.Fatalf("unsupported WSS PMTU was silently accepted: code=%d error=%q probes=%d", code, raw, r.probes)
	}
	code, raw, errText = run("link", "diagnose", string(sender.ID), "--json")
	var report diagnostics.Report
	if code != 0 || errText != "" || json.Unmarshal([]byte(raw), &report) != nil ||
		report.MTU.SelectedMTU != 0 || report.MTU.Mode != "not_measured" ||
		report.Quality.PacketsSent != 5 || report.Quality.PacketsReceived != 5 || r.probes != 5 {
		t.Fatalf("WSS active 5-ping CLI wrong: code=%d report=%+v stderr=%q probes=%d", code, report, errText, r.probes)
	}
	if bound := throughputMeasuredInterface(linkDiagnostic{report: report}); bound != iface {
		t.Fatalf("WSS private throughput binding lost verified interface identity: %q != %q", bound, iface)
	}
	var menu, menuErr bytes.Buffer
	if code := menuCheckOneConnection(sender.ID, &menu, &menuErr, opts); code != 0 ||
		!strings.Contains(menu.String(), "5/5 replies") ||
		!strings.Contains(menu.String(), "86.5 ms") ||
		!strings.Contains(menu.String(), "120 / 345 bytes") ||
		r.probes != 10 {
		t.Fatalf("WSS menu per-Link observation not shared with CLI: code=%d output=%q err=%q probes=%d", code, menu.String(), menuErr.String(), r.probes)
	}
	menu.Reset()
	if code := menuShowLocalStatus(sender.ID, &menu, &menuErr, opts); code != 0 ||
		!strings.Contains(menu.String(), "WSS helper") ||
		!strings.Contains(menu.String(), "WG ingress") ||
		!strings.Contains(menu.String(), "120 / 345 bytes") ||
		r.probes != 10 {
		t.Fatalf("WSS local status menu missing helper+guard evidence: code=%d output=%q", code, menu.String())
	}
	code, raw, errText = run("link", "diagnose", "--all", "--json")
	var all healthCenterResponse
	if code != 0 || errText != "" || json.Unmarshal([]byte(raw), &all) != nil ||
		all.Observed != 1 || all.Blocked != 0 || all.Unknown != 0 ||
		len(all.Checks) != 1 || all.Checks[0].ReasonCode != "link_peer_replied" ||
		all.Checks[0].Observed == nil || all.Checks[0].Observed.MTU.SelectedMTU != 0 ||
		r.probes != 15 {
		t.Fatalf("WSS all-Link health incorrectly blocked: code=%d all=%+v stderr=%q probes=%d", code, all, errText, r.probes)
	}
}
func TestWSSHealthRefusesActivePingIfOriginalGuardNotReady(t *testing.T) {
	opts, link, _, _, _ := savedExternalWSSFixture(t)
	iface, _ := wgbackend.InterfaceName(link.ID)
	r := &localWSSHealthRunner{addr: link.Addresses.Local.Addr().String(), peer: link.Addresses.Peer.Addr().String(), iface: iface, pubkey: link.WireGuard.LocalPublicKey, listenPort: link.WireGuard.ListenPort}
	opts.probeRunner = r
	opts.wssObserver = func(_ context.Context, _ string, _ linux.BoundedRunner, link domain.Link) (WSSLinkDiagnostics, error) {
		return WSSLinkDiagnostics{LinkID: link.ID, KernelWireGuardPresent: true,
			WSSHelperActive: true, WGIngressGuardActive: false}, nil
	}
	var out, stderr bytes.Buffer
	code := runWithRuntime([]string{"link", "diagnose", string(link.ID), "--json"}, &out, &stderr, opts)
	if code == 0 || r.probes != 0 || strings.Contains(out.String(), "link_peer_replied") {
		t.Fatalf("WSS guard missing, but diagnosis claimed peer success: code=%d output=%q probes=%d", code, out.String(), r.probes)
	}
}

func TestWSSDiagnosticRejectsForeignLocalPublicIdentityOrPort(t *testing.T) {
	for _, tc := range []struct {
		name        string
		breakRunner func(*localWSSHealthRunner)
	}{
		{"different local WireGuard public key", func(r *localWSSHealthRunner) { r.pubkey = "unexpected-public-key" }},
		{"different WireGuard listen port", func(r *localWSSHealthRunner) { r.listenPort++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, link, _, _, _ := savedExternalWSSFixture(t)
			iface, _ := wgbackend.InterfaceName(link.ID)
			runner := &localWSSHealthRunner{addr: link.Addresses.Local.Addr().String(),
				peer: link.Addresses.Peer.Addr().String(), iface: iface,
				pubkey: link.WireGuard.LocalPublicKey, listenPort: link.WireGuard.ListenPort}
			tc.breakRunner(runner)
			opts.probeRunner = runner
			opts.wssObserver = func(_ context.Context, _ string, _ linux.BoundedRunner, _ domain.Link) (WSSLinkDiagnostics, error) {
				return WSSLinkDiagnostics{LinkID: link.ID,
					KernelWireGuardPresent: true, WSSHelperActive: true, WGIngressGuardActive: true}, nil
			}
			var out, errs bytes.Buffer
			code := runWithRuntime([]string{"link", "diagnose", string(link.ID), "--json"}, &out, &errs, opts)
			if code == 0 || runner.probes != 0 || strings.Contains(out.String(), "link_peer_replied") {
				t.Fatalf("foreign WSS local identity was incorrectly pinged code=%d probes=%d response=%q", code, runner.probes, out.String())
			}
		})
	}
}

// Exercise the exact interactive selection shown by the Owner's screenshot,
// not only direct helpers. Native menu numbering and return-to-menu behavior
// remain unchanged for managed WSS.
func TestManagedWSSActualTTYMenuStatusAndConnectionResult(t *testing.T) {
	opts, sender, _, _, secret := savedExternalWSSFixture(t)
	iface, _ := wgbackend.InterfaceName(sender.ID)
	runner := &localWSSHealthRunner{
		addr: sender.Addresses.Local.Addr().String(), peer: sender.Addresses.Peer.Addr().String(),
		iface: iface, pubkey: sender.WireGuard.LocalPublicKey, listenPort: sender.WireGuard.ListenPort}
	opts.probeRunner = runner
	opts.wssObserver = func(_ context.Context, _ string, _ linux.BoundedRunner, link domain.Link) (WSSLinkDiagnostics, error) {
		if link.ID != sender.ID {
			t.Fatal("wrong WSS identity in menu")
		}
		return WSSLinkDiagnostics{SchemaVersion: 1, LinkID: sender.ID, Role: "listen",
			WSSHelperActive: true, WGIngressGuardActive: true, KernelWireGuardPresent: true,
			WireGuardHandshakeObserved: true, LastHandshakeUnix: 1800000000, RXBytes: 120, TXBytes: 345}, nil
	}
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("1")
	tty.expect("WSS helper")
	tty.expect("WG ingress")
	tty.expect("Press Enter to continue...")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("2")
	tty.expect("5/5 replies (0% packet loss)")
	tty.expect("Path MTU")
	tty.expect("Press Enter to continue...")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("4")
	tty.expect("WSS role")
	tty.expect("WSS TLS TCP port")
	tty.expect("Press Enter to continue...")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("0")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if runner.probes != 5 || strings.Contains(tty.all, secret) ||
		strings.Contains(tty.all, "Link diagnosis unsupported on this host") ||
		strings.Contains(tty.all, "not supported for manual setup") {
		t.Fatalf("real PTY menu WSS behavior regressed: ping=%d transcript=%q", runner.probes, tty.all)
	}
}
