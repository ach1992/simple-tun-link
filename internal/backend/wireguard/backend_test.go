package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type fakeKernel struct {
	target        observedLink
	others        []observedLink
	calls         [][]string
	fail          string
	wantSecret    string
	exposedSecret bool
}

func (f *fakeKernel) Run(_ context.Context, binary string, args ...string) (linux.CommandResult, error) {
	f.calls = append(f.calls, append([]string{binary}, args...))
	if strings.Contains(strings.Join(args, " "), f.wantSecret) && f.wantSecret != "" {
		f.exposedSecret = true
	}
	if f.fail == "ip-add" && len(args) >= 2 && args[0] == "link" && args[1] == "add" {
		return linux.CommandResult{}, errors.New("synthetic add failure")
	}
	switch {
	case binary == "ip" && reflect.DeepEqual(args, []string{"-details", "-json", "link", "show", "type", "wireguard"}):
		if !f.target.Exists {
			return linux.CommandResult{Stdout: []byte("[]")}, nil
		}
		raw, _ := json.Marshal([]any{map[string]any{"ifindex": f.target.IfIndex, "ifname": f.target.Name, "ifalias": f.target.Alias, "flags": func() []string {
			if f.target.Up {
				return []string{"UP"}
			}
			return []string{}
		}(), "linkinfo": map[string]any{"info_kind": "wireguard"}}})
		return linux.CommandResult{Stdout: raw}, nil
	case binary == "ip" && len(args) == 5 && args[0] == "-json" && args[1] == "address":
		var addrs []any
		for _, v := range f.target.IPv4Addresses {
			addrs = append(addrs, map[string]any{"family": "inet", "local": v.Addr().String(), "prefixlen": v.Bits()})
		}
		raw, _ := json.Marshal([]any{map[string]any{"ifindex": f.target.IfIndex, "ifname": f.target.Name, "addr_info": addrs}})
		return linux.CommandResult{Stdout: raw}, nil
	case binary == "ip" && len(args) == 5 && args[0] == "link" && args[1] == "add":
		f.target = observedLink{Exists: true, IfIndex: 17, Name: args[2]}
		return linux.CommandResult{}, nil
	case binary == "wg" && len(args) == 3 && args[0] == "show":
		iface, field := args[1], args[2]
		if iface == "all" {
			var lines []string
			all := append(append([]observedLink(nil), f.others...), f.target)
			for _, candidate := range all {
				if !candidate.Exists {
					continue
				}
				switch field {
				case "listen-port":
					lines = append(lines, fmt.Sprintf("%s %d", candidate.Name, candidate.ListenPort))
				case "public-key":
					lines = append(lines, fmt.Sprintf("%s %s", candidate.Name, candidate.PublicKey))
				}
			}
			return linux.CommandResult{Stdout: []byte(strings.Join(lines, "\n"))}, nil
		}
		if !f.target.Exists || iface != f.target.Name {
			return linux.CommandResult{}, errors.New("missing fake WG interface")
		}
		var value string
		switch field {
		case "public-key":
			value = f.target.PublicKey
		case "listen-port":
			value = strconv.Itoa(int(f.target.ListenPort))
		case "peers":
			value = strings.Join(f.target.Peers, "\n")
		case "allowed-ips":
			if len(f.target.Peers) == 1 {
				value = f.target.Peers[0] + "\t" + f.target.AllowedIPs
			}
		case "endpoints":
			if len(f.target.Peers) == 1 {
				value = f.target.Peers[0] + "\t" + f.target.Endpoint
			}
		case "persistent-keepalive":
			if len(f.target.Peers) == 1 {
				value = f.target.Peers[0] + "\t" + strconv.Itoa(int(f.target.Keepalive))
			}
		case "latest-handshakes":
			if len(f.target.Peers) == 1 {
				value = f.target.Peers[0] + "\t1700000000"
			}
		case "transfer":
			if len(f.target.Peers) == 1 {
				value = f.target.Peers[0] + "\t1234\t5678"
			}
		default:
			return linux.CommandResult{}, errors.New("unexpected WG show request: " + field)
		}
		return linux.CommandResult{Stdout: []byte(value + "\n")}, nil
	}
	return linux.CommandResult{}, errors.New("unexpected fake command")
}
func (f *fakeKernel) RunWithFiles(_ context.Context, binary string, files []*os.File, args ...string) (linux.CommandResult, error) {
	if binary != "wg" || len(files) != 1 || len(args) != 14 || args[0] != "set" || args[4] != "private-key" || args[5] != "/proc/self/fd/3" {
		return linux.CommandResult{}, fmt.Errorf("unexpected fake WG configuration command")
	}
	raw, err := io.ReadAll(files[0])
	if err != nil {
		return linux.CommandResult{}, err
	}
	if strings.TrimSpace(string(raw)) != f.wantSecret {
		return linux.CommandResult{}, errors.New("wrong private FD")
	}
	f.calls = append(f.calls, append([]string{binary}, args...))
	for _, arg := range args {
		if strings.Contains(arg, f.wantSecret) {
			f.exposedSecret = true
		}
	}
	key, err := DecodePrivateKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return linux.CommandResult{}, err
	}
	pub, err := key.PublicKey()
	if err != nil {
		return linux.CommandResult{}, err
	}
	f.target.PublicKey = pub
	p, _ := strconv.Atoi(args[3])
	f.target.ListenPort = uint16(p)
	f.target.Peers = []string{args[7]}
	f.target.Endpoint = args[9]
	f.target.AllowedIPs = args[11]
	ka, _ := strconv.Atoi(args[13])
	f.target.Keepalive = uint16(ka)
	return linux.CommandResult{}, nil
}

type fakeRoute struct{ source netip.Addr }

func (r fakeRoute) Resolve(_ context.Context, _ netip.Addr) (linux.Route, error) {
	return linux.Route{Source: r.source, Device: "eth0"}, nil
}

type fakeFirewall struct {
	exists bool
	rule   linux.InboundFirewallRule
}

func (f *fakeFirewall) HasInbound(_ context.Context, _ domain.LinkID, r linux.InboundFirewallRule) (bool, error) {
	return f.exists && r == f.rule, nil
}
func (f *fakeFirewall) HasOwnedInbound(_ context.Context, _ domain.LinkID, _ bool) (bool, error) {
	return f.exists, nil
}
func (f *fakeFirewall) EnsureInboundLocked(_ context.Context, _ domain.LinkID, r linux.InboundFirewallRule) (func(context.Context) error, bool, error) {
	prev := f.exists
	f.exists = true
	f.rule = r
	return func(context.Context) error { f.exists = prev; return nil }, !prev, nil
}
func (f *fakeFirewall) RemoveInboundLocked(_ context.Context, _ domain.LinkID, r linux.InboundFirewallRule) (bool, error) {
	if !f.exists || f.rule != r {
		return false, nil
	}
	f.exists = false
	return true, nil
}

type fakeCollisions struct{ conflicts []linux.ObservedResource }

func (f fakeCollisions) Inspect(_ context.Context, claims []domain.ResourceClaim) ([]linux.ObservedResource, error) {
	var out []linux.ObservedResource
	for _, claim := range claims {
		for _, obs := range f.conflicts {
			same, e := domain.ResourceClaimsConflict(claim, obs.Claim)
			if e != nil {
				return nil, e
			}
			if same {
				out = append(out, obs)
			}
		}
	}
	return out, nil
}

func fixture(t *testing.T) (*Backend, domain.Link, *KeyStore, *fakeKernel, *fakeFirewall) {
	t.Helper()
	local, localPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, peerPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	link := domain.Link{ID: "lnk_0123456789abcdef0123456789abcdef", Underlay: domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("192.0.2.20")}, Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.80.50.0/31"), Peer: netip.MustParsePrefix("10.80.50.1/31")}, Backend: domain.BackendWireGuard, Encapsulation: domain.EncapUDP, WireGuard: domain.WireGuardOptions{LocalPublicKey: localPub, PeerPublicKey: peerPub, ListenPort: 51871, PeerPort: 51872, LocalKeepalive: 25}}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	keys, err := NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.PutNew(link.ID, local); err != nil {
		t.Fatal(err)
	}
	fake := &fakeKernel{wantSecret: local.SecretWireValue()}
	fw := &fakeFirewall{}
	b, err := New(Options{Runner: fake, Routes: fakeRoute{link.Underlay.Local}, Firewall: fw, Collisions: fakeCollisions{}, Keys: keys,
		LookupIndex: func(name string) (int, error) {
			if !fake.target.Exists {
				return 0, errors.New("not found")
			}
			return fake.target.IfIndex, nil
		},
		SetAlias: func(_ context.Context, index int, alias string) error {
			fake.target.Alias = alias
			fake.target.Owner = link.ID
			return nil
		},
		AddAddress: func(_ context.Context, index int, prefix netip.Prefix) error {
			fake.target.IPv4Addresses = []netip.Prefix{prefix}
			return nil
		},
		SetUp:      func(_ context.Context, index int) error { fake.target.Up = true; return nil },
		DeleteLink: func(_ context.Context, index int) error { fake.target = observedLink{}; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return b, link, keys, fake, fw
}

func TestWireGuardOwnedLifecycleNoSecretInArgs(t *testing.T) {
	b, link, keys, kernel, fw := fixture(t)
	ctx := context.Background()
	obs, err := b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	p, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, p); err != nil {
		t.Fatal(err)
	}
	undo, err := b.Apply(ctx, req, obs, p)
	if err != nil {
		t.Fatal(err)
	}
	if undo == nil {
		t.Fatal("missing rollback")
	}
	if _, err := b.Verify(ctx, req); err != nil {
		t.Fatal(err)
	}
	if !fw.exists || kernel.exposedSecret {
		t.Fatal("firewall missing or credential leaked to command arguments")
	}
	obs, err = b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	req.OwnedResources = p.Resources()
	again, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Empty() {
		t.Fatal("idempotent ensure should be empty")
	}
	if err := b.Validate(ctx, req, obs, again); err != nil {
		t.Fatal(err)
	}
	remove := core.Request{Operation: core.OperationRemove, Link: link, Prior: &link, OwnedResources: p.Resources()}
	old, err := b.Plan(ctx, remove, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, remove, obs, old); err != nil {
		t.Fatal(err)
	}
	_, err = b.Apply(ctx, remove, obs, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(ctx, remove); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Load(link.ID); err != nil {
		t.Fatalf("remove must not silently lose private key: %v", err)
	}
}

func TestWireGuardRejectsCredentialMismatchBeforeHostMutation(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	_, wrongPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	link.WireGuard.LocalPublicKey = wrongPub
	obs, err := b.Inspect(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Plan(context.Background(), core.Request{Operation: core.OperationEnsure, Link: link}, obs); err == nil {
		t.Fatal("mismatched credential accepted")
	}
	if len(kernel.calls) == 0 || kernel.target.Exists {
		t.Fatal("should only inspect, never mutate")
	}
}

func TestWireGuardRollbackAfterSafePartialCreate(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	b.addAddress = func(context.Context, int, netip.Prefix) error {
		return errors.New("synthetic address failure without publication")
	}
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, err := b.Inspect(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Plan(context.Background(), req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(context.Background(), req, obs, p); err != nil {
		t.Fatal(err)
	}
	undo, err := b.Apply(context.Background(), req, obs, p)
	if err == nil || undo == nil {
		t.Fatal("expected failure with owned rollback")
	}
	if err := undo(context.Background()); err != nil {
		t.Fatal(err)
	}
	if kernel.target.Exists {
		t.Fatal("owned incomplete WireGuard interface was not deleted")
	}
}

func TestWireGuardRollbackPreservesChangedState(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	b.addAddress = func(context.Context, int, netip.Prefix) error {
		kernel.target.IPv4Addresses = []netip.Prefix{netip.MustParsePrefix("10.44.1.1/32")}
		return errors.New("ambiguous foreign address")
	}
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, _ := b.Inspect(context.Background(), link)
	p, err := b.Plan(context.Background(), req, obs)
	if err != nil {
		t.Fatal(err)
	}
	undo, err := b.Apply(context.Background(), req, obs, p)
	if err == nil || undo == nil {
		t.Fatal("expected failure")
	}
	if err := undo(context.Background()); err == nil {
		t.Fatal("rollback should fail closed on unexpected address")
	}
	if !kernel.target.Exists {
		t.Fatal("drifted interface must be preserved")
	}
}

func TestWireGuardBackendInvalidAndForeignState(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, _ := b.Inspect(context.Background(), link)
	p, _ := b.Plan(context.Background(), req, obs)
	kernel.target = observedLink{Exists: true, IfIndex: 17, Name: "stlwg0123456789", Alias: "foreign", Owner: ""}
	current, err := b.Inspect(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(context.Background(), req, current, p); err == nil {
		t.Fatal("foreign interface accepted")
	}
	link.WireGuard.ListenPort = 0
	if err := validateLink(link); err == nil {
		t.Fatal("port-free activation accepted")
	}
	if _, err := parseLinks([]byte("null")); err == nil {
		t.Fatal("absent JSON treated as empty host")
	}
}

func TestWireGuardDiagnosticsIdentityBoundAndSecretFree(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	ctx := context.Background()
	obs, err := b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	p, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Apply(ctx, req, obs, p); err != nil {
		t.Fatal(err)
	}
	got, err := b.DiagnosticState(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if got.Interface == "" || got.PeerPublicKey != link.WireGuard.PeerPublicKey ||
		got.LatestHandshakeUnix != 1700000000 || got.RXBytes != 1234 || got.TXBytes != 5678 || kernel.exposedSecret {
		t.Fatalf("WireGuard status invalid or leaked sensitive material: %+v", got)
	}
	kernel.target.Peers = []string{link.WireGuard.LocalPublicKey}
	if _, err = b.DiagnosticState(ctx, link); err == nil {
		t.Fatal("peer identity drift accepted during diagnostic observation")
	}
	for _, call := range kernel.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "private-key") && !strings.Contains(joined, "/proc/self/fd/3") {
			t.Fatal("private key read through unsafe WG status/argv path")
		}
		if strings.Contains(joined, "dump") || strings.Contains(joined, "preshared") {
			t.Fatal("secret-bearing WG introspection used")
		}
	}
}

func TestWireGuardMultiLinkKernelPortAndPublicIdentityCollisions(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	ctx := context.Background()
	obs, err := b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	p, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, p); err != nil {
		t.Fatal(err)
	}
	kernel.others = []observedLink{{Exists: true, IfIndex: 99, Name: "unmanaged-wg", ListenPort: link.WireGuard.ListenPort, PublicKey: link.WireGuard.PeerPublicKey}}
	if err := b.Validate(ctx, req, obs, p); err == nil {
		t.Fatal("accepted a foreign WireGuard listener on same port")
	}
	kernel.others[0].ListenPort = 61330
	kernel.others[0].PublicKey = link.WireGuard.LocalPublicKey
	if err := b.Validate(ctx, req, obs, p); err == nil {
		t.Fatal("accepted a foreign WireGuard interface using local public identity")
	}
}

func TestWireGuardGenericHostListenerCollision(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	b.collisions = fakeCollisions{conflicts: []linux.ObservedResource{{Claim: domain.ResourceClaim{
		Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(link.WireGuard.ListenPort)),
	}, Source: "foreign-UDP"}}}
	obs, err := b.Inspect(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	p, err := b.Plan(context.Background(), req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(context.Background(), req, obs, p); err == nil {
		t.Fatal("accepted occupied UDP port")
	}
	if kernel.target.Exists {
		t.Fatal("collision mutated host state")
	}
}
