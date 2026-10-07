package linux

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type resourceRunner struct {
	output map[string]string
	err    map[string]error
}

func (r resourceRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if err := r.err[key]; err != nil {
		return CommandResult{}, err
	}
	out, ok := r.output[key]
	if !ok {
		return CommandResult{}, fmt.Errorf("unexpected command %s", key)
	}
	return CommandResult{Stdout: []byte(out)}, nil
}

func TestCollisionInspectorFindsCommonHostCollisionsAndOwner(t *testing.T) {
	runner := resourceRunner{output: map[string]string{
		"ip -json link show":            `[{"ifname":"stl0","ifalias":"stl:lnk_0123456789abcdef0123456789abcdef"},{"ifname":"eth0"}]`,
		"ip -json address show":         `[{"ifname":"stl0","addr_info":[{"local":"10.80.20.0","prefixlen":31}]},{"ifname":"eth0","addr_info":[{"local":"192.0.2.10","prefixlen":24}]}]`,
		"ip -json route show table all": `[{"dst":"10.80.30.0/24","dev":"eth0"},{"dst":"default","dev":"eth0"}]`,
		"ss -H -u -l -n":                "UNCONN 0 0 0.0.0.0:4500 0.0.0.0:*\n",
	}}
	inspector := CollisionInspector{Snapshotter: HostSnapshotter{Runner: runner}}
	claims := []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: "stl0"},
		{Kind: domain.ResourceLinkSubnet, Key: "10.80.20.0/31"},
		{Kind: domain.ResourceLinkSubnet, Key: "10.80.30.0/25"},
		{Kind: domain.ResourceUDPListenPort, Key: "4500"},
	}
	got, err := inspector.Inspect(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 4 {
		t.Fatalf("conflicts = %#v, want at least four observations", got)
	}
	owner := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	foundOwnedInterface := false
	for _, observed := range got {
		if observed.Claim.Kind == domain.ResourceInterface && observed.Claim.Key == "stl0" {
			foundOwnedInterface = true
			if observed.Owner != owner {
				t.Fatalf("interface owner = %q, want %q", observed.Owner, owner)
			}
		}
	}
	if !foundOwnedInterface {
		t.Fatal("interface collision not reported")
	}
}

func TestCollisionInspectorRequiresExplicitProbeForSpecificKinds(t *testing.T) {
	runner := resourceRunner{output: map[string]string{
		"ip -json link show":            "[]",
		"ip -json address show":         "[]",
		"ip -json route show table all": "[]",
		"ss -H -u -l -n":                "",
	}}
	claim := domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "gre:key:100"}
	inspector := CollisionInspector{Snapshotter: HostSnapshotter{Runner: runner}}
	if _, err := inspector.Inspect(context.Background(), []domain.ResourceClaim{claim}); err == nil {
		t.Fatal("expected missing backend-specific collision probe to fail closed")
	}

	called := false
	inspector.Extra = map[string]ResourceProbe{
		domain.ResourceBackendID: ResourceProbeFunc(func(_ context.Context, got domain.ResourceClaim) ([]ObservedResource, error) {
			called = true
			if got.Canonical() != claim.Canonical() {
				t.Fatalf("probe claim = %#v, want %#v", got, claim)
			}
			return nil, nil
		}),
	}
	if _, err := inspector.Inspect(context.Background(), []domain.ResourceClaim{claim}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("backend-specific probe was not called")
	}
}

func TestParseUDPListenersHandlesIPv4AndIPv6(t *testing.T) {
	got, err := parseUDPListeners("UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\nUNCONN 0 0 [::]:4500 [::]:*\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[51820]; !ok {
		t.Fatal("missing UDP port 51820")
	}
	if _, ok := got[4500]; !ok {
		t.Fatal("missing UDP port 4500")
	}
}
