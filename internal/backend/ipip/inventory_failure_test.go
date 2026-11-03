package ipip

import (
	"context"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type unreadableIPIPInventory struct {
	fakeRunner
	output []byte
	calls  []string
}

func (r *unreadableIPIPInventory) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	joined := strings.Join(args, " ")
	r.calls = append(r.calls, joined)
	if joined == "-details -json link show type ipip" {
		return linux.CommandResult{Stdout: r.output}, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestIPIPSuccessfulExitMalformedInventoryFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name         string
		output       string
		moduleOnDisk bool
		wantReason   string
	}{
		{"placeholder rows with proven unloaded module", "[{},{},{}]", true, "kernel_module_not_loaded"},
		{"placeholder rows with unknown module", "[{},{},{}]", false, "ipip_kernel_inventory_unverified"},
		{"null is not a verified empty list", "null", false, "ipip_kernel_inventory_unverified"},
		{"whitespace is not a verified empty list", "  \n  ", false, "ipip_kernel_inventory_unverified"},
		{"fallback missing identity", `[{"linkinfo":{"info_kind":"ipip","info_data":{"local":"any","remote":"any"}}}]`, false, "ipip_kernel_inventory_unverified"},
		{"one-sided wildcard cannot hide a foreign device", `[{"ifindex":1,"ifname":"tunl0","linkinfo":{"info_kind":"ipip","info_data":{"local":"any","remote":"192.0.2.2"}}}]`, false, "ipip_kernel_inventory_unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := testLink()
			runner := &unreadableIPIPInventory{fakeRunner: fakeRunner{link: link}, output: []byte(tc.output)}
			backend, err := New(Options{
				Runner: runner, Routes: fakeRoute{linux.Route{Peer: link.Underlay.Peer, Source: link.Underlay.Local, Device: "eth0"}},
				Firewall: &fakeFirewall{}, Collisions: fakeCollisions{},
				ModuleProbe: func(_ context.Context, module string) bool {
					if module != "ipip" {
						t.Fatalf("unexpected module %q", module)
					}
					return tc.moduleOnDisk
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = backend.Inspect(context.Background(), link)
			if err == nil {
				t.Fatal("unverified inventory accepted as free host resources")
			}
			public := stlerr.Public(err)
			if public.Code != stlerr.CodeInspect || public.ReasonCode != tc.wantReason || public.NextStep == "" ||
				strings.Contains(public.Error()+public.NextStep, tc.output) {
				t.Fatalf("unsafe/unhelpful inspection failure: %+v", public)
			}
			status, err := backend.Capability(context.Background(), link)
			if err != nil || status.Available || status.ReasonCode != tc.wantReason {
				t.Fatalf("capability disagrees with Engine inventory: %+v %v", status, err)
			}
			for _, call := range runner.calls {
				if strings.Contains(call, "link add") || strings.Contains(call, "link del") ||
					strings.Contains(call, "modprobe") || strings.Contains(call, "fou add") {
					t.Fatalf("inspection/capability mutated the host: %s", call)
				}
			}
		})
	}
}

func TestIPIPEmptyArrayAndValidWildcardAreNotMalformed(t *testing.T) {
	for _, input := range []string{
		"[]",
		`[{"ifindex":1,"ifname":"tunl0","linkinfo":{"info_kind":"ipip","info_data":{"local":"any","remote":"any"}}}]`,
	} {
		got, err := parseIPIPLinks([]byte(input))
		if err != nil || len(got) != 0 {
			t.Fatalf("trustworthy empty/wildcard IPIP observation refused: %v %#v", err, got)
		}
	}
}
