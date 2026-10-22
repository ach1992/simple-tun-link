package wss

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type nftTableInventoryStub struct{ data string }

func (r nftTableInventoryStub) Run(context.Context, string, ...string) (linux.CommandResult, error) {
	return linux.CommandResult{}, fmt.Errorf("only bounded queries allowed")
}
func (r nftTableInventoryStub) RunBounded(_ context.Context, _ linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if name != "nft" || strings.Join(args, " ") != "-j list tables" {
		return linux.CommandResult{}, fmt.Errorf("unexpected readback")
	}
	return linux.CommandResult{Stdout: []byte(r.data)}, nil
}
func TestWSSNFTTableInventoryNeverTreatsIncompleteReadbackAsAbsence(t *testing.T) {
	link := wssTestLink()
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	valid := `{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1}},{"table":{"family":"inet","name":"unrelated"}}]}`
	for label, input := range map[string]string{
		"missing-list":       `{}`,
		"null-list":          `{"nftables":null}`,
		"empty-list":         `{"nftables":[]}`,
		"duplicate-member":   `{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1,"version":"1.1.4"}}]}`,
		"case-alias-member":  `{"nftables":[{"metaInfo":{"version":"1.1.3","json_schema_version":1}}]}`,
		"duplicate-metadata": `{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1}},{"metainfo":{"version":"1.1.3","json_schema_version":1}}]}`,
		"unknown-object":     `{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1}},{"chain":{"family":"inet"}}]}`,
		"trailing-data":      valid + `{"nftables":[]}`,
		"truncated":          `{"nftables":[`,
		"duplicate-table":    `{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1}},{"table":{"family":"inet","name":"same"}},{"table":{"family":"inet","name":"same"}}]}`,
	} {
		t.Run(label, func(t *testing.T) {
			host := Host{Runner: nftTableInventoryStub{data: input}}
			found, err := host.GuardPresent(context.Background(), link)
			if err == nil || found {
				t.Fatalf("malformed nft inventory returned absence: found=%t err=%v", found, err)
			}
		})
	}
	host := Host{Runner: nftTableInventoryStub{data: valid}}
	present, err := host.GuardPresent(context.Background(), link)
	if err != nil || present {
		t.Fatalf("valid complete foreign table inventory rejected: %v", err)
	}
}
func TestWSSUnitPropertiesRequireExactRestartAndSandbox(t *testing.T) {
	want := map[string]string{
		"Type": "exec", "Restart": "on-failure", "RestartUSec": "2s",
		"NoNewPrivileges": "yes", "PrivateTmp": "yes",
		"ProtectSystem": "strict", "ProtectHome": "yes",
		"CollectMode": "inactive-or-failed",
	}
	if err := verifyWSSUnitSecurityProperties(want); err != nil {
		t.Fatal(err)
	}
	for key := range want {
		t.Run(key, func(t *testing.T) {
			changed := map[string]string{}
			for k, v := range want {
				changed[k] = v
			}
			changed[key] = "none"
			if err := verifyWSSUnitSecurityProperties(changed); err == nil {
				t.Fatalf("mismatched systemd property %s was trusted", key)
			}
			delete(changed, key)
			if err := verifyWSSUnitSecurityProperties(changed); err == nil {
				t.Fatalf("missing systemd property %s was trusted", key)
			}
		})
	}
}
