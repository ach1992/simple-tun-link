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

type wssUnitAbsentStub struct{ result string }

func (r wssUnitAbsentStub) Run(context.Context, string, ...string) (linux.CommandResult, error) {
	return linux.CommandResult{}, fmt.Errorf("only bounded systemd inspection")
}
func (r wssUnitAbsentStub) RunBounded(_ context.Context, _ linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if name != "systemctl" || len(args) < 3 || args[0] != "show" {
		return linux.CommandResult{}, fmt.Errorf("unexpected unit inspection")
	}
	return linux.CommandResult{Stdout: []byte(r.result)}, nil
}
func TestWSSUnitNotFoundReadbackRequiresCompleteConsistentState(t *testing.T) {
	link := wssTestLink()
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	valid := "LoadState=not-found\nActiveState=inactive\nTransient=no\nDescription=\nExecStart=\nEnvironment=\nCollectMode=inactive\n"
	// Real systemd 249 (Ubuntu 22.04) and 259 (Ubuntu 26.04)
	// omit ExecStart completely when LoadState=not-found.
	realUnit := (Host{}).unitName(link)
	real249 := fmt.Sprintf("Type=\nRestart=no\nRestartUSec=100ms\nEnvironment=\nPrivateTmp=no\nProtectHome=no\nProtectSystem=no\nNoNewPrivileges=no\nDescription=%s\nLoadState=not-found\nActiveState=inactive\nTransient=no\nCollectMode=inactive\n", realUnit)
	real259 := fmt.Sprintf("Description=%s\nLoadState=not-found\nActiveState=inactive\nTransient=no\nCollectMode=inactive\nType=\nRestart=no\nRestartUSec=100ms\nEnvironment=\nPrivateTmp=no\nProtectHome=no\nProtectSystem=no\nNoNewPrivileges=no\n", realUnit)
	for name, data := range map[string]string{
		"valid":                 valid,
		"systemd249-no-exec":    real249,
		"systemd259-no-exec":    real259,
		"missing-description":   strings.Replace(real249, "Description="+realUnit+"\n", "", 1),
		"foreign-description":   strings.Replace(real249, "Description="+realUnit, "Description=foreign-unit", 1),
		"missing-type":          strings.Replace(real249, "Type=\n", "", 1),
		"missing-restart":       strings.Replace(real249, "Restart=no\n", "", 1),
		"foreign-restart":       strings.Replace(real249, "Restart=no", "Restart=always", 1),
		"missing-sandbox":       strings.Replace(real249, "NoNewPrivileges=no\n", "", 1),
		"foreign-sandbox":       strings.Replace(real249, "NoNewPrivileges=no", "NoNewPrivileges=yes", 1),
		"missing-collect":       strings.Replace(real249, "CollectMode=inactive\n", "", 1),
		"foreign-exec":          strings.Replace(real249, "Environment=\n", "ExecStart=/bin/foreign\nEnvironment=\n", 1),
		"contradictory-main-ex": strings.Replace(real249, "Environment=\n", "ExecStartEx={ path=/bin/sh }\nEnvironment=\n", 1),
		"contradictory-post-ex": strings.Replace(real249, "Environment=\n", "ExecStartPostEx={ path=/bin/sh }\nEnvironment=\n", 1),
		"no-collect-mode":       strings.Replace(valid, "CollectMode=inactive\n", "", 1),
		"unexpected-active":     strings.Replace(valid, "ActiveState=inactive", "ActiveState=active", 1),
		"unexpected-transient":  strings.Replace(valid, "Transient=no", "Transient=yes", 1),
		"late-exec":             strings.Replace(valid, "ExecStart=", "ExecStart=/usr/bin/foreign", 1),
		"malformed":             strings.Replace(valid, "LoadState=not-found\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			h := Host{Runner: wssUnitAbsentStub{data}}
			unit, err := h.inspectUnit(context.Background(), link)
			if name == "valid" || name == "systemd249-no-exec" || name == "systemd259-no-exec" {
				if err != nil || unit.loaded {
					t.Fatalf("valid not-found rejected: %v", err)
				}
			} else if err == nil {
				t.Fatalf("untrusted absent-unit observation accepted: %+v", unit)
			}
		})
	}
}
