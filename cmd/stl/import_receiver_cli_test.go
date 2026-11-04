package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// Actual CLI entrypoints, not a synthetic diagnosis wrapper. An exact
// confirmed Setup Link intended for another host must not reach any
// persistent PSK/WG/TLS state, backend Apply or destructive cleanup.
func TestAllCLIImportsRejectWrongReceiverBeforeDurableEffects(t *testing.T) {
	for _, kind := range []string{"gre", "ipip", "l2tpv3", "wireguard", "ipsec-esp", "ipsec-natt", "wss", "quic"} {
		t.Run(kind, func(t *testing.T) {
			var args []string
			var raw string
			source, _ := makeLifecycleDesired(t, "c", "10.75.52.0/31")
			switch kind {
			case "gre", "ipip", "l2tpv3":
				switch kind {
				case "ipip":
					source.Backend = domain.BackendIPIP
				case "l2tpv3":
					source.Backend = domain.BackendL2TPv3
				}
				raw = testQuickSetupLink(t, source, nil)
			case "wireguard":
				source.Backend, source.Encapsulation = domain.BackendWireGuard, domain.EncapUDP
				key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
				completeWireGuardFixture(t, &source, key)
				raw = testQuickSetupLink(t, source, []byte(key))
			case "ipsec-esp", "ipsec-natt":
				source.Backend = domain.BackendIPsec
				source.Encapsulation = domain.EncapESP
				if kind == "ipsec-natt" {
					source.Encapsulation = domain.EncapNATT
				}
				raw = testQuickSetupLink(t, source, bytes.Repeat([]byte{0x59}, 32))
			case "wss":
				offer, _ := testProtectedWSSReceiverOffer(t)
				raw = string(offer)
			case "quic":
				_, offer := testQUICOffer(t)
				raw = string(offer)
			}
			cmd := "import"
			if kind == "wss" {
				cmd = "import-wss"
			}
			if kind == "quic" {
				cmd = "import-quic"
			}
			args = []string{"link", cmd, "--stdin", "--confirm", setupLinkConfirmation(raw), "--json"}
			root := filepath.Join(t.TempDir(), "preexisting-private-root")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "unrelated-owned-material")
			if err := os.WriteFile(marker, []byte("PRESERVE_EXISTING_MATERIAL"), 0600); err != nil {
				t.Fatal(err)
			}
			probe := &greReceiverProbe{inventory: greReceiverInventory("eth0", "203.0.113.197")}
			fake := newLifecycleFake()
			opts := &runtimeOptions{stateRoot: root, probeRunner: probe, backends: []backend.Backend{fake}}
			var out, errOut bytes.Buffer
			exit := runWithRuntimeInput(args, strings.NewReader(raw), &out, &errOut, opts)
			var response lifecycleFailureResponse
			if exit == 0 || errOut.Len() != 0 || json.Unmarshal(out.Bytes(), &response) != nil ||
				response.Error == nil || response.Error.ReasonCode != "local_underlay_not_assigned" ||
				response.Error.Evidence == nil || response.Error.Evidence.HostMutation != "not_attempted" ||
				response.Error.Evidence.CredentialProvision != "" || probe.calls != 1 ||
				strings.Contains(out.String(), raw) || strings.Contains(out.String(), "PRESERVE_EXISTING_MATERIAL") ||
				len(fake.applies) != 0 {
				t.Fatalf("%s permitted wrong recipient Import, leaked offer or lost evidence: exit=%d out=%q err=%q reads=%d applies=%d",
					kind, exit, out.String(), errOut.String(), probe.calls, len(fake.applies))
			}
			list, err := os.ReadDir(root)
			if err != nil || len(list) != 1 || list[0].Name() != "unrelated-owned-material" {
				t.Fatalf("%s created private credential/State or removed unrelated material: %v %v", kind, list, err)
			}
			kept, err := os.ReadFile(marker)
			if err != nil || string(kept) != "PRESERVE_EXISTING_MATERIAL" {
				t.Fatalf("%s changed preexisting material: %v", kind, err)
			}
		})
	}
}

func TestConfirmedCLIImportSeparatesIncompleteInventoryAndInterruptions(t *testing.T) {
	source, _ := makeLifecycleDesired(t, "d", "10.75.54.0/31")
	raw := testQuickSetupLink(t, source, nil)
	for _, tc := range []struct {
		name, data string
		cause      error
		want       string
	}{
		{"incomplete", `[{"ifname":"eth0"}]`, nil, "local_underlay_unverified"},
		{"mixed partial", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"203.0.113.197"}]},{"ifname":"eth1"}]`, nil, "local_underlay_unverified"},
		{"empty valid", `[]`, nil, "local_underlay_not_assigned"},
		{"ambiguous", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.20"}]},{"ifname":"eth1","addr_info":[{"family":"inet","local":"192.0.2.20"}]}]`, nil, "local_underlay_ambiguous"},
		{"canceled", "", context.Canceled, "operation_cancelled_before_apply"},
		{"timeout", "", context.DeadlineExceeded, "operation_deadline_exceeded_before_apply"},
		{"capture limit", "", linux.ErrOutputLimit, "local_underlay_capture_limited"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &greReceiverProbe{inventory: tc.data, err: tc.cause}
			root := filepath.Join(t.TempDir(), "never-created")
			var out, errOut bytes.Buffer
			rc := runWithRuntimeInput([]string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(raw), "--json"},
				strings.NewReader(raw), &out, &errOut,
				&runtimeOptions{stateRoot: root, probeRunner: probe, backends: []backend.Backend{newLifecycleFake()}})
			var response lifecycleFailureResponse
			if rc == 0 || errOut.Len() != 0 || json.Unmarshal(out.Bytes(), &response) != nil ||
				response.Error == nil || response.Error.ReasonCode != tc.want ||
				response.Error.NextStep == "" || response.Error.Evidence == nil ||
				response.Error.Evidence.HostMutation != "not_attempted" || probe.calls != 1 ||
				strings.Contains(out.String(), raw) {
				t.Fatalf("incomplete/interrupt local evidence falsely passed: code=%d out=%s err=%s", rc, out.String(), errOut.String())
			}
			if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected import created state: %v", err)
			}
		})
	}
}
