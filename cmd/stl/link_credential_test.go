package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type retirementProbeFake struct {
	linkName       string
	alias          string
	livePublic     string
	ownedFirewall  bool
	inspectionFail bool
	calls          []string
}

func (r *retirementProbeFake) Run(_ context.Context, binary string, args ...string) (linux.CommandResult, error) {
	line := binary + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if r.inspectionFail {
		return linux.CommandResult{}, errors.New("unavailable host tool")
	}
	switch {
	case binary == "ip" && len(args) == 4 && args[0] == "-details" && args[1] == "-json" && args[2] == "link" && args[3] == "show":
		if r.linkName != "" || r.alias != "" {
			row := map[string]any{"ifname": "unrelated-iface", "ifalias": r.alias}
			if r.linkName != "" {
				row["ifname"] = r.linkName
			}
			raw, _ := json.Marshal([]any{row})
			return linux.CommandResult{Stdout: raw}, nil
		}
		return linux.CommandResult{Stdout: []byte("[]")}, nil
	case binary == "wg" && len(args) == 3 && args[0] == "show" && args[1] == "all" && args[2] == "public-key":
		if r.livePublic != "" {
			return linux.CommandResult{Stdout: []byte("other-wg\t" + r.livePublic + "\n")}, nil
		}
		return linux.CommandResult{Stdout: []byte("")}, nil
	case binary == "iptables" && len(args) > 3 && args[len(args)-2] == "-S" && args[len(args)-1] == "INPUT":
		if r.ownedFirewall {
			return linux.CommandResult{Stdout: []byte("-A INPUT -m comment --comment stl:lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:fake -j ACCEPT\n")}, nil
		}
		return linux.CommandResult{Stdout: []byte("-P INPUT ACCEPT\n")}, nil
	}
	return linux.CommandResult{}, errors.New("unexpected read-only retirement probe: " + line)
}

func TestWireGuardCredentialRetireNeedsCommittedAndLiveHostAbsence(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	probe := &retirementProbeFake{}
	opts.probeRunner = probe
	link, _ := makeLifecycleDesired(t, "a", "10.70.31.0/31")
	output := filepath.Join(parent, "retire-a.stl")
	code, reply, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", output, "--json"}, creatorRequest(t, link), opts)
	if code != 0 || stderr != "" {
		t.Fatalf("sender fixture failed: %d %q %q", code, reply, stderr)
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	localKey, err := keys.Load(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	public, err := localKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"link", "credential", "retire", string(link.ID), "--confirm", string(link.ID), "--public-key", public, "--json"}
	code, reply, stderr = creatorRun(args, "", opts)
	if code == 0 || stderr != "" || strings.Contains(reply, localKey.SecretWireValue()) || len(probe.calls) != 0 {
		t.Fatalf("retired still-committed credential or leaked private bytes: %d %q %q calls=%v", code, reply, stderr, probe.calls)
	}
	if _, err = keys.Load(link.ID); err != nil {
		t.Fatal("still-committed key was removed", err)
	}
	code, reply, stderr = creatorRun([]string{"link", "remove", string(link.ID), "--confirm", string(link.ID), "--json"}, "", opts)
	if code != 0 || stderr != "" || fake.present[link.ID] {
		t.Fatalf("canonical removal failed: %d %q %q", code, reply, stderr)
	}
	for _, tc := range []struct {
		name  string
		drift func()
		clear func()
	}{
		{"interface-name", func() { probe.linkName = "stlwg" + string(link.ID)[4:14] }, func() { probe.linkName = "" }},
		{"owner-alias", func() { probe.alias = "stl:" + string(link.ID) }, func() { probe.alias = "" }},
		{"active-public-key", func() { probe.livePublic = public }, func() { probe.livePublic = "" }},
		{"malformed-public-key-observation", func() { probe.livePublic = "not-a-public-key" }, func() { probe.livePublic = "" }},
		{"owned-firewall", func() { probe.ownedFirewall = true }, func() { probe.ownedFirewall = false }},
		{"unknown-inspection", func() { probe.inspectionFail = true }, func() { probe.inspectionFail = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.drift()
			code, reply, stderr := creatorRun(args, "", opts)
			tc.clear()
			if code == 0 || stderr != "" || strings.Contains(reply, localKey.SecretWireValue()) {
				t.Fatalf("unproven host absence retired credential: %d %q %q", code, reply, stderr)
			}
			if _, err := keys.Load(link.ID); err != nil {
				t.Fatalf("unproven absence destroyed key: %v", err)
			}
		})
	}
	code, reply, stderr = creatorRun(append([]string(nil), args...), "", opts)
	if code != 0 || stderr != "" {
		t.Fatalf("safe retirement failed: %d %q %q calls=%v", code, reply, stderr, probe.calls)
	}
	var retired wireGuardCredentialRetireResponse
	if err := json.Unmarshal([]byte(reply), &retired); err != nil || !retired.Retired || retired.LinkID != link.ID {
		t.Fatalf("inaccurate retirement result %+v %v", retired, err)
	}
	if _, err = keys.Load(link.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired credential still present: %v", err)
	}
	code, reply, stderr = creatorRun(args, "", opts)
	if code != 0 || stderr != "" {
		t.Fatalf("already retired state not idempotent: %d %q %q", code, reply, stderr)
	}
	if err = json.Unmarshal([]byte(reply), &retired); err != nil || retired.Retired {
		t.Fatalf("duplicate retirement claimed mutation %+v %v", retired, err)
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snapshot.Links) != 0 {
		t.Fatalf("retirement altered committed state: %+v %v", snapshot, err)
	}
}

func TestWireGuardCredentialRetireMismatchAndUnsafeFileFailClosed(t *testing.T) {
	root, parent, _, opts := newCreatorTest(t)
	opts.probeRunner = &retirementProbeFake{}
	link, _ := makeLifecycleDesired(t, "b", "10.70.32.0/31")
	output := filepath.Join(parent, "retire-b.stl")
	code, _, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", output, "--json"}, creatorRequest(t, link), opts)
	if code != 0 || stderr != "" {
		t.Fatalf("fixture creation failed %d %q", code, stderr)
	}
	code, _, stderr = creatorRun([]string{"link", "remove", string(link.ID), "--confirm", string(link.ID), "--json"}, "", opts)
	if code != 0 || stderr != "" {
		t.Fatalf("fixture remove failed %d %q", code, stderr)
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	local, err := keys.Load(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	public, err := local.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	_, different, err := wireguard.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, pub := range []string{different, strings.Repeat("X", 44)} {
		args := []string{"link", "credential", "retire", string(link.ID), "--confirm", string(link.ID), "--public-key", pub, "--json"}
		code, _, _ = creatorRun(args, "", opts)
		if code == 0 {
			t.Fatal("mismatched/invalid public identity permitted retirement")
		}
	}
	path := filepath.Join(root, "credentials", string(link.ID)+".wgkey")
	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, _ = creatorRun([]string{"link", "credential", "retire", string(link.ID), "--confirm", string(link.ID), "--public-key", public, "--json"}, "", opts)
	if code == 0 {
		t.Fatal("insecure protected file permitted retirement")
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("credential deleted despite unsafe permissions", err)
	}
}

func TestWireGuardRetirementRejectsMissingDesiredStateEvidence(t *testing.T) {
	// Protected credential can outlive a failed first Ensure. Absence of a
	// state.json file must NOT authorize KeyStore destruction.
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	own, public, err := wireguard.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	id := domain.LinkID("lnk_cccccccccccccccccccccccccccccccc")
	if err := keys.PutNew(id, own); err != nil {
		t.Fatal(err)
	}
	options := &runtimeOptions{stateRoot: root, backends: []backend.Backend{&wireGuardCreatorFake{newLifecycleFake()}}, probeRunner: &retirementProbeFake{}}
	code, _, _ := creatorRun([]string{"link", "credential", "retire", string(id), "--confirm", string(id), "--public-key", public, "--json"}, "", options)
	if code == 0 {
		t.Fatal("missing durable state was treated as successful Link removal")
	}
	if _, err = keys.Load(id); err != nil {
		t.Fatalf("retirement destroyed an unreconciled key: %v", err)
	}
}
