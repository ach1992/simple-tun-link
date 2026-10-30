package quicwgorigin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/quicguard"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
	"golang.org/x/sys/unix"
)

const (
	testID    domain.LinkID = "lnk_0123456789abcdef0123456789abcdef"
	testNonce               = "0123456789abcdef0123456789abcdef"
	testBoot                = "11111111-2222-3333-4444-555555555555"
	testNS                  = "net:[4026532999]"
	testPort                = uint16(51820)
)

func testInputs(t *testing.T) (string, domain.WireGuardOptions) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	key, pub, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zeroize()
	_, peer, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := wgbackend.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutNew(testID, key); err != nil {
		t.Fatal(err)
	}
	return root, domain.WireGuardOptions{LocalPublicKey: pub, PeerPublicKey: peer, ListenPort: testPort, PeerPort: 51821}
}

func originalGuard() quicguard.OriginalGuardObservation {
	origin, _ := linux.PlanQUICWGHostOrigin(testID, testNonce, testPort)
	return quicguard.OriginalGuardObservation{
		LinkID: testID, Table: origin.Guard.TableName(), ListenPort: testPort,
		KernelBootID: testBoot, NetworkNS: testNS,
		Status:        quicguard.GuardRecordedOriginalWitness,
		Handles:       linux.WGIngressLiveHandles{Table: 21, Chain: 22, Rule: 23},
		ReceiptDevice: 45, ReceiptInode: 46}
}

type mockKernel struct {
	created  bool
	alias    string
	index    int
	name     string
	events   []string
	occupied bool
	noWG     bool
}

func (f *mockKernel) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	return f.RunBounded(ctx, linux.CaptureLimits{Stdout: 1 << 20, Stderr: 1 << 16}, name, args...)
}
func (f *mockKernel) RunBounded(ctx context.Context, lim linux.CaptureLimits,
	name string, args ...string) (linux.CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return linux.CommandResult{}, err
	}
	f.events = append(f.events, name+" "+strings.Join(args, " "))
	switch {
	case name == "wg" && reflect.DeepEqual(args, []string{"show", "interfaces"}):
		if f.noWG {
			return linux.CommandResult{}, errors.New("missing wg executable")
		}
		return linux.CommandResult{}, nil
	case name == "wg" && len(args) == 3 && args[0] == "show" && args[1] == "all":
		return linux.CommandResult{}, nil
	case name == "wg" && len(args) == 3 && args[0] == "show" && args[1] == f.name:
		switch args[2] {
		case "public-key":
			return linux.CommandResult{Stdout: []byte("(none)\n")}, nil
		case "listen-port":
			return linux.CommandResult{Stdout: []byte("off\n")}, nil
		case "peers":
			return linux.CommandResult{}, nil
		}
	case name == "ss" && len(args) == 4:
		return linux.CommandResult{}, nil
	case name == "ip" && reflect.DeepEqual(args, []string{"-details", "-json", "link", "show"}):
		rows := []map[string]any{{"ifindex": 1, "ifname": "lo"}}
		if f.occupied {
			rows = append(rows, map[string]any{"ifindex": 6, "ifname": f.name})
		}
		raw, _ := json.Marshal(rows)
		return linux.CommandResult{Stdout: raw}, nil
	case name == "ip" && reflect.DeepEqual(args, []string{"-details", "-json", "link", "show", "dev", f.name}):
		if !f.created {
			return linux.CommandResult{}, errors.New("missing staged interface")
		}
		raw, _ := json.Marshal([]map[string]any{{"ifindex": f.index, "ifname": f.name,
			"ifalias": f.alias, "flags": []string{"NOARP"}, "linkinfo": map[string]string{"info_kind": "wireguard"}}})
		return linux.CommandResult{Stdout: raw}, nil
	case name == "ip" && reflect.DeepEqual(args, []string{"-details", "-json", "address", "show", "dev", f.name}):
		if !f.created {
			return linux.CommandResult{}, errors.New("missing staged address")
		}
		raw, _ := json.Marshal([]map[string]any{{"ifindex": f.index, "ifname": f.name, "addr_info": []any{}}})
		return linux.CommandResult{Stdout: raw}, nil
	}
	return linux.CommandResult{}, fmt.Errorf("unexpected test-only query %s %s", name, strings.Join(args, " "))
}

func mockOps(f *mockKernel) kernelOps {
	guard := originalGuard()
	return kernelOps{runner: f, boot: func() (string, error) { return testBoot, nil },
		ns: func() (string, error) { return testNS, nil },
		guard: func(context.Context, string, domain.LinkID, string, uint16) (quicguard.OriginalGuardObservation, error) {
			f.events = append(f.events, "guard")
			return guard, nil
		},
		create: func(_ context.Context, name string) error {
			f.events = append(f.events, "create")
			if f.created {
				return errors.New("exclusive creation collision")
			}
			f.name = name
			f.index = 5
			f.created = true
			return nil
		},
		alias: func(_ context.Context, index int, alias string) error {
			f.events = append(f.events, "alias")
			if !f.created || index != f.index {
				return errors.New("foreign ifindex")
			}
			f.alias = alias
			return nil
		}}
}

func TestOriginalKernelWGFirstCreateGuardBeforeEffectReceiptAndReadOnly(t *testing.T) {
	root, wg := testInputs(t)
	f := &mockKernel{}
	ops := mockOps(f)
	origin, _ := linux.PlanQUICWGHostOrigin(testID, testNonce, testPort)
	if err := createWithReceipt(context.Background(), root, testID, testNonce, wg, ops); err != nil {
		t.Fatalf("original-first guarded creation: %v; events=%v", err, f.events)
	}
	firstGuard, firstCreate := -1, -1
	for i, s := range f.events {
		if s == "guard" && firstGuard < 0 {
			firstGuard = i
		}
		if s == "create" && firstCreate < 0 {
			firstCreate = i
		}
	}
	if firstGuard < 0 || firstCreate <= firstGuard || !f.created || f.alias != origin.OwnerTag {
		t.Fatalf("creation bypassed guard-first rule: %+v", f)
	}
	dir, err := openReceiptDir(root, false)
	if err != nil {
		t.Fatal(err)
	}
	receipt, birth, err := readReceipt(dir, testID, testNonce, testPort)
	unix.Close(dir)
	if err != nil || receipt.IfIndex != 5 || receipt.StagingName != origin.StagingName ||
		receipt.OwnerTag != origin.OwnerTag || birth.Inode == 0 || receipt.GuardHandles != originalGuard().Handles {
		t.Fatalf("durable original witness invalid: %+v %+v %v", receipt, birth, err)
	}
	obs, err := inspectWithinAdmission(context.Background(), root, testID, testNonce, testPort, wg.LocalPublicKey, ops)
	if err != nil || obs.IfIndex != 5 || obs.NetworkNS != testNS {
		t.Fatalf("read-only witness mismatch: %+v %v", obs, err)
	}
	events := len(f.events)
	if err := createWithReceipt(context.Background(), root, testID, testNonce, wg, ops); err == nil {
		t.Fatal("repeat creation adopted existing original")
	}
	if !f.created || f.alias != origin.OwnerTag || len(f.events) != events {
		t.Fatal("repeat changed host or consulted kernel despite existing birth receipt")
	}
}

func TestOriginalKernelWGPreEffectFailClosed(t *testing.T) {
	cases := []struct {
		name  string
		setup func(string, *mockKernel, *kernelOps)
	}{
		{"missing-key", func(root string, _ *mockKernel, _ *kernelOps) {
			_ = os.Remove(filepath.Join(root, "credentials", string(testID)+".wgkey"))
		}},
		{"missing-guard", func(_ string, _ *mockKernel, ops *kernelOps) {
			ops.guard = func(context.Context, string, domain.LinkID, string, uint16) (quicguard.OriginalGuardObservation, error) {
				return quicguard.OriginalGuardObservation{}, errors.New("no original guard")
			}
		}},
		{"foreign-staging", func(_ string, f *mockKernel, _ *kernelOps) { f.occupied = true }},
		{"unavailable-wg-inventory", func(_ string, f *mockKernel, _ *kernelOps) { f.noWG = true }},
		{"canceled-context", func(_ string, _ *mockKernel, _ *kernelOps) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, wg := testInputs(t)
			f := &mockKernel{}
			ops := mockOps(f)
			tc.setup(root, f, &ops)
			ctx := context.Background()
			if tc.name == "canceled-context" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if err := createWithReceipt(ctx, root, testID, testNonce, wg, ops); err == nil {
				t.Fatalf("%s admitted unsafe host effect", tc.name)
			}
			if f.created {
				t.Fatal("pre-effect failure dispatched kernel CREATE")
			}
		})
	}
}

func TestOriginalKernelWGPostEffectQuarantine(t *testing.T) {
	cases := []struct {
		name   string
		change func(*kernelOps, *mockKernel)
	}{
		{"exclusive-ack-uncertain", func(ops *kernelOps, f *mockKernel) {
			original := ops.create
			ops.create = func(ctx context.Context, name string) error {
				if err := original(ctx, name); err != nil {
					return err
				}
				return errors.New("lost ACK after effective RTM_NEWLINK")
			}
		}},
		{"alias-uncertain", func(ops *kernelOps, _ *mockKernel) {
			ops.alias = func(context.Context, int, string) error { return errors.New("lost alias ACK") }
		}},
		{"guard-replaced", func(ops *kernelOps, _ *mockKernel) {
			first := true
			ops.guard = func(context.Context, string, domain.LinkID, string, uint16) (quicguard.OriginalGuardObservation, error) {
				guard := originalGuard()
				if first {
					first = false
				} else {
					guard.Handles.Rule++
				}
				return guard, nil
			}
		}},
		{"guard-receipt-same-values-new-inode", func(ops *kernelOps, _ *mockKernel) {
			first := true
			ops.guard = func(context.Context, string, domain.LinkID, string, uint16) (quicguard.OriginalGuardObservation, error) {
				guard := originalGuard()
				if first {
					first = false
				} else {
					guard.ReceiptInode++
				}
				return guard, nil
			}
		}},
		{"namespace-drift", func(ops *kernelOps, f *mockKernel) {
			ops.ns = func() (string, error) {
				if f.created {
					return "net:[4026533000]", nil
				}
				return testNS, nil
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, wg := testInputs(t)
			f := &mockKernel{}
			ops := mockOps(f)
			tc.change(&ops, f)
			if err := createWithReceipt(context.Background(), root, testID, testNonce, wg, ops); err == nil {
				t.Fatal("uncertain post-effect state accepted")
			}
			if !f.created {
				t.Fatal("did not exercise actual effect boundary")
			}
			dir, err := openReceiptDir(root, false)
			if err != nil {
				t.Fatal(err)
			}
			err = requireReceiptVacant(dir, testID)
			unix.Close(dir)
			if err != nil {
				t.Fatal("uncertain effect manufactured a successful durable receipt")
			}
			if !f.created {
				t.Fatal("uncertain host resource automatically removed")
			}
		})
	}
}

func TestOriginalWGReceiptForeignSameByteReplacementRejected(t *testing.T) {
	root, wg := testInputs(t)
	f := &mockKernel{}
	ops := mockOps(f)
	if err := createWithReceipt(context.Background(), root, testID, testNonce, wg, ops); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "credentials", receiptDir, receiptName(testID))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Same-byte replacement between separate observations is NOT original
	// lifetime proof and must NOT authorize deletion. A same-byte inode swap
	// while one pinned observation is in flight must be rejected.
	replacement := false
	oldGuard := ops.guard
	ops.guard = func(ctx context.Context, root string, id domain.LinkID, nonce string, port uint16) (quicguard.OriginalGuardObservation, error) {
		if !replacement {
			replacement = true
			contents, e := os.ReadFile(path)
			if e != nil {
				return quicguard.OriginalGuardObservation{}, e
			}
			if e = os.Rename(path, path+".older"); e != nil {
				return quicguard.OriginalGuardObservation{}, e
			}
			if e = os.WriteFile(path, contents, 0o600); e != nil {
				return quicguard.OriginalGuardObservation{}, e
			}
		}
		return oldGuard(ctx, root, id, nonce, port)
	}
	obs, err := inspectWithinAdmission(context.Background(), root, testID, testNonce, testPort, wg.LocalPublicKey, ops)
	if !replacement || err == nil || obs != (OriginalObservation{}) {
		t.Fatalf("same-byte inode replacement accepted: %+v %v", obs, err)
	}
}

func TestEngineRejectsNativeWGCreationWithoutCanonicalJournal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store := state.NewFileStore(root)
	registry, err := backend.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := app.New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := StageOriginal(context.Background(), engine, testID); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("unowned QUIC host-effect writer allowed without Engine journal: %v", err)
	}
}

func TestNativeWGReceiptHasNoPrivateKey(t *testing.T) {
	root, wg := testInputs(t)
	ops := mockOps(&mockKernel{})
	if err := createWithReceipt(context.Background(), root, testID, testNonce, wg, ops); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "credentials", receiptDir, receiptName(testID)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private_key")) || bytes.Contains(raw, []byte("secret")) {
		t.Fatal("original kernel receipt contains private secret field")
	}
}

// An invented record, changed protection, symlink or noncanonical encoding
// cannot turn a matching live kernel link into a first-create witness.
func TestNativeWGBirthReceiptModeSymlinkAndForeignEncodingFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"unsafe-mode", func(t *testing.T, p string) {
			t.Helper()
			if err := os.Chmod(p, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"foreign-symlink", func(t *testing.T, p string) {
			t.Helper()
			if err := os.Rename(p, p+".saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".saved", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown-json-field", func(t *testing.T, p string) {
			t.Helper()
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			raw = bytes.Replace(raw, []byte(`"schema_version":1,`), []byte(`"schema_version":1,"foreign":true,`), 1)
			if err := os.WriteFile(p, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, wg := testInputs(t)
			ops := mockOps(&mockKernel{})
			if err := createWithReceipt(context.Background(), root, testID, testNonce, wg, ops); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "credentials", receiptDir, receiptName(testID))
			tc.mutate(t, path)
			observation, err := inspectWithinAdmission(context.Background(), root, testID, testNonce, testPort, wg.LocalPublicKey, ops)
			if err == nil || observation != (OriginalObservation{}) {
				t.Fatalf("untrusted birth evidence promoted to ownership: %+v %v", observation, err)
			}
		})
	}
}
