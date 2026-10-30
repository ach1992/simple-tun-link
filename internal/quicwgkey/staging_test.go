package quicwgkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type vacantHost struct{}

func (vacantHost) Vacant(context.Context, []domain.ResourceClaim) (bool, error) {
	return true, nil
}

func journalEngine(t *testing.T) (*app.Engine, *state.FileStore) {
	t.Helper()
	root := t.TempDir()
	store := state.NewFileStore(root)
	registry, err := backend.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := app.New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	return engine, store
}

func journalIntent(role composition.Role) state.QUICCrashOperation {
	local := composition.QUICLocalAdmission{
		LinkID: domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Role: role,
		LocalWGUDPPort: 51821, LocalHelperUDPPort: 52211, RemoteWGUDPPort: 51820,
	}
	wg := domain.WireGuardOptions{
		LocalPublicKey: "IS1qsvcyqHq8sEBGvIFZh5zr6ZpE6Ch3m9rj/xVhF1c=",
		PeerPublicKey:  "4eCgBnNdRX6z+xV0sqQtFWxCyjV4pNzj9nUv59yBfBU=",
		ListenPort:     51821, PeerPort: 52211,
	}
	if role == composition.Listen {
		local.LocalWGUDPPort, local.LocalHelperUDPPort, local.RemoteWGUDPPort = 51820, 443, 0
		wg.ListenPort, wg.PeerPort = 51820, 51821
	}
	return state.QUICCrashOperation{
		Plan: composition.QUICHostPlan{Local: local,
			Physical: netip.MustParseAddrPort("198.51.100.60:443"), TLSName: "198.51.100.60"},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.96.20.0/31"), Peer: netip.MustParsePrefix("10.96.20.1/31")},
		WireGuard:         wg,
		CertificateSHA256: strings.Repeat("a", 64), TrustCASHA256: strings.Repeat("b", 64),
		AuthorizationSHA256: strings.Repeat("c", 64), HelperConfigSHA256: strings.Repeat("d", 64),
		ExecutablePath: "/opt/hysteria", ExecutableSHA256: strings.Repeat("e", 64),
		ExecutableDevice: 1, ExecutableInode: 2,
	}
}

func prepareOriginalKey(t *testing.T, role composition.Role) (
	*app.Engine, *state.FileStore, state.QUICCrashOperation, wgbackend.PrivateKey) {
	t.Helper()
	engine, store := journalEngine(t)
	key, public, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal("cannot generate isolated native WireGuard credential")
	}
	intent := journalIntent(role)
	intent.WireGuard.LocalPublicKey = public
	op, err := engine.PrepareQUICCrash(context.Background(), intent, vacantHost{})
	if err != nil {
		t.Fatal("cannot prepare durable QUIC journal: ", err)
	}
	return engine, store, op, key
}

func TestOriginalPrivateKeyUsesJournalAndOriginalNativeKeyStore(t *testing.T) {
	for _, role := range []composition.Role{composition.Dial, composition.Listen} {
		t.Run(string(role), func(t *testing.T) {
			ctx := context.Background()
			engine, store, op, key := prepareOriginalKey(t, role)
			defer key.Zeroize()
			id := op.Plan.Local.LinkID
			before, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(store.RootDir(), "credentials", string(id)+".wgkey")
			if err := InspectJournalKey(ctx, engine, id); stlerr.CodeOf(err) != stlerr.CodeState {
				t.Fatalf("unpublished native key inspected as present: %v", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("private key read created a file")
			}
			wrong, _, err := wgbackend.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			wrongErr := StageInitial(ctx, engine, id, wrong)
			if stlerr.CodeOf(wrongErr) != stlerr.CodeConflict ||
				strings.Contains(wrongErr.Error(), wrong.SecretWireValue()) {
				t.Fatalf("invalid private identity accepted or disclosed: %v", wrongErr)
			}
			wrong.Zeroize()
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("non-journaled native private key was written")
			}
			if err := StageInitial(ctx, engine, id, key); err != nil {
				t.Fatalf("first native private key publication failed: %v", err)
			}
			if err := InspectJournalKey(ctx, engine, id); err != nil {
				t.Fatalf("protected native key readback failed: %v", err)
			}
			for _, f := range []struct {
				path string
				mode os.FileMode
			}{
				{store.RootDir(), 0o700},
				{filepath.Join(store.RootDir(), "credentials"), 0o700},
				{path, 0o600},
			} {
				info, err := os.Lstat(f.path)
				if err != nil || info.Mode().Perm() != f.mode || info.Mode()&os.ModeSymlink != 0 {
					t.Fatalf("wrong owner-private file or directory mode: %v", err)
				}
			}
			oldFile, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			keyStore, err := wgbackend.NewKeyStore(store.RootDir())
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := keyStore.Load(id)
			if err != nil || recovered != key {
				t.Fatalf("private key differs from original: %v", err)
			}
			if err := StageInitial(ctx, engine, id, key); stlerr.CodeOf(err) != stlerr.CodeState {
				t.Fatalf("original matching key was silently adopted: %v", err)
			}
			newFile, err := os.Lstat(path)
			if err != nil || !os.SameFile(oldFile, newFile) {
				t.Fatal("repeated staging replaced the protected credential inode")
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 || entries[0].Name() != string(id)+".wgkey" {
				t.Fatal("private staging retained an unexpected temporary credential file")
			}
			after, err := store.Load(ctx)
			if err != nil || !reflect.DeepEqual(before, after) || len(after.Links) != 0 ||
				len(after.QUICCrashOperations) != 1 {
				t.Fatalf("native key staging consumed a journal or committed a Link: %v", err)
			}
			stateJSON, err := json.Marshal(after)
			if err != nil || bytes.Contains(stateJSON, []byte(key.SecretWireValue())) {
				t.Fatal("private native key leaked into ordinary State")
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := InspectJournalKey(ctx, engine, id); stlerr.CodeOf(err) != stlerr.CodeState {
				t.Fatalf("unsafe credential permissions were accepted: %v", err)
			}
		})
	}
}

func TestOriginalPrivateKeyRequiresJournalAndRejectsForeignLeaf(t *testing.T) {
	ctx := context.Background()
	t.Run("missing journal", func(t *testing.T) {
		engine, store := journalEngine(t)
		key, _, err := wgbackend.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		defer key.Zeroize()
		id := journalIntent(composition.Dial).Plan.Local.LinkID
		if err := StageInitial(ctx, engine, id, key); stlerr.CodeOf(err) != stlerr.CodeConflict {
			t.Fatalf("private staging bypassed absent journal: %v", err)
		}
		if err := InspectJournalKey(ctx, engine, id); stlerr.CodeOf(err) != stlerr.CodeConflict {
			t.Fatalf("private read bypassed absent journal: %v", err)
		}
		if _, err := os.Stat(filepath.Join(store.RootDir(), "credentials")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("missing journal caused a credential write")
		}
	})
	t.Run("foreign symlink", func(t *testing.T) {
		engine, store, op, key := prepareOriginalKey(t, composition.Listen)
		defer key.Zeroize()
		dir := filepath.Join(store.RootDir(), "credentials")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		foreign := filepath.Join(t.TempDir(), "foreign")
		if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, string(op.Plan.Local.LinkID)+".wgkey")
		if err := os.Symlink(foreign, target); err != nil {
			t.Fatal(err)
		}
		if err := StageInitial(ctx, engine, op.Plan.Local.LinkID, key); stlerr.CodeOf(err) != stlerr.CodeState {
			t.Fatalf("foreign credential file was overwritten or adopted: %v", err)
		}
		if err := InspectJournalKey(ctx, engine, op.Plan.Local.LinkID); stlerr.CodeOf(err) != stlerr.CodeState {
			t.Fatalf("foreign credential symlink passed inspection: %v", err)
		}
		info, err := os.Lstat(target)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatal("foreign symlink replaced")
		}
		content, err := os.ReadFile(foreign)
		if err != nil || string(content) != "foreign" {
			t.Fatal("foreign file contents changed")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatal("foreign refusal leaked temporary credential")
		}
	})
}

func TestIndependentQUICJournalsKeepNativeKeysSeparate(t *testing.T) {
	ctx := context.Background()
	engine, store := journalEngine(t)
	first := journalIntent(composition.Dial)
	second := first
	second.Plan.Local.LinkID = domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	second.Plan.Local.LocalWGUDPPort, second.Plan.Local.LocalHelperUDPPort = 51822, 52212
	second.Addresses.Local = netip.MustParsePrefix("10.96.21.0/31")
	second.Addresses.Peer = netip.MustParsePrefix("10.96.21.1/31")
	second.WireGuard.ListenPort, second.WireGuard.PeerPort = 51822, 52212
	var keys [2]wgbackend.PrivateKey
	for i, op := range []*state.QUICCrashOperation{&first, &second} {
		key, public, err := wgbackend.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
		op.WireGuard.LocalPublicKey = public
	}
	defer keys[0].Zeroize()
	defer keys[1].Zeroize()
	journals := make([]state.QUICCrashOperation, 2)
	for i, intent := range []state.QUICCrashOperation{first, second} {
		op, err := engine.PrepareQUICCrash(ctx, intent, vacantHost{})
		if err != nil {
			t.Fatalf("independent Link journal rejected: %v", err)
		}
		journals[i] = op
	}
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, op := range journals {
		if err := StageInitial(ctx, engine, op.Plan.Local.LinkID, keys[i]); err != nil {
			t.Fatalf("independent Link key not staged: %v", err)
		}
		if err := InspectJournalKey(ctx, engine, op.Plan.Local.LinkID); err != nil {
			t.Fatalf("independent Link key not verified: %v", err)
		}
	}
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || len(after.QUICCrashOperations) != 2 {
		t.Fatalf("independent Link credentials modified journal: %v", err)
	}
	for i, op := range journals {
		reader, err := wgbackend.NewKeyStore(store.RootDir())
		if err != nil {
			t.Fatal(err)
		}
		got, err := reader.Load(op.Plan.Local.LinkID)
		if err != nil || got != keys[i] {
			t.Fatalf("independent native credential mismatch: %v", err)
		}
	}
}
