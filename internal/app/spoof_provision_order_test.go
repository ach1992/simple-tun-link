package app

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type provisioningSpoofFake struct {
	*fakeBackend
	onValidate func() error
}

func (*provisioningSpoofFake) Kind() domain.Backend { return domain.BackendSpoof }

func (b *provisioningSpoofFake) Validate(ctx context.Context, req backend.Request, obs backend.Observation, plan backend.Plan) error {
	if b.onValidate != nil {
		if err := b.onValidate(); err != nil {
			return err
		}
	}
	return b.fakeBackend.Validate(ctx, req, obs, plan)
}

func provisioningSpoofLink(t *testing.T, name, local, peer string) domain.Link {
	t.Helper()
	link := linkFor(t, name, local, peer)
	_, pub, err := spoof.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	link.Backend = domain.BackendSpoof
	link.Encapsulation = domain.EncapUDP
	link.Spoof = domain.SpoofOptions{
		Role:       "creator",
		SourceFile: "/root/stl/spoof/sources.txt",
		ListenPort: 48001, PeerPort: 48002,
		OuterProtocol:  "udp",
		LocalPublicKey: base64.RawURLEncoding.EncodeToString(pub[:]),
		MaterialSHA256: strings.Repeat("a", 64),
	}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	return link
}

func TestSpoofProvisionDefersProtectedWriteUntilAfterLockedResourceAdmission(t *testing.T) {
	b := &provisioningSpoofFake{fakeBackend: newFakeBackend()}
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := state.NewFileStore(root)
	engine, err := New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	first := provisioningSpoofLink(t, "spoof-shared", "10.88.1.1/32", "10.88.1.2/32")
	second := provisioningSpoofLink(t, "spoof-shared", "10.88.2.1/32", "10.88.2.2/32")
	third := provisioningSpoofLink(t, "spoof-distinct", "10.88.3.1/32", "10.88.3.2/32")
	// The fake's only resource claim is DisplayName (an interface-like
	// identity). It models the exact conflicting resource that an actual
	// Spoof sender port would reserve without privileged network writes.
	marker := filepath.Join(root, "spoof-credential-stage")
	staged := 0
	stage := func() error {
		staged++
		return os.WriteFile(marker, []byte("staged"), 0600)
	}
	b.onValidate = func() error {
		if _, err := os.Stat(marker); err != nil {
			return errors.New("Spoof credential was not published before backend Validate")
		}
		return nil
	}
	if _, err := engine.EnsureWithSpoofProvision(context.Background(), first, stage); err != nil || staged != 1 {
		t.Fatalf("initial Spoof provisioning failed: staged=%d err=%v", staged, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	staged = 0
	if _, err := engine.EnsureWithSpoofProvision(context.Background(), second, stage); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("conflicting Spoof resource was not rejected: %v", err)
	}
	if staged != 0 {
		t.Fatalf("conflicting Spoof Link staged %d protected credentials before conflict admission", staged)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("rejected Spoof Link left a protected credential: %v", err)
	}
	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, present := snapshot.Find(first.ID); !present {
		t.Fatal("conflict changed the original Link")
	}
	if _, present := snapshot.Find(second.ID); present {
		t.Fatal("conflicting Spoof Link committed")
	}
	if _, err := engine.EnsureWithSpoofProvision(context.Background(), third, stage); err != nil || staged != 1 {
		t.Fatalf("independent Spoof provisioning failed: staged=%d err=%v", staged, err)
	}
}
