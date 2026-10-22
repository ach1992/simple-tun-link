package wireguard

import (
	"context"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type wssVacancyTestHost struct{}

func (wssVacancyTestHost) GuardPresent(context.Context, domain.Link) (bool, error) { return false, nil }
func (wssVacancyTestHost) HelperPresent(context.Context, domain.Link) (bool, error) {
	return false, nil
}
func (wssVacancyTestHost) HelperLoaded(context.Context, domain.Link) (bool, error) { return false, nil }
func (wssVacancyTestHost) Preflight(context.Context, domain.Link, bool) error      { return nil }
func (wssVacancyTestHost) EnsureGuard(context.Context, domain.Link) (core.Rollback, error) {
	return nil, nil
}
func (wssVacancyTestHost) StartHelper(context.Context, domain.Link) (core.Rollback, error) {
	return nil, nil
}
func (wssVacancyTestHost) StopHelper(context.Context, domain.Link) (core.Rollback, error) {
	return nil, nil
}
func (wssVacancyTestHost) RemoveGuard(context.Context, domain.Link) (core.Rollback, error) {
	return nil, nil
}

func TestWSSCrashVacancyDeniesUnexpectedGlobalKernelIdentity(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	b.wssHost = wssVacancyTestHost{}
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, err := core.WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	observation := observation{WSSLink: link}
	if vacant, vacancyErr := b.CrashHostVacant(ctx, observation); vacancyErr == nil || vacant {
		t.Fatal("namespace-local empty state was accepted without original deletion witness")
	}
	ctx, err = core.WithWSSWGDeleted(ctx, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := b.CrashHostVacant(ctx, observation)
	if err != nil || !ok {
		t.Fatalf("original deletion witness plus verified empty host was not accepted: %v", err)
	}
	kernel.others = []observedLink{{Exists: true, Name: "another-if", PublicKey: link.WireGuard.LocalPublicKey, ListenPort: 65532}}
	ok, err = b.CrashHostVacant(ctx, observation)
	if err != nil || ok {
		t.Fatalf("same private identity survived on another interface: vacant=%t err=%v", ok, err)
	}
	kernel.others = []observedLink{{Exists: true, Name: "another-if", PublicKey: link.WireGuard.PeerPublicKey, ListenPort: link.WireGuard.ListenPort}}
	ok, err = b.CrashHostVacant(ctx, observation)
	if err != nil || ok {
		t.Fatalf("reserved kernel UDP listener moved: vacant=%t err=%v", ok, err)
	}
	kernel.others = []observedLink{{Exists: true, Name: "untrusted if name", PublicKey: link.WireGuard.PeerPublicKey, ListenPort: 65531}}
	ok, err = b.CrashHostVacant(ctx, observation)
	if err == nil || ok {
		t.Fatalf("malformed global WG output verified absent: vacant=%t err=%v", ok, err)
	}
	observation.WSSLink = domain.Link{}
	if ok, err = b.CrashHostVacant(ctx, observation); err == nil || ok {
		t.Fatal("missing committed public WSS identity verified absent")
	}
}

// Regression: a WG interface can be moved to a foreign namespace and left
// DOWN, hiding both its name and original UDP socket from the source
// namespace. The original rollback function must NOT report successful
// deletion merely because Inspect no longer sees its former ifindex.
func TestWSSCreatedInterfaceRollbackNeverConfusesMovedOutWithDeletion(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	b.wssHost = wssVacancyTestHost{}
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	name, err := InterfaceName(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	kernel.target = observedLink{} // migrated original: absent in this ns
	ctx, err := core.WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	err = b.rollbackCreatedInterface(ctx, link, name, creationProgress{
		Created: true, Marked: true, IfIndex: 17,
	})
	if err == nil || kernel.deletedInterfaces != 0 {
		t.Fatal("rollback promoted namespace-local absence into a WG deletion witness")
	}
}
