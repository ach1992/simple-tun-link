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
	observation := observation{WSSLink: link}
	ok, err := b.CrashHostVacant(context.Background(), observation)
	if err != nil || !ok {
		t.Fatalf("empty host was not proven vacant: %v", err)
	}
	kernel.others = []observedLink{{Exists: true, Name: "another-if", PublicKey: link.WireGuard.LocalPublicKey, ListenPort: 65532}}
	ok, err = b.CrashHostVacant(context.Background(), observation)
	if err != nil || ok {
		t.Fatalf("same private identity survived on another interface: vacant=%t err=%v", ok, err)
	}
	kernel.others = []observedLink{{Exists: true, Name: "another-if", PublicKey: "other", ListenPort: link.WireGuard.ListenPort}}
	ok, err = b.CrashHostVacant(context.Background(), observation)
	if err != nil || ok {
		t.Fatalf("reserved kernel UDP listener moved: vacant=%t err=%v", ok, err)
	}
	kernel.others = []observedLink{{Exists: true, Name: "untrusted if name", PublicKey: "other", ListenPort: 65531}}
	ok, err = b.CrashHostVacant(context.Background(), observation)
	if err == nil || ok {
		t.Fatalf("malformed global WG output verified absent: vacant=%t err=%v", ok, err)
	}
	observation.WSSLink = domain.Link{}
	if ok, err = b.CrashHostVacant(context.Background(), observation); err == nil || ok {
		t.Fatal("missing committed public WSS identity verified absent")
	}
}
