package ipsec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type admittedAbsentIPsec struct {
	calls int
	fail  bool
}

func (a *admittedAbsentIPsec) Authorize(context.Context) error {
	a.calls++
	if a.fail {
		return errors.New("no admitted writer")
	}
	return nil
}

type vacantDeviceRunner struct{ calls []string }

func (r *vacantDeviceRunner) RunBounded(_ context.Context, _ CaptureLimits, binary string, args ...string) (CommandResult, error) {
	cmd := binary + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	if cmd != "ip -details -json link show" {
		return CommandResult{}, errors.New("no kernel mutations permitted")
	}
	return CommandResult{Stdout: []byte(`[{"ifname":"lo"},{"ifname":"eth0"}]`)}, nil
}

func TestIPsecMissingPSKVacantJournalFullReadOnlyProgressAndResume(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		for _, scenario := range []string{"complete", "interrupted-phase", "psk-reappears", "VICI-reappears", "foreign-SA", "admission-loss"} {
			t.Run(string(encap)+"/"+scenario, func(t *testing.T) {
				link := testIPsecLink(t, encap)
				profile, err := NewProfile(link)
				if err != nil {
					t.Fatal(err)
				}
				root := t.TempDir()
				if err := os.Chmod(root, 0o700); err != nil {
					t.Fatal(err)
				}
				keys, err := NewPSKStore(root)
				if err != nil {
					t.Fatal(err)
				}
				material := []byte("0123456789abcdef0123456789abcdef")
				if err := keys.PutNew(link.ID, material); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, "credentials", string(link.ID)+".ipsecpsk")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				a := &admittedAbsentIPsec{}
				r := &vacantDeviceRunner{}
				xfrm := goodXFRMFixture()
				stage := state.IPsecRemovePrepared
				advances := 0
				b := &OperationalBackend{OperationalOptions: OperationalOptions{Admission: a, Runner: r, Keys: keys,
					XFRM: XFRMVacancyInspector{Runner: xfrm.Run}, IPBinary: "ip"}}
				b.SetRemoveJournal(func(_ context.Context, p Profile) (RemovalCheckpoint, error) {
					if p != profile {
						t.Fatal("foreign journal profile")
					}
					return RemovalCheckpoint{Phase: stage}, nil
				}, func(_ context.Context, p Profile, from, to string) error {
					if p != profile || from != stage || !state.IPsecRemoveNextPhase(from, to) {
						t.Fatal("non-durable or out-of-order phase advance")
					}
					if scenario == "interrupted-phase" && advances == 3 {
						return errors.New("journal persistence fault")
					}
					stage = to
					advances++
					if scenario == "psk-reappears" && advances == 3 {
						if err := keys.PutNew(link.ID, material); err != nil {
							t.Fatal(err)
						}
					}
					if scenario == "foreign-SA" && advances == 3 {
						xfrm.rows["ip -json xfrm state"] = []byte(`[{"if_id":"untrusted"}]`)
					}
					if scenario == "admission-loss" && advances == 3 {
						a.fail = true
					}
					return nil
				})
				calls := 0
				inspect := func(_ context.Context, p Profile) (Snapshot, error) {
					calls++
					if p != profile {
						t.Fatal("foreign VICI reader")
					}
					if scenario == "VICI-reappears" && calls == 4 {
						return Snapshot{ConnectionNamePresent: true}, nil
					}
					return Snapshot{}, nil
				}
				plan := operationalPlan{Profile: profile, Claims: profile.ResourceClaims(), Remove: true, CredentialAbsent: true}
				undo, err := b.runJournalledVacantRemove(context.Background(), plan, inspect)
				if scenario == "complete" {
					if err != nil || undo == nil || stage != state.IPsecRemoveDeviceAbsent || advances != len(state.IPsecRemovePhases)-1 {
						t.Fatalf("no-effect Remove did not complete: phase=%s advances=%d err=%v", stage, advances, err)
					}
					if err := undo(context.Background()); err != nil {
						t.Fatal("no-op removal requested rollback key", err)
					}
				} else if err == nil || stage == state.IPsecRemoveDeviceAbsent {
					t.Fatalf("no-effect finalizer ignored %s: phase=%s error=%v", scenario, stage, err)
				}
				if scenario != "complete" && scenario != "psk-reappears" && scenario != "VICI-reappears" && scenario != "foreign-SA" && scenario != "admission-loss" && stage != state.IPsecRemoveIssuingConnection {
					t.Fatal("interrupted journal advanced through uncertain effect")
				}
				for _, cmd := range r.calls {
					if cmd != "ip -details -json link show" {
						t.Fatal("journal performed a host mutation", cmd)
					}
				}
				for _, cmd := range xfrm.called {
					if strings.Contains(cmd, "add") || strings.Contains(cmd, "del") || strings.Contains(cmd, "route") {
						t.Fatal("journal attempted a remote/host mutation", cmd)
					}
				}
				if a.calls == 0 || calls == 0 {
					t.Fatal("no fresh ownership observations")
				}
			})
		}
	}
}
