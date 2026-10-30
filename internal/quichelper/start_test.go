package quichelper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"github.com/ach1992/simple-tun-link/internal/quicwgorigin"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

const fixtureID domain.LinkID = "lnk_0123456789abcdef0123456789abcdef"
const fixtureNonce = "0123456789abcdef0123456789abcdef"

type originFixture struct {
	root                         string
	plan                         quic.Plan
	op                           state.QUICCrashOperation
	ops                          originalOps
	starts, observes, preflights int
	lastSpec                     unitSpec
}

func newOriginFixture(t *testing.T) *originFixture {
	t.Helper()
	f := &originFixture{root: filepath.Join(t.TempDir(), "state")}
	if err := os.Mkdir(f.root, 0o700); err != nil {
		t.Fatal(err)
	}
	creds, err := credentials.OpenProtected(f.root, true)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(creds)
	binary := filepath.Join(t.TempDir(), "fixture-executable")
	raw := []byte("non-executable test-only original identity\n")
	if err := os.WriteFile(binary, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(binary, &st); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	key, public, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key.Zeroize()
	peerKey, peer, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peerKey.Zeroize()
	f.plan = quic.Plan{LinkID: fixtureID, Role: quic.Listen, Underlay: netip.MustParseAddrPort("198.51.100.60:443"), TLSName: "198.51.100.60", LocalWGUDPPort: 51820}
	hostPlan, err := f.plan.HostPlan(51820)
	if err != nil {
		t.Fatal(err)
	}
	f.op = state.QUICCrashOperation{Plan: hostPlan, Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.81.22.0/31"), Peer: netip.MustParsePrefix("10.81.22.1/31")}, WireGuard: domain.WireGuardOptions{LocalPublicKey: public, PeerPublicKey: peer, ListenPort: 51820, PeerPort: 51821}, Nonce: fixtureNonce,
		CertificateSHA256: strings.Repeat("a", 64), TrustCASHA256: strings.Repeat("b", 64), AuthorizationSHA256: strings.Repeat("c", 64), HelperConfigSHA256: strings.Repeat("d", 64), ExecutablePath: binary, ExecutableSHA256: hex.EncodeToString(sum[:]), ExecutableDevice: uint64(st.Dev), ExecutableInode: st.Ino}
	provider, err := composition.WireGuardProviderClaims(fixtureID, f.op.Addresses.Local, f.op.WireGuard)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := f.plan.CarrierClaims(51820)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, claim := range append(provider, carrier...) {
		if !seen[claim.Canonical()] {
			f.op.Resources = append(f.op.Resources, claim)
			seen[claim.Canonical()] = true
		}
	}
	if err := f.op.Validate(); err != nil {
		t.Fatal(err)
	}
	host := hostIdentity{BootID: "11111111-2222-3333-4444-555555555555", NetworkNS: "net:[4026532999]", MountNS: "mnt:[2]", PIDNS: "pid:[3]", UserNS: "user:[4]", ManagerStartTime: 1}
	wg := quicwgorigin.OriginalObservation{LinkID: fixtureID, StagingName: "q123", IfIndex: 4, KernelBootID: host.BootID, NetworkNS: host.NetworkNS, ReceiptDevice: 1, ReceiptInode: 2, GuardReceiptDevice: 3, GuardReceiptInode: 4, KeyDevice: 5, KeyInode: 6}
	clock := uint64(100)
	f.ops = originalOps{
		preflight: func(_ context.Context, s unitSpec) (hostIdentity, error) {
			f.preflights++
			f.lastSpec = s
			return host, nil
		},
		start: func(_ context.Context, s unitSpec) error {
			f.starts++
			f.lastSpec = s
			info, err := os.Stat(filepath.Join(f.root, "credentials", markerDirectory, attemptName(fixtureID)))
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("start happened before durable protected attempt")
			}
			return nil
		},
		observe: func(_ context.Context, s unitSpec) (*processPin, error) {
			f.observes++
			fd, err := unix.PidfdOpen(os.Getpid(), 0)
			if err != nil {
				t.Fatal(err)
			}
			return &processPin{fd: fd, Observation: processObservation{PID: os.Getpid(), StartTime: 1, InvocationID: strings.Repeat("a", 32), ControlGroup: "/system.slice/" + s.Name, NetworkNS: host.NetworkNS, ExecutableDevice: uint64(st.Dev), ExecutableInode: st.Ino, StartMonotonicUSec: 150}}, nil
		},
		host: func() (hostIdentity, error) { return host, nil }, wg: func(context.Context, string, domain.LinkID, string, domain.WireGuardOptions) (quicwgorigin.OriginalObservation, error) {
			return wg, nil
		},
		material: func(_ context.Context, _ string, _ quic.Plan, _ state.QUICCrashOperation, fn func() error) error {
			return fn()
		}, checkMaterial: func(string, quic.Plan, state.QUICCrashOperation) error { return nil },
		openExecutable: func(op state.QUICCrashOperation) (*os.File, pinnedexec.Identity, error) {
			return pinnedexec.Open(op.ExecutablePath, op.ExecutableSHA256)
		}, now: func() (uint64, error) { v := clock; clock += 100; return v, nil },
	}
	return f
}

func markerExists(t *testing.T, f *originFixture, birth bool) bool {
	t.Helper()
	name := attemptName(fixtureID)
	if birth {
		name = birthName(fixtureID)
	}
	_, err := os.Lstat(filepath.Join(f.root, "credentials", markerDirectory, name))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestOriginalStartPersistsAttemptThenBirthAndNeverReplays(t *testing.T) {
	f := newOriginFixture(t)
	got, err := startAdmitted(context.Background(), f.root, f.plan, f.op, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	if got.LinkID != fixtureID || got.PID != os.Getpid() || f.starts != 1 || f.observes != 2 || !markerExists(t, f, false) || !markerExists(t, f, true) {
		t.Fatalf("original first-start evidence incomplete: %+v", got)
	}
	if !strings.HasPrefix(f.lastSpec.Binary, "/proc/") || !strings.Contains(f.lastSpec.Binary, "/fd/") {
		t.Fatal("start reopened executable by canonical path")
	}
	// Even if the external service has now disappeared, a recorded first
	// attempt cannot become a new original creation on the same journal.
	if _, err := startAdmitted(context.Background(), f.root, f.plan, f.op, f.ops); err == nil {
		t.Fatal("replayed original start")
	}
	if f.starts != 1 || f.preflights != 1 {
		t.Fatal("retry reached manager after protected attempt existed")
	}
}

func TestOriginalStartUncertainFailureKeepsAttemptWithoutBirth(t *testing.T) {
	for _, failure := range []string{"start", "process", "material", "guard", "host", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			f := newOriginFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sensitive := "sensitive-upstream-output-must-not-escape"
			switch failure {
			case "start":
				prior := f.ops.start
				f.ops.start = func(c context.Context, s unitSpec) error { _ = prior(c, s); return errors.New(sensitive) }
			case "process":
				f.ops.observe = func(context.Context, unitSpec) (*processPin, error) { return nil, errors.New(sensitive) }
			case "material":
				prior := f.ops.checkMaterial
				calls := 0
				f.ops.checkMaterial = func(r string, p quic.Plan, o state.QUICCrashOperation) error {
					calls++
					if calls == 2 {
						return errors.New(sensitive)
					}
					return prior(r, p, o)
				}
			case "guard":
				prior := f.ops.wg
				calls := 0
				f.ops.wg = func(c context.Context, r string, id domain.LinkID, n string, w domain.WireGuardOptions) (quicwgorigin.OriginalObservation, error) {
					calls++
					v, e := prior(c, r, id, n, w)
					if calls > 1 {
						v.GuardReceiptInode++
					}
					return v, e
				}
			case "host":
				prior := f.ops.host
				calls := 0
				f.ops.host = func() (hostIdentity, error) {
					calls++
					v, e := prior()
					if calls > 1 {
						v.ManagerStartTime++
					}
					return v, e
				}
			case "cancel":
				prior := f.ops.start
				f.ops.start = func(c context.Context, s unitSpec) error { err := prior(c, s); cancel(); return err }
			}
			_, err := startAdmitted(ctx, f.root, f.plan, f.op, f.ops)
			if err == nil || strings.Contains(err.Error(), sensitive) {
				t.Fatalf("uncertain failure accepted or sensitive error exposed: %v", err)
			}
			if f.starts != 1 || !markerExists(t, f, false) || markerExists(t, f, true) {
				t.Fatalf("uncertain first start lost quarantine or wrote birth: %d", f.starts)
			}
			if _, err := startAdmitted(context.Background(), f.root, f.plan, f.op, f.ops); err == nil || f.starts != 1 {
				t.Fatal("uncertain original attempt was replayed")
			}
		})
	}
}

func TestOriginalStartCancellationAndForeignPreflightHaveNoStartAttempt(t *testing.T) {
	for _, cancelAt := range []string{"entry", "preflight"} {
		t.Run(cancelAt, func(t *testing.T) {
			f := newOriginFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelAt == "entry" {
				cancel()
			} else {
				prior := f.ops.preflight
				f.ops.preflight = func(c context.Context, s unitSpec) (hostIdentity, error) {
					host, err := prior(c, s)
					cancel()
					return host, err
				}
			}
			if _, err := startAdmitted(ctx, f.root, f.plan, f.op, f.ops); err == nil {
				t.Fatal("canceled start admitted")
			}
			if f.starts != 0 || markerExists(t, f, false) {
				t.Fatal("pre-effect cancellation created an attempt or started helper")
			}
		})
	}
	f := newOriginFixture(t)
	f.ops.preflight = func(context.Context, unitSpec) (hostIdentity, error) {
		return hostIdentity{}, errors.New("foreign drop-in")
	}
	if _, err := startAdmitted(context.Background(), f.root, f.plan, f.op, f.ops); err == nil || f.starts != 0 || markerExists(t, f, false) {
		t.Fatal("foreign preflight reached first-start effect")
	}
}

func TestOriginalStartSameByteAttemptReplacementFailsClosed(t *testing.T) {
	f := newOriginFixture(t)
	prior := f.ops.start
	f.ops.start = func(c context.Context, s unitSpec) error {
		if err := prior(c, s); err != nil {
			return err
		}
		path := filepath.Join(f.root, "credentials", markerDirectory, attemptName(fixtureID))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	if _, err := startAdmitted(context.Background(), f.root, f.plan, f.op, f.ops); err == nil {
		t.Fatal("same-byte substituted attempt accepted")
	}
	if !markerExists(t, f, false) || markerExists(t, f, true) {
		t.Fatal("substitution removed quarantine or created birth")
	}
}

func TestOriginalStartPartialOrForeignMarkerNeverPermitsStart(t *testing.T) {
	for _, kind := range []string{"partial", "symlink", "birth-only"} {
		t.Run(kind, func(t *testing.T) {
			f := newOriginFixture(t)
			store, err := openMarkers(f.root)
			if err != nil {
				t.Fatal(err)
			}
			store.close()
			path := filepath.Join(f.root, "credentials", markerDirectory, attemptName(fixtureID))
			switch kind {
			case "partial":
				err = os.WriteFile(path, []byte("{"), 0o600)
			case "symlink":
				err = os.Symlink("/does-not-exist", path)
			case "birth-only":
				err = os.WriteFile(filepath.Join(filepath.Dir(path), birthName(fixtureID)), []byte("{}"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := startAdmitted(context.Background(), f.root, f.plan, f.op, f.ops); err == nil || f.starts != 0 || f.preflights != 0 {
				t.Fatal("existing uncertain evidence permitted fresh manager attempt")
			}
		})
	}
}
