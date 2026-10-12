// Real canonical Engine IPsec lifecycle exercised ONLY in an isolated,
// network-disconnected, disposable two-peer Docker integration fixture.
// This is not a production installer or alternative user-facing CLI.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const fixtureRoot = "/run/stl-ipsec-proof"

type laboratoryAdmission struct{ side string }

func (a laboratoryAdmission) Authorize(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil ||
		os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_ENGINE_FIXTURE") != "approved" ||
		os.Geteuid() != 0 {
		return fmt.Errorf("isolated laboratory authority unavailable")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return fmt.Errorf("disposable container marker missing")
	}
	dir, err := os.Lstat(fixtureRoot)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0o700 ||
		dir.Sys() == nil {
		return fmt.Errorf("protected laboratory runtime directory unavailable")
	}
	// The only accepted daemon for side 'a' or 'b' was launched in this
	// network namespace by the disconnected fixture, from its own reviewed
	// config. Never use this admission in production: package/systemd
	// provenance is deliberately separate and has not been attested here.
	pidRaw, err := os.ReadFile(fixtureRoot + "/" + a.side + ".pid")
	if err != nil {
		return fmt.Errorf("owned fixture daemon identity missing")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidRaw)))
	if err != nil || pid < 2 {
		return fmt.Errorf("owned fixture daemon identity invalid")
	}
	selfNS, err1 := os.Readlink("/proc/self/ns/net")
	daemonNS, err2 := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err1 != nil || err2 != nil || selfNS != daemonNS {
		return fmt.Errorf("fixture daemon is outside current peer namespace")
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || filepath.Base(exe) != "charon-systemd" {
		return fmt.Errorf("fixture daemon executable identity invalid")
	}
	environment, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil || !strings.Contains(string(environment),
		"STRONGSWAN_CONF="+fixtureRoot+"/"+a.side+".conf\x00") {
		return fmt.Errorf("fixture daemon runtime configuration is not exact")
	}
	socket := fixtureRoot + "/" + a.side + ".vici"
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 ||
		info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("fixture VICI socket unavailable")
	}
	return nil
}

func link(suffix, side, encap string) domain.Link {
	a := side == "a"
	first, second := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	addrA, addrB := netip.MustParsePrefix("10.251.88.0/31"), netip.MustParsePrefix("10.251.88.1/31")
	if suffix == "b" {
		addrA, addrB = netip.MustParsePrefix("10.251.88.2/31"), netip.MustParsePrefix("10.251.88.3/31")
	}
	if !a {
		first, second = second, first
		addrA, addrB = addrB, addrA
	}
	return domain.Link{
		ID:            domain.LinkID("lnk_" + strings.Repeat(suffix, 32)),
		Backend:       domain.BackendIPsec,
		Encapsulation: domain.Encapsulation(encap),
		Underlay:      domain.Underlay{Local: first, Peer: second},
		Addresses:     domain.LinkAddresses{Local: addrA, Peer: addrB},
	}
}

func main() {
	if err := run(); err != nil {
		// No raw untrusted kernel/VICI/secret errors may ever reach stdout.
		fmt.Fprintln(os.Stderr, "ENGINE_IPSEC_FIXTURE_ERROR: operation rejected or not confirmed")
		os.Exit(1)
	}
}

func run() (operationErr error) {
	phase := "fixture_input"
	defer func() {
		if operationErr != nil {
			fmt.Fprintf(os.Stderr, "ENGINE_IPSEC_FAILED_STAGE=%s CODE=%s\n", phase, stlerr.CodeOf(operationErr))
			if os.Getenv("STL_IPSEC_LAB_TRACE") == "approved" {
				// Laboratory-only, independent fixture diagnostics. Never
				// transmit raw VICI frames, private PSKs or kernel SA keys.
				fmt.Fprintf(os.Stderr, "ENGINE_LAB_SAFE_ERROR=%s\n", operationErr)
			}
		}
	}()
	if len(os.Args) != 5 {
		return errors.New("usage: peer OPERATION a|b a|b esp|nat-t")
	}
	op, side, suffix, enc := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	if (side != "a" && side != "b") || (suffix != "a" && suffix != "b") ||
		(enc != "esp" && enc != "nat-t") {
		return fmt.Errorf("invalid bounded fixture identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	admit := laboratoryAdmission{side: side}
	phase = "lab_admission"
	if err := admit.Authorize(ctx); err != nil {
		return err
	}
	l := link(suffix, side, enc)
	if err := l.Validate(); err != nil {
		return err
	}
	stateRoot := fixtureRoot + "/engine-state-" + side
	phase = "runtime_assembly"
	keys, err := ipsec.NewPSKStore(stateRoot)
	if err != nil {
		return err
	}
	writer, err := ipsec.NewScopedWriter(fixtureRoot + "/" + side + ".vici")
	if err != nil {
		return err
	}
	runner := linux.ExecRunner{}
	impl, err := ipsec.NewOperationalBackend(ipsec.OperationalOptions{
		Admission: admit, Keys: keys, Writer: writer,
		Runner: ipsec.BoundedExecRunner{},
		Routes: ipsec.HostRouteResolveFunc(func(ctx context.Context, peer netip.Addr) (ipsec.HostRoute, error) {
			resolved, err := (linux.RouteResolver{Runner: runner}).Resolve(ctx, peer)
			if err != nil {
				return ipsec.HostRoute{}, err
			}
			return ipsec.HostRoute{Source: resolved.Source, Device: resolved.Device}, nil
		}),
		XFRM:     ipsec.NewXFRMVacancyInspector("ip"),
		SetAlias: linux.SetLinkAliasByIndex, AddAddr: linux.AddIPv4AddressByIndex,
		SetUp: linux.SetLinkUpByIndex, Delete: linux.DeleteLinkByIndex,
	})
	if err != nil {
		return err
	}
	registry, err := backend.NewRegistry(impl)
	if err != nil {
		return err
	}
	engine, err := app.New(registry, state.NewFileStore(stateRoot), state.NewLockManager(stateRoot))
	if err != nil {
		return err
	}
	secretFile := fixtureRoot + "/" + suffix + ".secret"
	handoffFile := fixtureRoot + "/" + suffix + ".handoff"
	switch op {
	case "create":
		if side != "a" {
			return errors.New("only A creates Quick Link")
		}
		secret, err := os.ReadFile(secretFile)
		if err != nil || len(secret) != 32 {
			return errors.New("fixture PSK unavailable")
		}
		defer clear(secret)
		offer, err := pairing.NewQuickOffer(l, secret)
		if err != nil {
			return err
		}
		defer offer.ClearRecipientCredential()
		phase = "stage_sender"
		if err := engine.StageIPsecSender(ctx, offer, keys, func(url string) error {
			// Sensitive handoff is never stdout, ordinary JSON or a log.
			fd, err := os.OpenFile(handoffFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			defer fd.Close()
			if _, err = fd.WriteString(url); err != nil {
				return err
			}
			return fd.Sync()
		}); err != nil {
			return err
		}
		phase = "activate_" + side
		if os.Getenv("STL_IPSEC_LAB_TRACE") == "approved" {
			req := backend.Request{Operation: backend.OperationEnsure, Link: l}
			observed, inspectErr := impl.Inspect(ctx, l)
			if inspectErr != nil {
				fmt.Fprintln(os.Stderr, "LAB_PRECHECK_INSPECT", inspectErr)
			}
			if inspectErr == nil {
				planned, planErr := impl.Plan(ctx, req, observed)
				if planErr != nil {
					fmt.Fprintln(os.Stderr, "LAB_PRECHECK_PLAN", planErr)
				}
				if planErr == nil {
					if validErr := impl.Validate(ctx, req, observed, planned); validErr != nil {
						fmt.Fprintln(os.Stderr, "LAB_PRECHECK_VALIDATE", validErr)
						if profile, profileErr := ipsec.NewProfile(l); profileErr == nil {
							fmt.Fprintln(os.Stderr, "LAB_XFRM_VACANCY", impl.XFRM.RequireVacant(ctx, profile))
						}
					}
				}
			}
		}
		if _, err := engine.ActivateStagedIPsec(ctx, l.ID); err != nil {
			return err
		}
	case "import", "import-mismatch":
		if side != "b" {
			return errors.New("only B imports Quick Link")
		}
		handoff, err := os.ReadFile(handoffFile)
		if err != nil {
			return errors.New("sensitive handoff missing")
		}
		defer clear(handoff)
		encoded := string(handoff)
		if op == "import-mismatch" {
			// Deliberately corrupt the received PSK while preserving the
			// same public peer identity: the confirmed transcript itself
			// changes, and IKE must refuse authentication.
			bad, err := os.ReadFile(fixtureRoot + "/" + suffix + "-mismatch.secret")
			if err != nil || len(bad) != 32 {
				return errors.New("negative-test PSK unavailable")
			}
			defer clear(bad)
			offer, err := pairing.NewQuickOffer(link(suffix, "a", enc), bad)
			if err != nil {
				return err
			}
			defer offer.ClearRecipientCredential()
			encoded, err = offer.EncodeSetupLink()
			if err != nil {
				return err
			}
		}
		sum := sha256.Sum256([]byte(encoded))
		phase = "stage_recipient"
		if err := engine.StageIPsecRecipient(ctx, encoded, hex.EncodeToString(sum[:]), keys); err != nil {
			return err
		}
		phase = "activate_" + side
		if os.Getenv("STL_IPSEC_LAB_TRACE") == "approved" {
			req := backend.Request{Operation: backend.OperationEnsure, Link: l}
			observed, inspectErr := impl.Inspect(ctx, l)
			if inspectErr != nil {
				fmt.Fprintln(os.Stderr, "LAB_PRECHECK_INSPECT", inspectErr)
			}
			if inspectErr == nil {
				planned, planErr := impl.Plan(ctx, req, observed)
				if planErr != nil {
					fmt.Fprintln(os.Stderr, "LAB_PRECHECK_PLAN", planErr)
				}
				if planErr == nil {
					if validErr := impl.Validate(ctx, req, observed, planned); validErr != nil {
						fmt.Fprintln(os.Stderr, "LAB_PRECHECK_VALIDATE", validErr)
						if profile, profileErr := ipsec.NewProfile(l); profileErr == nil {
							fmt.Fprintln(os.Stderr, "LAB_XFRM_VACANCY", impl.XFRM.RequireVacant(ctx, profile))
						}
					}
				}
			}
		}
		if _, err := engine.ActivateStagedIPsec(ctx, l.ID); err != nil {
			return err
		}
	case "ensure":
		phase = "ensure"
		r, err := engine.Ensure(ctx, l)
		if err != nil {
			return err
		}
		if r.Changed {
			fmt.Printf("ENGINE_IPSEC_REAPPLY_CHANGED=%v\n", r.Changed)
		}
	case "connect":
		phase = "connect"
		if err := engine.ConnectIPsec(ctx, l.ID); err != nil {
			return err
		}
	case "remove":
		phase = "remove"
		if _, err := engine.Remove(ctx, l.ID); err != nil {
			return err
		}
	case "status":
		phase = "status"
		s, err := state.NewFileStore(stateRoot).Load(ctx)
		if err != nil {
			return err
		}
		rec, ok := s.Find(l.ID)
		if !ok || rec.Desired != l {
			return errors.New("IPsec Link is not exactly committed")
		}
		if _, err := impl.Verify(ctx, backend.Request{Operation: backend.OperationEnsure, Link: rec.Desired, Prior: &rec.Desired, OwnedResources: rec.OwnedResources}); err != nil {
			return err
		}
	case "restore":
		phase = "restore"
		results, err := engine.RestoreAll(ctx)
		if err != nil {
			return err
		}
		_ = results
	default:
		return fmt.Errorf("unrecognized fixture operation")
	}
	fmt.Printf("ENGINE_IPSEC_%s_OK peer=%s link=%s encap=%s\n",
		strings.ToUpper(op), side, suffix, enc)
	return nil
}
