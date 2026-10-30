package quichelper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"github.com/ach1992/simple-tun-link/internal/quicwgorigin"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// OriginalObservation describes this call's positive first-start witness.
// It does not grant stop/restart, continued-lifetime, restore or retirement
// authority. A committed, operational private L3 Link is still not created.
type OriginalObservation struct {
	LinkID                                      domain.LinkID
	Unit, InvocationID, KernelBootID, NetworkNS string
	PID                                         int
	ProcessStartTime, StartedMonotonicUSec      uint64
}

// StartOriginal is deliberately not wired to a public backend or CLI. The
// only production entry uses the canonical immutable journal/Engine locks,
// exact protected material, original guarded DOWN WG witness, and fixed
// local system-manager adapter. Every attempt is CREATE-only and durable
// before start. Failure leaves all possible effects quarantined; there is
// no retry, adoption, Stop, Restart, ResetFailed, Collect or cleanup API.
func StartOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID) (OriginalObservation, error) {
	if ctx == nil || engine == nil || id.Validate() != nil {
		return OriginalObservation{}, fmt.Errorf("original QUIC helper requires canonical Engine admission")
	}
	var observation OriginalObservation
	err := engine.WithQUICCrashHelperAdmission(ctx, id, func(c context.Context, root string, plan quic.Plan, op state.QUICCrashOperation) error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var err error
		observation, err = startAdmitted(c, root, plan, op, productionOps())
		return err
	})
	if err != nil {
		return OriginalObservation{}, err
	}
	return observation, nil
}

// Injection is package-private and exists only for deterministic ordering,
// crash, drift and cancellation tests. The public entry always fixes ops.
type originalOps struct {
	preflight      func(context.Context, unitSpec) (hostIdentity, error)
	start          func(context.Context, unitSpec) error
	observe        func(context.Context, unitSpec) (*processPin, error)
	host           func() (hostIdentity, error)
	wg             func(context.Context, string, domain.LinkID, string, domain.WireGuardOptions) (quicwgorigin.OriginalObservation, error)
	material       func(context.Context, string, quic.Plan, state.QUICCrashOperation, func() error) error
	checkMaterial  func(string, quic.Plan, state.QUICCrashOperation) error
	openExecutable func(state.QUICCrashOperation) (*os.File, pinnedexec.Identity, error)
	now            func() (uint64, error)
}

func expectedMaterial(op state.QUICCrashOperation) quic.HelperConfigIdentity {
	return quic.HelperConfigIdentity{
		ConfigSHA256: op.HelperConfigSHA256, Credentials: quic.CredentialIdentity{CertificateSHA256: op.CertificateSHA256, TrustCASHA256: op.TrustCASHA256, AuthorizationSHA256: op.AuthorizationSHA256, ObfuscationSHA256: op.ObfuscationSHA256},
		Executable: pinnedexec.Identity{SHA256: op.ExecutableSHA256, Device: op.ExecutableDevice, Inode: op.ExecutableInode}}
}

func productionOps() originalOps {
	h := systemdHost{}
	return originalOps{preflight: h.preflight, start: h.start, observe: h.observe, host: currentHostIdentity, wg: quicwgorigin.VerifyRecordedOriginalWithinAdmission, now: monotonicUSec,
		openExecutable: func(op state.QUICCrashOperation) (*os.File, pinnedexec.Identity, error) {
			approved, err := quic.InspectPinnedHysteria(op.ExecutablePath)
			if err != nil || approved != expectedMaterial(op).Executable {
				return nil, pinnedexec.Identity{}, fmt.Errorf("official QUIC executable identity differs")
			}
			return pinnedexec.Open(op.ExecutablePath, op.ExecutableSHA256)
		},
		material: func(ctx context.Context, root string, p quic.Plan, op state.QUICCrashOperation, perform func() error) error {
			return quic.WithPinnedJournalGeneration(ctx, root, p, op.WireGuard.ListenPort, op.ExecutablePath, op.Nonce, expectedMaterial(op), perform)
		},
		checkMaterial: func(root string, p quic.Plan, op state.QUICCrashOperation) error {
			got, err := quic.InspectJournalGeneration(root, p, op.WireGuard.ListenPort, op.ExecutablePath, op.Nonce, expectedMaterial(op))
			if err != nil || got != expectedMaterial(op) {
				return fmt.Errorf("original QUIC protected generation differs")
			}
			return nil
		},
	}
}

func startAdmitted(ctx context.Context, root string, plan quic.Plan, op state.QUICCrashOperation, ops originalOps) (OriginalObservation, error) {
	fail := func(stage string) (OriginalObservation, error) {
		return OriginalObservation{}, fmt.Errorf("original QUIC helper %s failed or uncertain; preserve attempt, possible helper and journal", stage)
	}
	if ctx == nil || ctx.Err() != nil || ops.preflight == nil || ops.start == nil || ops.observe == nil || ops.host == nil || ops.wg == nil || ops.material == nil || ops.checkMaterial == nil || ops.openExecutable == nil || ops.now == nil {
		return fail("admission")
	}
	if op.Validate() != nil {
		return fail("journal validation")
	}
	projected, err := plan.HostPlan(op.WireGuard.ListenPort)
	if err != nil || projected != op.Plan {
		return fail("plan identity")
	}
	spec, err := buildUnitSpec(plan, op.Nonce, op.ExecutablePath, root)
	if err != nil {
		return fail("unit planning")
	}
	store, err := openMarkers(root)
	if err != nil {
		return fail("marker admission")
	}
	defer store.close()
	if err := store.vacant(plan.LinkID); err != nil {
		return fail("attempt already exists or vacancy")
	}
	executable, identity, err := ops.openExecutable(op)
	if err != nil || executable == nil || identity != expectedMaterial(op).Executable {
		if executable != nil {
			executable.Close()
		}
		return fail("executable pin")
	}
	defer executable.Close()
	// systemd opens the still-held descriptor through this live caller's proc
	// entry. It never reopens the canonical executable between inspection and
	// exec. The ephemeral path is recorded only as first-start evidence.
	spec.Binary = "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(executable.Fd()), 10)
	var result OriginalObservation
	var retained *processPin
	defer func() {
		if retained != nil {
			_ = retained.Close()
		}
	}()
	err = ops.material(ctx, root, plan, op, func() error {
		stageFail := func(stage string) error { _, e := fail(stage); return e }
		host, err := ops.preflight(ctx, spec)
		if err != nil {
			return stageFail("manager preflight")
		}
		wg, err := ops.wg(ctx, root, plan.LinkID, op.Nonce, op.WireGuard)
		if err != nil || wg.KernelBootID != host.BootID || wg.NetworkNS != host.NetworkNS {
			return stageFail("original guard and WG observation")
		}
		journalRaw, err := json.Marshal(op)
		if err != nil {
			return stageFail("journal identity")
		}
		digest := sha256.Sum256(journalRaw)
		bound, err := ops.now()
		if err != nil || bound == 0 {
			return stageFail("start bound")
		}
		attempt := attemptMarker{SchemaVersion: 1, LinkID: plan.LinkID, Nonce: op.Nonce, JournalSHA256: hex.EncodeToString(digest[:]), Unit: spec.Name, Description: spec.Description, LaunchPath: spec.Binary,
			CanonicalExecutable: op.ExecutablePath, Executable: identity, Host: host, WireGuard: wg, StartedAfterUSec: bound}
		if ctx.Err() != nil {
			return stageFail("pre-attempt cancellation")
		}
		attemptPin, err := store.writeAttempt(attempt)
		if err != nil {
			return stageFail("durable attempt publication")
		}
		defer attemptPin.Close()
		// The marker survives every failure from here, even if systemd never
		// received the start or later reports the unit entirely absent.
		if ctx.Err() != nil || ops.checkMaterial(root, plan, op) != nil {
			return stageFail("pre-start material or cancellation")
		}
		again, err := ops.host()
		if err != nil || again != host || store.verifyAttempt(attempt, attemptPin) != nil {
			return stageFail("pre-start manager or attempt drift")
		}
		if err := ops.start(ctx, spec); err != nil {
			return stageFail("first-start dispatch")
		}
		pin, err := ops.observe(ctx, spec)
		if err != nil || pin == nil {
			return stageFail("original process readback")
		}
		retained = pin
		now, err := ops.now()
		p := pin.Observation
		if err != nil || p.StartMonotonicUSec < bound || p.StartMonotonicUSec > now || p.ExecutableDevice != identity.Device || p.ExecutableInode != identity.Inode || p.NetworkNS != host.NetworkNS || pin.alive() != nil {
			return stageFail("original process binding")
		}
		postWG, err := ops.wg(ctx, root, plan.LinkID, op.Nonce, op.WireGuard)
		if err != nil || postWG != wg {
			return stageFail("post-start original guard or WG drift")
		}
		postHost, err := ops.host()
		if err != nil || postHost != host || ops.checkMaterial(root, plan, op) != nil || ctx.Err() != nil {
			return stageFail("post-start manager or material drift")
		}
		if store.verifyAttempt(attempt, attemptPin) != nil || pin.alive() != nil {
			return stageFail("pre-receipt original witness")
		}
		birth := birthMarker{SchemaVersion: 1, Attempt: attempt, Process: p}
		birthPin, err := store.writeBirth(birth)
		if err != nil {
			return stageFail("original birth receipt publication")
		}
		defer birthPin.Close()
		last, err := ops.observe(ctx, spec)
		if err != nil || last == nil {
			return stageFail("post-receipt process observation")
		}
		defer last.Close()
		if last.Observation != p || pin.alive() != nil || store.verifyBirth(birth, birthPin) != nil || store.verifyAttempt(attempt, attemptPin) != nil || ctx.Err() != nil {
			return stageFail("final original receipt or process drift")
		}
		result = OriginalObservation{LinkID: plan.LinkID, Unit: spec.Name, InvocationID: p.InvocationID, KernelBootID: host.BootID, NetworkNS: host.NetworkNS, PID: p.PID, ProcessStartTime: p.StartTime, StartedMonotonicUSec: p.StartMonotonicUSec}
		return nil
	})
	if err != nil {
		return OriginalObservation{}, err
	}
	if retained == nil || retained.alive() != nil {
		return fail("final original process liveness")
	}
	return result, nil
}
