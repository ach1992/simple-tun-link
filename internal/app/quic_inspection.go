package app

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type QUICInspection = backend.QUICDiagnostic

// InspectQUIC binds read-only evidence to the exact protected committed owner
// under normal Engine locks. A missing object is a current observation, never
// permission to recreate it or a claim about other namespaces or peer traffic.
func (e *Engine) InspectQUIC(ctx context.Context, id domain.LinkID) (QUICInspection, error) {
	if ctx == nil || id.Validate() != nil {
		return QUICInspection{}, fmt.Errorf("invalid QUIC inspection")
	}
	maintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return QUICInspection{}, err
	}
	defer maintenance()
	release, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return QUICInspection{}, err
	}
	defer release()
	s, err := e.store.Load(ctx)
	if err != nil {
		return QUICInspection{}, err
	}
	r, ok := s.Find(id)
	if !ok || r.Desired.Backend != domain.BackendWireGuardQUIC || r.QUICGeneration.Validate(r.Desired) != nil {
		return QUICInspection{}, fmt.Errorf("committed managed QUIC owner unavailable")
	}
	if _, pending := s.FindQUICCrashOperation(id); pending {
		return QUICInspection{}, stlerr.New(stlerr.CodeConflict, "quic_inspect", string(id), "wireguard-quic", "QUIC operation is quarantined; no managed readiness claim")
	}
	claims, err := resourceLockClaims(r.OwnedResources)
	if err != nil {
		return QUICInspection{}, err
	}
	resources, err := e.locks.Acquire(ctx, claims)
	if err != nil {
		return QUICInspection{}, err
	}
	defer resources()
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return QUICInspection{}, err
	}
	current, ok := fresh.Find(id)
	if !ok || !sameQUICRecord(r, current) {
		return QUICInspection{}, fmt.Errorf("QUIC owner changed during inspection admission")
	}
	if _, pending := fresh.FindQUICCrashOperation(id); pending {
		return QUICInspection{}, fmt.Errorf("QUIC operation became quarantined")
	}
	ctx, err = e.quicInitialContext(ctx, r.Desired, r)
	if err != nil {
		return QUICInspection{}, err
	}
	impl, ok := e.backends.Get(domain.BackendWireGuardQUIC)
	if !ok {
		return QUICInspection{}, fmt.Errorf("managed QUIC backend unavailable")
	}
	observer, ok := impl.(interface {
		BeginQUIC(context.Context, domain.Link, *state.QUICGeneration) (context.Context, func() error, error)
		QUICDiagnostic(context.Context, domain.Link) (backend.QUICDiagnostic, error)
	})
	if !ok {
		return QUICInspection{}, fmt.Errorf("managed QUIC observation unavailable")
	}
	ctx, close, err := observer.BeginQUIC(ctx, r.Desired, &r.QUICGeneration)
	if err != nil {
		return QUICInspection{}, err
	}
	if close == nil {
		return QUICInspection{}, fmt.Errorf("QUIC observation scope unavailable")
	}
	defer close()
	return observer.QUICDiagnostic(ctx, r.Desired)
}
