package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// SpoofRPFilterChange describes the actual prospective Linux value, including
// host-global "all" changes that can also affect unrelated services.
type SpoofRPFilterChange struct {
	Interface string `json:"interface"`
	Current   int    `json:"current"`
	Proposed  int    `json:"proposed"`
}

type SpoofRPFilterPlan struct {
	LinkID          domain.LinkID         `json:"link_id"`
	Interface       string                `json:"interface"`
	Mode            string                `json:"requested_mode"`
	EffectiveBefore int                   `json:"effective_before"`
	EffectiveAfter  int                   `json:"effective_after"`
	Changes         []SpoofRPFilterChange `json:"changes"`
	GlobalImpact    bool                  `json:"global_impact"`
	ExistingOwners  int                   `json:"other_managed_links"`
	Note            string                `json:"note"`
}

// SpoofRPFilterManager owns the operator-confirmed exception to the ordinary
// read-only sysctl policy. The Engine alone owns its Link and maintenance
// admission; the manager serializes the shared host settings separately.
type SpoofRPFilterManager interface {
	Preview(context.Context, state.Snapshot, domain.LinkID, string, string) (SpoofRPFilterPlan, error)
	Apply(context.Context, state.Store, domain.LinkID, string, string) (SpoofRPFilterPlan, error)
	Release(context.Context, state.Store, domain.LinkID) error
	Reconcile(context.Context, state.Store) error
}

func (e *Engine) SetSpoofRPFilterManager(manager SpoofRPFilterManager) { e.spoofRPFilter = manager }

func (e *Engine) PreviewSpoofRPFilter(ctx context.Context, id domain.LinkID, iface, mode string) (SpoofRPFilterPlan, error) {
	if e.spoofRPFilter == nil {
		return SpoofRPFilterPlan{}, errors.New("Spoof rp_filter manager unavailable")
	}
	if err := id.Validate(); err != nil {
		return SpoofRPFilterPlan{}, err
	}
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return SpoofRPFilterPlan{}, err
	}
	if record, found := snapshot.Find(id); !found || record.Desired.Backend != domain.BackendSpoof {
		return SpoofRPFilterPlan{}, errors.New("rp_filter preview requires an existing Spoof Link")
	}
	return e.spoofRPFilter.Preview(ctx, snapshot, id, iface, mode)
}

func (e *Engine) ConfigureSpoofRPFilter(ctx context.Context, id domain.LinkID, iface, mode string) (SpoofRPFilterPlan, error) {
	if e.spoofRPFilter == nil {
		return SpoofRPFilterPlan{}, errors.New("Spoof rp_filter manager unavailable")
	}
	if err := id.Validate(); err != nil {
		return SpoofRPFilterPlan{}, err
	}
	maintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return SpoofRPFilterPlan{}, err
	}
	defer maintenance()
	unlock, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return SpoofRPFilterPlan{}, err
	}
	defer unlock()
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return SpoofRPFilterPlan{}, err
	}
	if record, found := snapshot.Find(id); !found || record.Desired.Backend != domain.BackendSpoof {
		return SpoofRPFilterPlan{}, errors.New("rp_filter change requires an existing Spoof Link")
	}
	return e.spoofRPFilter.Apply(ctx, e.store, id, iface, mode)
}

func (e *Engine) RestoreSpoofRPFilter(ctx context.Context, id domain.LinkID) error {
	if e.spoofRPFilter == nil {
		return errors.New("Spoof rp_filter manager unavailable")
	}
	if err := id.Validate(); err != nil {
		return err
	}
	maintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return err
	}
	defer maintenance()
	unlock, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return err
	}
	defer unlock()
	if err := e.spoofRPFilter.Release(ctx, e.store, id); err != nil {
		return fmt.Errorf("Spoof rp_filter cleanup pending; retry link rp-filter restore: %w", err)
	}
	return nil
}
