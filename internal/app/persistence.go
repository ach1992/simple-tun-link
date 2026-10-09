package app

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// RestorePersistence owns one host-wide reboot restore mechanism. A separate
// persistence mechanism is optional: on hosts without systemd, the engine can
// still manage Links in manual/non-persistent mode.
type RestorePersistence interface {
	EnsureRestore(context.Context, string) (func(context.Context) error, bool, error)
	RemoveRestore(context.Context) error
	IsRestoreInstalled(context.Context) (bool, error)
}

// NewWithRestorePersistence attaches reboot persistence to the canonical
// Ensure/Remove engine. The restore command uses this same engine rather than
// introducing a second lifecycle implementation.
func NewWithRestorePersistence(backends *backend.Registry, store state.Store, locks Locker, manager RestorePersistence, executable string) (*Engine, error) {
	if manager == nil || executable == "" {
		return nil, fmt.Errorf("restore persistence manager and executable are required")
	}
	engine, err := New(backends, store, locks)
	if err != nil {
		return nil, err
	}
	engine.restorePersistence = manager
	engine.restoreExecutable = executable
	return engine, nil
}
