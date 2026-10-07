package app

import (
	"context"

	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// RestoreAll reapplies every persisted desired Link through the same idempotent
// Ensure lifecycle used by normal operations. It intentionally does not create
// a second persistence-specific mutation path. Results completed before a
// failure are returned so callers can report deterministic partial progress.
func (e *Engine) RestoreAll(ctx context.Context) ([]Result, error) {
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "cannot load persisted Links", err)
	}

	results := make([]Result, 0, len(snapshot.Links))
	for _, record := range snapshot.Links {
		result, err := e.Ensure(ctx, record.Desired)
		if err != nil {
			return results, contextualize(err, stlerr.CodeApply, "restore", record.Desired, "cannot restore persisted Link")
		}
		results = append(results, result)
	}
	return results, nil
}
