package main

import (
	"errors"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// restoreFailureSummary selects only validated per-Link public errors already
// produced by the Engine. It does not surface causes, raw command output,
// credentials, display names or untrusted persisted configuration.
type restoreFailureSummary struct {
	LinkID   domain.LinkID
	Backend  string
	Reason   string
	NextStep string
	Evidence *stlerr.OperationEvidence
}

func restoreFailureSummaries(operationErr error) []restoreFailureSummary {
	var summaries []restoreFailureSummary
	seen := map[domain.LinkID]bool{}
	var visit func(error)
	visit = func(err error) {
		if err == nil {
			return
		}
		if typed, ok := err.(*stlerr.Error); ok {
			id := domain.LinkID(typed.ObjectID)
			if id.Validate() == nil && !seen[id] {
				public := stlerr.WithGuidance(typed)
				seen[id] = true
				summaries = append(summaries, restoreFailureSummary{
					LinkID: id, Backend: public.Backend, Reason: public.ReasonCode,
					NextStep: public.NextStep, Evidence: stlerr.EvidenceOf(typed),
				})
			}
		}
		if many, ok := err.(interface{ Unwrap() []error }); ok {
			for _, nested := range many.Unwrap() {
				visit(nested)
			}
			return
		}
		visit(errors.Unwrap(err))
	}
	visit(operationErr)
	return summaries
}
