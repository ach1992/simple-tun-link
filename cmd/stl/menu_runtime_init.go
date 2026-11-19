package main

import (
	"errors"
	"io"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// These internal error categories are assigned where the runtime is built.
// Neither arbitrary backend errors nor external command output may become
// public menu text. The original cause remains available to errors.Is/As.
type runtimeInitKind string

const (
	runtimeInitBackend      runtimeInitKind = "backend"
	runtimeInitCredentials  runtimeInitKind = "credentials"
	runtimeInitExecutable   runtimeInitKind = "executable"
	runtimeInitSystemd      runtimeInitKind = "systemd"
	runtimeInitSelection    runtimeInitKind = "selection"
	runtimeInitRegistration runtimeInitKind = "registration"
)

type runtimeInitIssue struct {
	kind  runtimeInitKind
	cause error
}

func (e *runtimeInitIssue) Error() string {
	return "runtime initialization unverified: " + string(e.kind)
}

func (e *runtimeInitIssue) Unwrap() error { return e.cause }

func runtimeInitFailure(kind runtimeInitKind, cause error) error {
	return &runtimeInitIssue{kind: kind, cause: cause}
}

// A selected runtime that cannot be constructed has not attempted Link Apply
// or staged a credential. The preceding PREPARE step (if any) is distinct.
func menuGuidedCreateRuntimeFailure(out io.Writer, selected domain.Backend, err error) int {
	public := stlerr.WithGuidance(stlerr.New(stlerr.CodeInspect, "guided_create_runtime", "", string(selected),
		"The selected tunnel runtime was not verified."))
	public.ReasonCode = "selected_runtime_unverified"
	public.NextStep = "Check stl version --json and this tunnel type's prerequisites; retry only after read-only inspection."

	var classified *runtimeInitIssue
	if errors.As(err, &classified) {
		switch classified.kind {
		case runtimeInitCredentials:
			public.ReasonCode = "selected_credential_store_unverified"
			public.NextStep = "Check STL private State storage ownership, permissions and free space (read-only). Do not replace existing credentials."
		case runtimeInitExecutable:
			public.ReasonCode = "installed_executable_identity_unverified"
			public.NextStep = "Check command -v stl, stl version --json and the canonical installed executable. Do not substitute an unowned binary."
		case runtimeInitSystemd:
			public.ReasonCode = "systemd_runtime_unverified"
			public.NextStep = "Check /run/systemd/system and systemctl is-system-running (read-only). Do not adopt or replace another service."
		case runtimeInitSelection:
			public.ReasonCode = "selected_backend_unavailable"
			public.NextStep = "Check the supported tunnel types in stl menu and the installed STL version; choose an actually registered backend."
		case runtimeInitRegistration:
			public.ReasonCode = "selected_backend_not_registered"
			public.NextStep = "Check selected tunnel prerequisites and installed STL version; for IPsec run stl doctor ipsec --json (read-only)."
		case runtimeInitBackend:
			public.ReasonCode = "selected_backend_initialization_unverified"
			public.NextStep = "Inspect selected backend prerequisites and stl version --json; for IPsec run stl doctor ipsec --json (read-only)."
		}
	}
	menuSection(out, "Selected tunnel / runtime check")
	menuField(out, "Backend", string(selected))
	menuField(out, "Reason", public.ReasonCode)
	menuField(out, "Next", public.NextStep)
	menuNotice(out, "WARNING", "No Link Apply or credential generation was requested by this step. Any earlier approved PREPARE effects remain.")
	return 4
}

// A nil menu entry must assemble only IPsec for read-only service admission.
// Injected options belong to their caller and must not be replaced.
func menuIPsecSelectedRuntime(options *runtimeOptions,
	assemble func(string, domain.Backend) (*runtimeOptions, error)) (*runtimeOptions, error) {
	if options != nil {
		return options, nil
	}
	resolved, err := assemble(state.DefaultRoot, domain.BackendIPsec)
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return nil, runtimeInitFailure(runtimeInitRegistration, nil)
	}
	return resolved, nil
}
