package stlerr

// WithGuidance produces a safe operator/machine-facing copy of a public
// error. Callers must supply authored, non-secret detail, not raw command,
// credential, pairing or kernel output. Existing domain-specific reason
// codes/actions always win; this is a conservative fallback, not diagnosis.
func WithGuidance(source *Error) *Error {
	if source == nil {
		source = New(CodeInternal, "", "", "", "internal error")
	}
	out := *source
	var code, step string
	switch out.Code {
	case CodeInvalid:
		code = "invalid_request"
		step = "Check the requested Link ID, arguments and versioned input; no mutation should be inferred."
	case CodeUnsupported:
		code = "capability_unavailable"
		step = "Check selected backend and host prerequisites; do not attempt to enable an unverified feature."
	case CodeConflict:
		code = "resource_conflict"
		step = "Inspect current Link and resource ownership; avoid replacing or adopting another owner's resources."
	case CodeInspect:
		code = "observation_unverified"
		step = "Retry read-only inspection and verify actual Link identity; do not infer absence or safe repair."
	case CodePlan:
		code = "plan_unverified"
		step = "Review backend prerequisites, target state and competing resource claims before retrying."
	case CodeValidate:
		code = "validation_unverified"
		step = "Correct unsupported or conflicting requested parameters before an apply attempt."
	case CodeApply:
		code = "apply_outcome_unverified"
		step = "Inspect host and saved state; a partial apply may require owned-resource reconciliation before retry."
	case CodeVerify:
		code = "verification_unverified"
		step = "Inspect live Link identity and reachability before retrying; do not assume a completed apply."
	case CodeState:
		code = "state_unverified"
		step = "Verify durable state and maintenance locks before retrying; avoid overwriting uncertain prior changes."
	case CodeRollback:
		code = "rollback_incomplete"
		step = "Reconcile owned partial host resources and persisted state before any further mutation."
	default:
		code = "internal_error"
		step = "Inspect local state read-only and consult the project runbook; do not assume success."
	}
	if out.ReasonCode == "" {
		out.ReasonCode = code
	}
	if out.NextStep == "" {
		out.NextStep = step
	}
	// Never promote internal causes into machine-readable or human fields.
	out.cause = nil
	return &out
}
