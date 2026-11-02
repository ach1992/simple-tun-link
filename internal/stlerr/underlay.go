package stlerr

// LocalUnderlayUnverified is a typed, public, secret-free Create/Import
// failure. It does not claim the remote peer was probed or disconnected.
// The supplied cause is retained solely for internal errors.Is/As; it is
// never rendered into CLI JSON, terminal output, or diagnostic logs.
func LocalUnderlayUnverified(operation, id, backend string, cause error) *Error {
	e := Wrap(CodePlan, operation, id, backend, "local IPv4/interface for this Link cannot be independently verified", cause)
	e.ReasonCode = "local_underlay_unverified"
	e.NextStep = "Use ip -json address show on THIS server to verify the assigned local IPv4/interface; select a uniquely assigned endpoint. Peer reachability is not required for Create or Import."
	return e
}
