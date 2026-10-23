package state

import (
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/hostidentity"
)

// WSSColdBootRestore is a narrowly scoped, single-use recovery witness for
// committed WSS records without trusted original birth provenance. ONLY the
// explicit manual Arm + real-kernel-generation Reconcile may issue it. A
// successful ordinary Ensure must never manufacture or renew this authority.
// Spent is durably set with the new pre-effect crash journal before Apply;
// a crash cannot replay it to create a second surviving original WG.
type WSSColdBootRestore struct {
	ArmedFrom    string `json:"armed_from"`
	ReconciledAt string `json:"reconciled_at"`
	Source       string `json:"source"`
	Spent        bool   `json:"spent,omitempty"`
}

func (w WSSColdBootRestore) Validate() error {
	if w == (WSSColdBootRestore{}) {
		return nil
	}
	if w.Source != hostidentity.VerifiedHostBootSourceV1 ||
		!hostidentity.ValidBootID(w.ArmedFrom) ||
		!hostidentity.ValidBootID(w.ReconciledAt) ||
		w.ArmedFrom == w.ReconciledAt {
		return fmt.Errorf("incomplete or untrusted original-kernel extinction witness")
	}
	return nil
}

// AvailableOn returns authorization only in an independently attested later
// host generation. It never authenticates the local absence of an interface.
func (w WSSColdBootRestore) AvailableOn(trustedCurrentBoot string) bool {
	return w != (WSSColdBootRestore{}) && !w.Spent &&
		w.Validate() == nil && hostidentity.ValidBootID(trustedCurrentBoot) &&
		trustedCurrentBoot != w.ArmedFrom
}
