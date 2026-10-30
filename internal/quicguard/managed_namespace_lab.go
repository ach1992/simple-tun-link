//go:build stl_e2e_lab

package quicguard

// ConfigureQUICNamespaceLab changes only the trusted-host source admission in
// a disposable namespace fixture. It never substitutes nft/WG/socket readers
// or the exclusive production effect, and is absent from production builds.
func ConfigureQUICNamespaceLab(m *Managed, source func() (string, error)) {
	if m != nil && source != nil {
		m.kernelBootID = source
	}
}
