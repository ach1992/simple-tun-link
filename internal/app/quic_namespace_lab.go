//go:build stl_e2e_lab

package app

// ConfigureQUICNamespaceLab exists only in explicitly tagged disposable lab
// binaries. Its source must report the real current fixture kernel Boot ID;
// it does not demonstrate trusted physical-host provenance or a real reboot.
// Production builds contain neither this symbol nor an override flag.
func ConfigureQUICNamespaceLab(e *Engine, source func() (string, error)) {
	if e != nil && source != nil {
		e.kernelBootID = source
	}
}
