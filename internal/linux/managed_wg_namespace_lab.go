//go:build stl_e2e_lab

package linux

import "github.com/ach1992/simple-tun-link/internal/hostidentity"

var managedNamespaceLabBootSource = hostidentity.CurrentKernelBootID

func managedSiblingKernelBootID() (string, error) { return managedNamespaceLabBootSource() }

// ConfigureQUICNamespaceLab is available only in an explicitly tagged
// disposable fixture. It supplies the actual /proc Boot ID in nested PID
// namespaces without claiming physical-host provenance or reboot acceptance.
// Every nft/kernel/socket reader and namespace comparison remains real.
func ConfigureQUICNamespaceLab(source func() (string, error)) {
	if source != nil {
		managedNamespaceLabBootSource = source
	}
}
