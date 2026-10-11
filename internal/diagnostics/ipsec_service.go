package diagnostics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// servicePathLstat observes a known service identity without opening it or
// following an alias, including a dangling symlink to a foreign service.
type servicePathLstat func(string) (os.FileInfo, error)

// inspectStrongSwanServiceFiles is only an observational prerequisite for
// the future native-exclusive IPsec runtime. No service control or file
// content is read. Absent known service files are NEVER ownership proof:
// an alternate package, socket, process or kernel writer could still exist.
func inspectStrongSwanServiceFiles(ctx context.Context, lstat servicePathLstat) IPsecHostCheck {
	const name = "strongswan_service"
	unknown := IPsecHostCheck{
		Name: name, Status: "unknown", ReasonCode: "strongswan_service_inventory_unverified",
		Summary:  "Known strongSwan service file identities could not all be inspected; absence cannot be inferred.",
		NextStep: "Check systemd/init file inventory and ownership manually; do not assume native-exclusive IPsec is available.",
	}
	if ctx == nil || lstat == nil || ctx.Err() != nil {
		return unknown
	}
	// Fixed Debian/Ubuntu unit identities and their admin/runtime overrides.
	// Paths are read with Lstat, not globbing, directory walking or systemctl.
	units := []string{"strongswan.service", "strongswan-starter.service", "charon-systemd.service", "ipsec.service"}
	roots := []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}
	var paths []string
	for _, root := range roots {
		for _, unit := range units {
			paths = append(paths, filepath.Join(root, unit))
		}
	}
	paths = append(paths, "/etc/init.d/ipsec", "/etc/init.d/strongswan", "/etc/init.d/strongswan-starter")

	uncertain := false
	for _, path := range paths {
		if ctx.Err() != nil {
			return unknown
		}
		info, err := lstat(path)
		if err == nil && info != nil {
			return IPsecHostCheck{
				Name: name, Status: "blocked", ReasonCode: "strongswan_service_observed",
				Summary:  "A known IPsec/strongSwan service identity exists, but STL cannot prove exclusive ownership.",
				NextStep: "Do not stop, adopt, reload or replace a foreign service. Inspect package/service ownership before attempting IPsec.",
			}
		}
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			uncertain = true
		}
	}
	if uncertain {
		return unknown
	}
	return IPsecHostCheck{
		Name: name, Status: "observed", ReasonCode: "strongswan_service_not_observed",
		Summary:  "No known Debian/Ubuntu strongSwan service file was observed; this is not proof of host or daemon vacancy.",
		NextStep: "A complete exclusive package, daemon, socket, port, configuration and kernel ownership check is still required.",
	}
}
