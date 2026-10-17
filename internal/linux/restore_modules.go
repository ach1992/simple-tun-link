package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// CommittedTunnelModuleRestorer prepares ONLY dependencies of a durable
// previously committed GRE/IPIP Link under Engine's maintenance/per-Link
// lock, as part of the already owned link restore service. No global
// modules-load.d file is created; shared modules are never unloaded.
//
// This does not activate a tunnel or trust modinfo as proof of support:
// backend Ensure must independently verify the real capability afterwards.
type CommittedTunnelModuleRestorer struct {
	Runner Runner
	// Test-only seams. Production invokes LoadTrustedKernelModule, which
	// ignores foreign modprobe.d hooks, sanitizes the environment and attests
	// every on-disk dependency before root insertion.
	Load    func(context.Context, string) error
	Present func(string) (bool, error)
	Observe func(context.Context, string) KernelModuleState
}

func CommittedLinkKernelModules(link domain.Link) []string {
	switch link.Backend {
	case domain.BackendGRE:
		switch link.Encapsulation {
		case domain.EncapNative:
			return []string{"ip_gre"}
		case domain.EncapFOU, domain.EncapGUE:
			return []string{"ip_gre", "fou"}
		}
	case domain.BackendIPIP:
		switch link.Encapsulation {
		case domain.EncapNative:
			return []string{"ipip"}
		case domain.EncapFOU, domain.EncapGUE:
			return []string{"ipip", "fou"}
		}
	}
	return nil
}

func (r CommittedTunnelModuleRestorer) Prepare(ctx context.Context, link domain.Link) error {
	needed := CommittedLinkKernelModules(link)
	if len(needed) == 0 {
		return nil
	}
	if ctx == nil || r.Runner == nil {
		return errors.New("restore kernel inventory unavailable")
	}
	present := r.Present
	if present == nil {
		present = func(name string) (bool, error) {
			_, err := os.Stat(filepath.Join("/sys/module", name))
			switch {
			case err == nil:
				return true, nil
			case errors.Is(err, os.ErrNotExist):
				return false, nil
			default:
				return false, errors.New("kernel module inventory incomplete")
			}
		}
	}
	observe := r.Observe
	if observe == nil {
		observe = (KernelModuleProbe{Runner: r.Runner, ModinfoBinary: "/sbin/modinfo"}).Observe
	}
	for _, name := range needed {
		if err := ctx.Err(); err != nil {
			return errors.New("restore kernel module operation cancelled")
		}
		found, err := present(name)
		if err != nil {
			return errors.New("restore kernel module observation unknown")
		}
		if found {
			continue
		}
		switch observe(ctx, name) {
		case KernelModuleBuiltin:
			// Built-in kernel code has no loadable artifact or obligatory
			// sysfs directory. Engine Ensure must independently verify its
			// real runtime capability before restoring the Link.
			continue
		case KernelModuleLoadableInactive:
			// Only independently proven missing loadable modules may be inserted.
		default:
			return fmt.Errorf("selected %s kernel dependency unavailable or not proven loadable", name)
		}
		load := r.Load
		if load == nil {
			load = LoadTrustedKernelModule
		}
		if err := load(ctx, name); err != nil {
			return fmt.Errorf("loading selected %s trusted kernel dependency failed; no unload attempted", name)
		}
		found, err = present(name)
		if err != nil || !found {
			return fmt.Errorf("selected %s module load was not verified", name)
		}
	}
	return nil
}
