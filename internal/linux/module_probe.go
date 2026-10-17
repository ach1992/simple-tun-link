package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// KernelModuleState describes independently observed module readiness.
// Unavailable means that the reported on-disk artifact is demonstrably not
// loadable; it does NOT prove the kernel capability is unsupported.
type KernelModuleState uint8

const (
	KernelModuleUnknown KernelModuleState = iota
	KernelModuleLoaded
	KernelModuleLoadableInactive
	KernelModuleUnavailable
)

// KernelModuleProbe observes only allowlisted modules, without causing host
// changes. Neither a successful iproute2 query nor a failed modinfo invocation
// substitutes for independent sysfs and on-disk evidence.
type KernelModuleProbe struct {
	Runner        Runner
	SysModuleRoot string
	ModinfoBinary string
	stat          func(string) (os.FileInfo, error) // test-only read-only seam
}

func (p KernelModuleProbe) Observe(ctx context.Context, module string) KernelModuleState {
	if ctx == nil || ctx.Err() != nil || p.Runner == nil {
		return KernelModuleUnknown
	}
	// No caller-controlled paths or unrestricted module identifier strings.
	switch module {
	case "fou", "ipip", "ip_gre":
	default:
		return KernelModuleUnknown
	}
	stat := p.stat
	if stat == nil {
		stat = os.Stat
	}
	root := p.SysModuleRoot
	if root == "" {
		root = "/sys/module"
	}
	rootInfo, err := stat(root)
	if err != nil || !rootInfo.IsDir() {
		// Missing or inaccessible sysfs is not evidence of an absent module.
		return KernelModuleUnknown
	}
	info, err := stat(filepath.Join(root, module))
	switch {
	case err == nil:
		if info.IsDir() {
			return KernelModuleLoaded
		}
		return KernelModuleUnknown
	case !os.IsNotExist(err):
		return KernelModuleUnknown
	}
	modinfo := p.ModinfoBinary
	if modinfo == "" {
		modinfo = "modinfo"
	}
	result, err := p.Runner.Run(ctx, modinfo, "-n", module)
	if err != nil || ctx.Err() != nil {
		return KernelModuleUnknown
	}
	filename := strings.TrimSpace(string(result.Stdout))
	if filename == "(builtin)" {
		// A built-in cannot be loaded with modprobe from a module file.
		return KernelModuleUnavailable
	}
	// modinfo output is untrusted diagnostic data, not permission to inspect
	// arbitrary filesystem paths or to load anything.
	if filepath.Clean(filename) != filename ||
		!(strings.HasPrefix(filename, "/lib/modules/") ||
			strings.HasPrefix(filename, "/usr/lib/modules/")) ||
		!(strings.HasSuffix(filename, ".ko") ||
			strings.HasSuffix(filename, ".ko.xz") ||
			strings.HasSuffix(filename, ".ko.zst") ||
			strings.HasSuffix(filename, ".ko.gz")) {
		return KernelModuleUnknown
	}
	info, err = stat(filename)
	if err == nil {
		if info.Mode().IsRegular() {
			return KernelModuleLoadableInactive
		}
		return KernelModuleUnavailable
	}
	if os.IsNotExist(err) {
		return KernelModuleUnavailable // reported artifact is absent
	}
	return KernelModuleUnknown
}

// Existing Engine/restore callers require only the positive, narrow proof
// that a module is inactive and loadable; all other states fail closed.
func (p KernelModuleProbe) AvailableButNotLoaded(ctx context.Context, module string) bool {
	return p.Observe(ctx, module) == KernelModuleLoadableInactive
}
