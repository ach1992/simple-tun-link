package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// KernelModuleProbe makes an independent, non-mutating observation after a
// kernel inventory command failed. Only a module proven absent from sysfs AND
// present as a disk artifact may be reported as "not loaded". This is not
// proof that loading will work, nor a replacement for actual inventory.
type KernelModuleProbe struct {
	Runner        Runner
	SysModuleRoot string
	ModinfoBinary string
}

func (p KernelModuleProbe) AvailableButNotLoaded(ctx context.Context, module string) bool {
	if ctx.Err() != nil || p.Runner == nil {
		return false
	}
	// No caller-controlled paths or unrestricted module identifier strings.
	switch module {
	case "fou", "ipip", "ip_gre":
	default:
		return false
	}
	root := p.SysModuleRoot
	if root == "" {
		root = "/sys/module"
	}
	_, err := os.Stat(filepath.Join(root, module))
	if !os.IsNotExist(err) {
		// Present, inaccessible or unknown is not "known not loaded".
		return false
	}
	modinfo := p.ModinfoBinary
	if modinfo == "" {
		modinfo = "modinfo"
	}
	result, err := p.Runner.Run(ctx, modinfo, "-n", module)
	if err != nil || ctx.Err() != nil {
		return false
	}
	filename := strings.TrimSpace(string(result.Stdout))
	// Built-in metadata is not a loadable artifact. A real module must
	// resolve to an ordinary kernel module file in the module tree.
	if !(strings.HasPrefix(filename, "/lib/modules/") ||
		strings.HasPrefix(filename, "/usr/lib/modules/")) ||
		!(strings.HasSuffix(filename, ".ko") ||
			strings.HasSuffix(filename, ".ko.xz") ||
			strings.HasSuffix(filename, ".ko.zst") ||
			strings.HasSuffix(filename, ".ko.gz")) {
		return false
	}
	info, err := os.Stat(filename)
	return err == nil && info.Mode().IsRegular()
}
