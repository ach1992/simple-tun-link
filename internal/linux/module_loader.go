package linux

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var moduleReleasePattern = regexp.MustCompile("^[a-zA-Z0-9_.+~-]{1,128}$")

// LoadTrustedKernelModule is the ONLY privileged kernel loader used by
// interactive PREPARE and committed RestoreAll. Foreign modprobe.d install or
// softdep policy is bypassed for the selected module AND its dependencies.
// The subprocess environment never inherits MODPROBE_OPTIONS, LD_* or PATH.
func LoadTrustedKernelModule(ctx context.Context, module string) error {
	return loadTrustedKernelModule(ctx, module, kernelModulePresent, runControlledModprobe, trustedModuleArtifact)
}

// Private seams are for isolated unit tests. Production always uses the fixed
// environment and verified module sources above, with no caller-driven argv.
func loadTrustedKernelModule(ctx context.Context, module string,
	present func(string) (bool, error),
	run func(context.Context, ...string) ([]byte, error),
	trusted func(string) error,
) error {
	if ctx == nil || present == nil || run == nil || trusted == nil {
		return errors.New("module loader is unavailable")
	}
	switch module {
	case "fou", "ipip", "ip_gre":
	default:
		return errors.New("module outside selected kernel allowlist")
	}
	if ctx.Err() != nil {
		return errors.New("module load canceled")
	}
	already, err := present(module)
	if err != nil {
		return errors.New("module presence is uncertain")
	}
	if already {
		return nil
	}
	// --config /dev/null disables ALL modprobe.d policy. --ignore-install is
	// defense-in-depth if an install directive somehow reached kmod.
	args := []string{"--config", "/dev/null", "--ignore-install"}
	preview, err := run(ctx, append(append([]string{}, args...), "--show-depends", module)...)
	if err != nil || ctx.Err() != nil {
		return errors.New("selected module dependencies unavailable")
	}
	if err := validateModuleDependencyPlan(module, preview, trusted); err != nil {
		return errors.New("untrusted or unverified kernel module dependencies")
	}
	already, err = present(module)
	if err != nil {
		return errors.New("module presence changed or unknown")
	}
	if already {
		return nil
	}
	if _, err := run(ctx, append(append([]string{}, args...), module)...); err != nil {
		return errors.New("selected kernel module insertion failed; no unload attempted")
	}
	already, err = present(module)
	if err != nil || !already {
		return errors.New("kernel module insertion not verified")
	}
	return nil
}

// Only insmod entries are accepted. Unknown directives, including install
// shell hooks at dependency level, are never executed. The selected target
// must be represented among the exact running-kernel source artifacts.
func validateModuleDependencyPlan(module string, output []byte, trusted func(string) error) error {
	if len(output) == 0 || len(output) > 65536 || output[len(output)-1] != '\n' {
		return errors.New("module plan missing or truncated")
	}
	lines := bytes.Split(bytes.TrimSuffix(output, []byte{'\n'}), []byte{'\n'})
	if len(lines) > 128 {
		return errors.New("module graph too large")
	}
	selected := false
	for _, line := range lines {
		fields := strings.Fields(string(line))
		if len(fields) != 2 || fields[0] != "insmod" {
			return errors.New("unexpected module plan operation")
		}
		if err := trusted(fields[1]); err != nil {
			return err
		}
		base := filepath.Base(fields[1])
		for _, suffix := range []string{".ko", ".ko.xz", ".ko.zst", ".ko.gz"} {
			if base == module+suffix {
				selected = true
				break
			}
		}
	}
	if !selected {
		return errors.New("selected module absent from trusted dependency graph")
	}
	return nil
}

func kernelModulePresent(module string) (bool, error) {
	_, err := os.Stat(filepath.Join("/sys/module", module))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func runControlledModprobe(ctx context.Context, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("module command context unavailable")
	}
	if len(args) < 4 || args[0] != "--config" || args[1] != "/dev/null" ||
		args[2] != "--ignore-install" {
		return nil, errors.New("module command arguments not trusted")
	}
	binary, err := filepath.EvalSymlinks("/sbin/modprobe")
	if err != nil || !trustedRootControlledPath("/sbin/modprobe", true) ||
		!trustedRootControlledPath(binary, false) {
		return nil, errors.New("modprobe executable origin untrusted")
	}
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "/sbin/modprobe", args...)
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"LANG=C",
		"HOME=/root",
	}
	stdout := &moduleBoundedWriter{max: 65536, cancel: cancel}
	stderr := &moduleBoundedWriter{max: 4096, cancel: cancel}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	if err != nil || runCtx.Err() != nil || stdout.truncated || stderr.truncated {
		return nil, errors.New("controlled module command incomplete")
	}
	return stdout.buffer.Bytes(), nil
}

type moduleBoundedWriter struct {
	buffer    bytes.Buffer
	max       int
	cancel    context.CancelFunc
	truncated bool
}

func (w *moduleBoundedWriter) Write(p []byte) (int, error) {
	if len(p) > w.max-w.buffer.Len() {
		w.truncated = true
		w.cancel()
		return 0, errors.New("bounded module command output")
	}
	return w.buffer.Write(p)
}

// Every transitive insmod object must resolve INSIDE the running kernel's
// module tree, through protected root-owned path components and a regular,
// non-group-writable module inode. Symlink targets outside are denied.
func trustedModuleArtifact(path string) error {
	releaseBytes, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return errors.New("running kernel release unavailable")
	}
	release := strings.TrimSpace(string(releaseBytes))
	if !moduleReleasePattern.MatchString(release) {
		return errors.New("kernel release unsafe")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("module artifact pathname malformed")
	}
	allowBase := false
	for _, root := range []string{"/lib/modules", "/usr/lib/modules"} {
		if strings.HasPrefix(path, root+"/"+release+"/") {
			allowBase = true
			break
		}
	}
	if !allowBase {
		return errors.New("module outside running-kernel tree")
	}
	if !strings.HasSuffix(path, ".ko") && !strings.HasSuffix(path, ".ko.xz") &&
		!strings.HasSuffix(path, ".ko.zst") && !strings.HasSuffix(path, ".ko.gz") {
		return errors.New("module object extension unsupported")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !trustedRootControlledPath(path, true) ||
		!trustedRootControlledPath(resolved, false) {
		return errors.New("module source or ancestors not root-controlled")
	}
	trustedTree := false
	for _, root := range []string{"/lib/modules", "/usr/lib/modules"} {
		base, err := filepath.EvalSymlinks(root + "/" + release)
		if err == nil && strings.HasPrefix(resolved, base+string(os.PathSeparator)) {
			trustedTree = true
		}
	}
	if !trustedTree {
		return errors.New("module object resolves outside running kernel tree")
	}
	return nil
}

func trustedRootControlledPath(path string, allowSymlink bool) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for part := path; ; part = filepath.Dir(part) {
		info, err := os.Lstat(part)
		if err != nil {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if !allowSymlink {
				return false
			}
		} else if info.Mode().Perm()&0o022 != 0 {
			return false
		}
		if part == path {
			if info.Mode()&os.ModeSymlink == 0 && !info.Mode().IsRegular() {
				return false
			}
		} else if info.Mode()&os.ModeSymlink == 0 && !info.IsDir() {
			return false
		}
		if part == "/" {
			return true
		}
	}
}
