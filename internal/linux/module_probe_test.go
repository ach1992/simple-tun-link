package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type moduleObservationRunner struct {
	path  string
	fail  bool
	calls []string
}

func (r *moduleObservationRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if r.fail {
		return CommandResult{}, errors.New("private modinfo error")
	}
	return CommandResult{Stdout: []byte(r.path)}, nil
}

func TestKernelModuleObservationEvidenceMatrix(t *testing.T) {
	for _, tc := range []struct {
		name         string
		loaded       bool
		missingRoot  bool
		sysfsErr     error
		artifactErr  error
		path         string
		modinfoFails bool
		want         KernelModuleState
		wantModinfo  bool
	}{
		{"verified loaded", true, false, nil, nil, "", false, KernelModuleLoaded, false},
		{"absent sysfs and valid module", false, false, nil, nil, "/lib/modules/mock/ipip.ko", false, KernelModuleLoadableInactive, true},
		{"absent sysfs but modinfo fails", false, false, nil, nil, "", true, KernelModuleUnknown, true},
		{"inaccessible sysfs", false, false, os.ErrPermission, nil, "/lib/modules/mock/ipip.ko", false, KernelModuleUnknown, false},
		{"sysfs root missing", false, true, nil, nil, "/lib/modules/mock/ipip.ko", false, KernelModuleUnknown, false},
		{"untrusted modinfo path", false, false, nil, nil, "/tmp/untrusted.ko", false, KernelModuleUnknown, true},
		{"modinfo path traversal", false, false, nil, nil, "/lib/modules/../../tmp/ipip.ko", false, KernelModuleUnknown, true},
		{"modinfo artifact missing", false, false, nil, os.ErrNotExist, "/lib/modules/mock/ipip.ko", false, KernelModuleUnavailable, true},
		{"modinfo artifact unreadable", false, false, nil, os.ErrPermission, "/lib/modules/mock/ipip.ko", false, KernelModuleUnknown, true},
		{"built-in no sysfs directory", false, false, nil, nil, "(builtin)", false, KernelModuleBuiltin, true},
		{"built-in metadata with missing sysfs root", false, true, nil, nil, "(builtin)", false, KernelModuleUnknown, false},
		{"built-in metadata but modinfo fails", false, false, nil, nil, "(builtin)", true, KernelModuleUnknown, true},
		{"malformed built-in metadata", false, false, nil, nil, "(builtin) extra", false, KernelModuleUnknown, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "sys-module")
			if !tc.missingRoot {
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.loaded {
				if err := os.Mkdir(filepath.Join(root, "ipip"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			artifact := filepath.Join(t.TempDir(), "ipip.ko")
			if err := os.WriteFile(artifact, []byte("test artifact only"), 0600); err != nil {
				t.Fatal(err)
			}
			runner := &moduleObservationRunner{path: tc.path, fail: tc.modinfoFails}
			probe := KernelModuleProbe{Runner: runner, SysModuleRoot: root}
			probe.stat = func(path string) (os.FileInfo, error) {
				if path == filepath.Join(root, "ipip") && tc.sysfsErr != nil {
					return nil, tc.sysfsErr
				}
				if path == "/lib/modules/mock/ipip.ko" {
					if tc.artifactErr != nil {
						return nil, tc.artifactErr
					}
					return os.Stat(artifact)
				}
				return os.Stat(path)
			}
			if got := probe.Observe(context.Background(), "ipip"); got != tc.want {
				t.Fatalf("state=%v want=%v", got, tc.want)
			}
			if got := probe.AvailableButNotLoaded(context.Background(), "ipip"); got != (tc.want == KernelModuleLoadableInactive) {
				t.Fatalf("legacy boolean wrapper made an unsupported claim: %v", got)
			}
			wantCalls := 0
			if tc.wantModinfo {
				wantCalls = 2
			}
			if len(runner.calls) != wantCalls {
				t.Fatalf("read-only module calls=%v want=%d", runner.calls, wantCalls)
			}
			for _, call := range runner.calls {
				if call != "modinfo -n ipip" {
					t.Fatalf("unexpected effectful observation command: %q", call)
				}
			}
			if contents, err := os.ReadFile(artifact); err != nil || string(contents) != "test artifact only" {
				t.Fatalf("observation changed artifact: contents=%q err=%v", contents, err)
			}
		})
	}
}

func TestKernelModuleObservationNeverProbesUnknownOrCanceledModules(t *testing.T) {
	runner := &moduleObservationRunner{path: "/lib/modules/mock/ipip.ko"}
	probe := KernelModuleProbe{Runner: runner, SysModuleRoot: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if probe.Observe(ctx, "ipip") != KernelModuleUnknown ||
		probe.Observe(context.Background(), "wireguard") != KernelModuleUnknown ||
		len(runner.calls) != 0 {
		t.Fatalf("unsupported module or canceled observation attempted a command: %v", runner.calls)
	}
}
