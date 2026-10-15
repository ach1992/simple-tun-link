package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const fakeFou = "/lib/modules/synthetic/kernel/net/ipv4/fou.ko.xz"
const fakeDep = "/lib/modules/synthetic/kernel/net/ipv4/udp_tunnel.ko.xz"

func TestTrustedModulePlanDeniesForeignInstallHooksAndDependencyEffects(t *testing.T) {
	for _, tc := range []struct {
		name, plan string
		allow      bool
	}{
		{"valid selected module plus a dependency", "insmod " + fakeDep + "\ninsmod " + fakeFou + "\n", true},
		{"foreign top-level install", "install /bin/sh -c 'touch /tmp/FOREIGN'\n", false},
		{"foreign dependency install", "install /bin/sh -c 'touch /tmp/FOREIGN'\ninsmod " + fakeFou + "\n", false},
		{"unexpected extra option", "insmod " + fakeFou + " --force\n", false},
		{"untrusted external path", "insmod /tmp/fou.ko\n", false},
		{"selected target absent", "insmod " + fakeDep + "\n", false},
		{"missing newline", "insmod " + fakeFou, false},
		{"unknown directive", "builtin /lib/modules/synthetic/kernel/net/ipv4/fou.ko\n", false},
		{"empty result", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trust := func(p string) error {
				if p != fakeDep && p != fakeFou {
					return errors.New("foreign module object")
				}
				return nil
			}
			err := validateModuleDependencyPlan("fou", []byte(tc.plan), trust)
			if (err == nil) != tc.allow {
				t.Fatalf("plan validation: allowed=%v error=%v", tc.allow, err)
			}
		})
	}
}

func TestTrustedModuleLoaderControlledArgvBeforeAnyEffect(t *testing.T) {
	var calls [][]string
	loaded := false
	observe := func(string) (bool, error) { return loaded, nil }
	run := func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) == 5 && args[3] == "--show-depends" {
			return []byte("insmod " + fakeDep + "\ninsmod " + fakeFou + "\n"), nil
		}
		if len(args) == 4 && args[3] == "fou" {
			loaded = true
			return nil, nil
		}
		t.Fatalf("unexpected command args: %v", args)
		return nil, errors.New("untrusted command")
	}
	trust := func(p string) error {
		if p != fakeDep && p != fakeFou {
			t.Fatal("foreign module source")
		}
		return nil
	}
	t.Setenv("MODPROBE_OPTIONS", "-C /tmp/foreign-modprobe.conf")
	t.Setenv("LD_PRELOAD", "/tmp/foreign-interposer.so")
	if err := loadTrustedKernelModule(context.Background(), "fou", observe, run, trust); err != nil {
		t.Fatal(err)
	}
	expected := [][]string{
		{"--config", "/dev/null", "--ignore-install", "--show-depends", "fou"},
		{"--config", "/dev/null", "--ignore-install", "fou"},
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("module command redirected by hostile environment: %v", calls)
	}
	calls = nil
	if err := loadTrustedKernelModule(context.Background(), "fou", observe, run, trust); err != nil || len(calls) != 0 {
		t.Fatalf("already loaded module was reinserted: %v %v", err, calls)
	}
}

func TestTrustedModuleLoaderNoEffectWhenUnknownOrCanceled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		module  string
		present func(string) (bool, error)
		ctx     context.Context
	}{
		{"not allowlisted", "wireguard", func(string) (bool, error) { return false, nil }, context.Background()},
		{"unknown presence", "ipip", func(string) (bool, error) { return false, errors.New("unknown") }, context.Background()},
		{"canceled", "ip_gre", func(string) (bool, error) { return false, nil }, canceledModuleContext()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			run := func(context.Context, ...string) ([]byte, error) {
				calls++
				return nil, errors.New("must not run")
			}
			if err := loadTrustedKernelModule(tc.ctx, tc.module, tc.present, run, func(string) error { return nil }); err == nil || calls != 0 {
				t.Fatalf("unexpected modprobe call after denial: err=%v calls=%d", err, calls)
			}
		})
	}
	foreignPlanCalls := 0
	run := func(_ context.Context, args ...string) ([]byte, error) {
		foreignPlanCalls++
		return []byte("install /bin/sh -c 'touch /tmp/FOREIGN'\n"), nil
	}
	if err := loadTrustedKernelModule(context.Background(), "ipip", func(string) (bool, error) {
		return false, nil
	}, run, func(string) error { return nil }); err == nil || foreignPlanCalls != 1 {
		t.Fatalf("foreign dependency hook advanced to insertion: %v calls=%d", err, foreignPlanCalls)
	}
}

func canceledModuleContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestTrustedModuleArtifactRefusesOutsideOrWritablePath(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "fou.ko")
	if err := os.WriteFile(path, []byte("not a kernel module"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := trustedModuleArtifact(path); err == nil {
		t.Fatal("foreign module file outside running-kernel tree was accepted")
	}
	if trustedRootControlledPath(path, false) {
		t.Fatal("unprivileged test file was classified as root-controlled")
	}
	if trustedModuleArtifact("../../../tmp/fou.ko") == nil {
		t.Fatal("relative module source path accepted")
	}
	if err := validateModuleDependencyPlan("fou", []byte("insmod "+fakeFou+"\n"), func(p string) error {
		if !strings.HasSuffix(p, ".ko.xz") {
			return errors.New("not an expected module")
		}
		return nil
	}); err != nil {
		t.Fatalf("valid test dependency path rejected: %v", err)
	}
}
