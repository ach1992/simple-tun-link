package gre

import (
	"context"
	"github.com/ach1992/simple-tun-link/internal/app"
	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type offlineGREHost struct {
	original   *fakeRunner
	localReads int
	captureErr error
}

func (h *offlineGREHost) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && len(args) == 3 && args[0] == "-json" && args[1] == "address" && args[2] == "show" {
		h.localReads++
		return linux.CommandResult{Stdout: []byte(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`)}, nil
	}
	return h.original.Run(ctx, name, args...)
}
func TestAllGREEncapsulationsCreateOfflineWithAssignedLocalIPv4(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapNative, domain.EncapFOU, domain.EncapGUE} {
		t.Run(string(encap), func(t *testing.T) {
			link := testLink()
			link.Encapsulation = encap
			if encap != domain.EncapNative {
				link.GRE.UDPPort = 51231
			}
			name, _ := InterfaceName(link.ID)
			original := &fakeRunner{link: link, name: name}
			fw := &fakeFirewall{}
			b := newTestBackend(t, original, fw, fakeCollisions{})
			host := &offlineGREHost{original: original}
			b.runner = host
			b.routes = brokenGREPlanRoute{}
			ctx := context.Background()
			req := core.Request{Operation: core.OperationEnsure, Link: link}
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatalf("cannot plan offline native GRE: %v", err)
			}
			if err = b.Validate(ctx, req, obs, plan); err != nil {
				t.Fatal(err)
			}
			if _, err = b.Apply(ctx, req, obs, plan); err != nil {
				t.Fatal(err)
			}
			if _, err = b.Verify(ctx, req); err != nil {
				t.Fatal(err)
			}
			if host.localReads < 3 || !original.state.Exists || !fw.present {
				t.Fatal("offline GRE did not create exact local resources")
			}
		})
	}
}

// Test double for a capture-bounded host inventory read. It must never
// turn a call to RunBounded into an unchecked unbounded success.
func (h *offlineGREHost) RunBounded(ctx context.Context, limits linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if limits.Stdout <= 0 || limits.Stderr <= 0 {
		return linux.CommandResult{}, linux.ErrOutputLimit
	}
	if err := ctx.Err(); err != nil {
		return linux.CommandResult{}, err
	}
	if h.captureErr != nil && name == "ip" && strings.Join(args, " ") == "-json address show" {
		return linux.CommandResult{}, h.captureErr
	}
	output, err := h.Run(ctx, name, args...)
	if len(output.Stdout) > limits.Stdout || len(output.Stderr) > limits.Stderr {
		return linux.CommandResult{}, linux.ErrOutputLimit
	}
	return output, err
}

// The real Engine must stop at Plan if the capture boundary refuses the local
// address inventory. A valid-looking preferred route is never a substitute.
func TestGREBoundedLocalInventoryFailureDoesNotApplyOrCommit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason error
	}{
		{"stdout_overflow", linux.ErrOutputLimit},
		{"stderr_overflow", linux.ErrOutputLimit},
		{"timeout", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := testLink()
			name, err := InterfaceName(link.ID)
			if err != nil {
				t.Fatal(err)
			}
			kernel := &fakeRunner{link: link, name: name}
			fw := &fakeFirewall{}
			b := newTestBackend(t, kernel, fw, fakeCollisions{})
			host := &offlineGREHost{original: kernel, captureErr: tc.reason}
			b.runner = host
			registry, err := core.NewRegistry(b)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			store := state.NewFileStore(root)
			engine, err := app.New(registry, store, state.NewLockManager(root))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := engine.Ensure(context.Background(), link); err == nil {
				t.Fatal("unverified host address was used to commit GRE Link")
			}
			if kernel.state.Exists || fw.present || len(kernel.mappings) != 0 {
				t.Fatal("failed capture triggered GRE host mutation")
			}
			for _, command := range kernel.commands {
				if strings.Contains(command, " link add ") || strings.Contains(command, " fou add ") {
					t.Fatalf("failed capture reached mutating kernel command: %q", command)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "state.json")); !os.IsNotExist(err) {
				t.Fatalf("Link was durably committed despite capture failure: %v", err)
			}
		})
	}
}
