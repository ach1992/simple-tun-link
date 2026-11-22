//go:build linux

package spoofhost

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/state"
)

// Run ONLY on an explicitly authorized disposable Linux VM: it performs
// actual kernel writes to net.ipv4.conf.all and exactly one selected NIC.
// Independently capture and restore the pre-test host baseline even on failure.
func TestPrivilegedSpoofRPFilterKernelOffLooseRollback(t *testing.T) {
	if os.Getenv("STL_SPOOF_RPF_PRIVILEGED_ACCEPTANCE") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root and explicit disposable Linux VM opt-in")
	}
	iface := os.Getenv("STL_SPOOF_RPF_TEST_NIC")
	if !validRPFilterInterface(iface) {
		t.Fatal("select one real task-owned VM incoming NIC via STL_SPOOF_RPF_TEST_NIC")
	}
	root := t.TempDir()
	manager := ManagedRPFilter{Root: root}
	origAll, err := manager.read("all")
	if err != nil {
		t.Fatal(err)
	}
	origNIC, err := manager.read(iface)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		// Kernel cleanup is independently guaranteed even if any assertion
		// fails before the managed Release or after the journal is corrupted.
		if err := manager.write(ctx, "all", origAll); err != nil {
			t.Errorf("critical: restore original all baseline: %v", err)
		}
		if err := manager.write(ctx, iface, origNIC); err != nil {
			t.Errorf("critical: restore original incoming NIC baseline: %v", err)
		}
	})
	if err := manager.write(ctx, "all", 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.write(ctx, iface, 1); err != nil {
		t.Fatal(err)
	}
	link := rpFilterTestLink("lnk_55555555555555555555555555555555", "10.246.62.165", "10.246.62.245")
	link.Spoof.IngressInterface = iface
	store := state.NewFileStore(root)
	if err := store.Update(ctx, func(s *state.Snapshot) error { s.Upsert(state.LinkRecord{Desired: link}); return nil }); err != nil {
		t.Fatal(err)
	}
	p, err := manager.Apply(ctx, store, link.ID, iface, "loose")
	if err != nil || p.EffectiveAfter != 2 {
		t.Fatalf("real kernel Loose not verified %+v %v", p, err)
	}
	if after, err := manager.read(iface); err != nil || after != 2 {
		t.Fatalf("Loose kernel readback: %d %v", after, err)
	}
	p, err = manager.Apply(ctx, store, link.ID, iface, "off")
	if err != nil || p.EffectiveAfter != 0 || !p.GlobalImpact {
		t.Fatalf("real kernel Off not verified %+v %v", p, err)
	}
	for _, name := range []string{"all", iface} {
		if value, err := manager.read(name); err != nil || value != 0 {
			t.Fatalf("Off kernel readback %s=%d %v", name, value, err)
		}
	}
	// Simulate daemon restart and pre-sysctl service restoration of original
	// values; manager must restore confirmed active Link's Off policy.
	if err := manager.write(ctx, "all", 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.write(ctx, iface, 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconcile(ctx, store); err != nil {
		t.Fatal(fmt.Errorf("real kernel reboot-style recovery: %w", err))
	}
	for _, name := range []string{"all", iface} {
		if value, err := manager.read(name); err != nil || value != 0 {
			t.Fatalf("recovered Off kernel readback %s=%d %v", name, value, err)
		}
	}
	if err := manager.Release(ctx, store, link.ID); err != nil {
		t.Fatalf("real kernel owner release: %v", err)
	}
	for _, name := range []string{"all", iface} {
		if value, err := manager.read(name); err != nil || value != 1 {
			t.Fatalf("released kernel baseline %s=%d %v", name, value, err)
		}
	}
	// With global all=2, incoming NIC=1, effective Loose is already
	// satisfied. The approved operation must journal its shared dependency
	// WITHOUT altering the NIC or global value unnecessarily.
	if err := manager.write(ctx, "all", 2); err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Apply(ctx, store, link.ID, iface, "loose")
	if err != nil || plan.EffectiveBefore != 2 || plan.EffectiveAfter != 2 || len(plan.Changes) != 0 {
		t.Fatalf("global-2 kernel Loose mutated an already-compatible NIC: %+v %v", plan, err)
	}
	if err := manager.write(ctx, "all", 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconcile(ctx, store); err == nil {
		t.Fatal("changed foreign global policy not detected")
	}
	if actual, _ := manager.read("all"); actual != 1 {
		t.Fatal("unapproved global sysctl overwrite")
	}
	if err := manager.write(ctx, "all", 2); err != nil {
		t.Fatal(err)
	}
	if err := manager.Release(ctx, store, link.ID); err != nil {
		t.Fatal(err)
	}
	if actual, _ := manager.read(iface); actual != 1 {
		t.Fatal("original NIC policy not restored")
	}
	if actual, _ := manager.read("all"); actual != 2 {
		t.Fatal("global-2 baseline not retained")
	}
}
