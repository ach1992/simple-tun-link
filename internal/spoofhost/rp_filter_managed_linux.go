//go:build linux

package spoofhost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// ManagedRPFilter changes host sysctls only after an explicit Link-scoped
// operator confirmation. Durable before-values and targets live in canonical
// State; a separate shared lock serializes all Spoof rp_filter writers.
// ProcRoot is injectable for isolated sysctl regression testing only.
type ManagedRPFilter struct {
	Root     string
	ProcRoot string
}

func (m ManagedRPFilter) proc() string {
	if m.ProcRoot == "" {
		return "/proc/sys"
	}
	return m.ProcRoot
}
func (m ManagedRPFilter) sysctlPath(iface string) (string, error) {
	if iface != "all" && !validRPFilterInterface(iface) {
		return "", fmt.Errorf("invalid rp_filter interface %q", iface)
	}
	return filepath.Join(m.proc(), "net", "ipv4", "conf", iface, "rp_filter"), nil
}
func validRPFilterInterface(iface string) bool {
	if iface == "" || iface == "all" || iface == "default" || iface == "." || iface == ".." || len(iface) > 15 {
		return false
	}
	for _, c := range iface {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}
func (m ManagedRPFilter) read(iface string) (int, error) {
	path, err := m.sysctlPath(iface)
	if err != nil {
		return 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s rp_filter: %w", iface, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n < 0 || n > 2 {
		return 0, fmt.Errorf("unexpected %s rp_filter value %q", iface, strings.TrimSpace(string(data)))
	}
	return n, nil
}
func (m ManagedRPFilter) write(ctx context.Context, iface string, value int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.proc() == "/proc/sys" && os.Geteuid() != 0 {
		return errors.New("root privileges required to change host rp_filter")
	}
	path, err := m.sysctlPath(iface)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("open %s rp_filter for write: %w", iface, err)
	}
	_, err = f.WriteString(strconv.Itoa(value))
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("set %s rp_filter: %w", iface, err)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s rp_filter: %w", iface, closeErr)
	}
	found, err := m.read(iface)
	if err != nil || found != value {
		return fmt.Errorf("%s rp_filter readback expected %d, found %d: %w", iface, value, found, err)
	}
	return nil
}
func (m ManagedRPFilter) lock(ctx context.Context) (func() error, error) {
	if m.Root == "" {
		return nil, errors.New("State root is required for rp_filter ownership")
	}
	return state.NewLockManager(m.Root).Acquire(ctx, []domain.ResourceClaim{{Kind: "stl-spoof-rp-filter", Key: "host"}})
}

// The exact local receive address normally identifies the incoming NIC. An
// operator override remains available for DNAT, ambiguous host routing and
// addresses assigned to a loopback interface.
// ResolveIncoming exposes only read-only capability-based NIC discovery.
func (m ManagedRPFilter) ResolveIncoming(link domain.Link, override string) (string, error) {
	return m.incoming(link, override)
}

func (m ManagedRPFilter) incoming(link domain.Link, override string) (string, error) {
	iface := override
	if iface == "" {
		iface = link.Spoof.IngressInterface
	}
	if iface != "" {
		if !validRPFilterInterface(iface) {
			return "", errors.New("invalid incoming interface")
		}
		if _, err := m.read(iface); err != nil {
			return "", err
		}
		return iface, nil
	}
	addr := link.Spoof.BindIPv4
	if !addr.IsValid() {
		addr = link.Underlay.Local
	}
	if !addr.Is4() {
		return "", errors.New("no local bind IPv4; specify --interface")
	}
	nics, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var matched []string
	for _, nic := range nics {
		if nic.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := nic.Addrs()
		if err != nil {
			continue
		}
		for _, item := range addrs {
			prefix, err := netip.ParsePrefix(item.String())
			if err == nil && prefix.Addr() == addr {
				matched = append(matched, nic.Name)
				break
			}
		}
	}
	if len(matched) != 1 {
		return "", fmt.Errorf("cannot unambiguously identify incoming NIC for local bind %s; specify --interface (found %d)", addr, len(matched))
	}
	if _, err := m.read(matched[0]); err != nil {
		return "", err
	}
	return matched[0], nil
}

func copyRPClaims(source []state.SpoofRPFilterClaim) []state.SpoofRPFilterClaim {
	return append([]state.SpoofRPFilterClaim(nil), source...)
}
func copyRPSettings(source []state.SpoofRPFilterSetting) []state.SpoofRPFilterSetting {
	return append([]state.SpoofRPFilterSetting(nil), source...)
}
func (m ManagedRPFilter) ensureSetting(settings *[]state.SpoofRPFilterSetting, iface string) error {
	for _, setting := range *settings {
		if setting.Interface == iface {
			return nil
		}
	}
	v, err := m.read(iface)
	if err != nil {
		return err
	}
	*settings = append(*settings, state.SpoofRPFilterSetting{Interface: iface, Original: v, Previous: v, Desired: v})
	return nil
}

// composeRPFilterPlans projects all existing owners together; OFF is more
// permissive than LOOSE for the same NIC. `all=0` is indispensable for OFF.
// Unclaimed settings converge back to their exact original before retirement.
func composeRPFilterPlans(claims []state.SpoofRPFilterClaim, settings []state.SpoofRPFilterSetting) {
	globalOff := false
	byNIC := make(map[string]string)
	for _, claim := range claims {
		if claim.Mode == "off" {
			globalOff = true
			byNIC[claim.Interface] = "off"
		} else if byNIC[claim.Interface] != "off" {
			byNIC[claim.Interface] = "loose"
		}
	}
	// Every approved owner, including Loose, journals the actual all value
	// before composing per-interface settings. Never assume all=0.
	baseAll := 0
	for _, setting := range settings {
		if setting.Interface == "all" {
			baseAll = setting.Original
			break
		}
	}
	for i := range settings {
		p := &settings[i]
		p.Previous = p.Desired
		p.Desired = p.Original
		if p.Interface == "all" {
			if globalOff {
				p.Desired = 0
			}
			continue
		}
		switch byNIC[p.Interface] {
		case "off":
			p.Desired = 0
		case "loose":
			// Do not change an already-compatible Linux policy just to own a
			// sysctl. When another Link sets all=0, however, preserve this
			// NIC's effective Loose policy if all=2 previously supplied it.
			if max(baseAll, p.Original) == 1 || globalOff && baseAll == 2 && p.Original < 2 {
				p.Desired = 2
			}
		}
	}
}

func (m ManagedRPFilter) planned(snapshot state.Snapshot, id domain.LinkID, iface, mode string) (app.SpoofRPFilterPlan, []state.SpoofRPFilterClaim, []state.SpoofRPFilterSetting, error) {
	if mode != "loose" && mode != "off" {
		return app.SpoofRPFilterPlan{}, nil, nil, errors.New("rp_filter mode must be loose or off")
	}
	record, active := snapshot.Find(id)
	if !active || record.Desired.Backend != domain.BackendSpoof {
		return app.SpoofRPFilterPlan{}, nil, nil, errors.New("rp_filter change requires a committed Spoof Link")
	}
	iface, err := m.incoming(record.Desired, iface)
	if err != nil {
		return app.SpoofRPFilterPlan{}, nil, nil, err
	}
	claims := copyRPClaims(snapshot.SpoofRPFilterClaims)
	settings := copyRPSettings(snapshot.SpoofRPFilterSettings)
	existingOwners := 0
	found := false
	for i := range claims {
		if claims[i].LinkID == id {
			claims[i].Interface, claims[i].Mode = iface, mode
			found = true
		} else {
			existingOwners++
		}
	}
	if !found {
		claims = append(claims, state.SpoofRPFilterClaim{LinkID: id, Interface: iface, Mode: mode})
	}
	// The effective Linux policy is max(all, NIC). Even a Loose-only
	// claim must record the *observed* global baseline. If all=2 already
	// supplies Loose, do not needlessly change the incoming NIC; if an
	// external service later alters all, fail with explicit foreign-policy
	// drift rather than silently treating the old effective guarantee as
	// satisfied or overwriting another service's choice.
	if err := m.ensureSetting(&settings, "all"); err != nil {
		return app.SpoofRPFilterPlan{}, nil, nil, err
	}
	for _, claim := range claims {
		if err := m.ensureSetting(&settings, claim.Interface); err != nil {
			return app.SpoofRPFilterPlan{}, nil, nil, err
		}
	}
	composeRPFilterPlans(claims, settings)
	beforeAll, err := m.read("all")
	if err != nil {
		return app.SpoofRPFilterPlan{}, nil, nil, err
	}
	beforeIface, err := m.read(iface)
	if err != nil {
		return app.SpoofRPFilterPlan{}, nil, nil, err
	}
	afterAll, afterIface := beforeAll, beforeIface
	plan := app.SpoofRPFilterPlan{LinkID: id, Interface: iface, Mode: mode, EffectiveBefore: max(beforeAll, beforeIface), ExistingOwners: existingOwners}
	for _, setting := range settings {
		current, readErr := m.read(setting.Interface)
		if readErr != nil {
			return app.SpoofRPFilterPlan{}, nil, nil, readErr
		}
		// A foreign concurrent change outside the recorded before-values and
		// prior/current owned targets must not be silently adopted.
		if current != setting.Original && current != setting.Previous && current != setting.Desired {
			return app.SpoofRPFilterPlan{}, nil, nil, fmt.Errorf("%s rp_filter changed outside STL ownership (current=%d, original=%d, previous=%d, desired=%d); inspect host sysctl before retry", setting.Interface, current, setting.Original, setting.Previous, setting.Desired)
		}
		if current != setting.Desired {
			plan.Changes = append(plan.Changes, app.SpoofRPFilterChange{Interface: setting.Interface, Current: current, Proposed: setting.Desired})
		}
		if setting.Interface == "all" {
			afterAll = setting.Desired
		}
		if setting.Interface == iface {
			afterIface = setting.Desired
		}
	}
	plan.EffectiveAfter = max(afterAll, afterIface)
	plan.GlobalImpact = slices.ContainsFunc(plan.Changes, func(c app.SpoofRPFilterChange) bool { return c.Interface == "all" })
	if mode == "off" {
		plan.Note = "OFF requires global all=0 and incoming NIC=0. Changing all can weaken OR strengthen effective filtering on other NICs depending on their individual values; explicitly confirm the host-wide impact."
	} else {
		plan.Note = "LOOSE generally changes only the receiving NIC. A reverse route must still exist; this cannot change provider firewall or anti-spoof filtering."
	}
	return plan, claims, settings, nil
}

func (m ManagedRPFilter) Preview(ctx context.Context, snapshot state.Snapshot, id domain.LinkID, iface, mode string) (app.SpoofRPFilterPlan, error) {
	if err := ctx.Err(); err != nil {
		return app.SpoofRPFilterPlan{}, err
	}
	plan, _, _, err := m.planned(snapshot, id, iface, mode)
	return plan, err
}

func (m ManagedRPFilter) Apply(ctx context.Context, store state.Store, id domain.LinkID, iface, mode string) (app.SpoofRPFilterPlan, error) {
	release, err := m.lock(ctx)
	if err != nil {
		return app.SpoofRPFilterPlan{}, err
	}
	defer release()
	var plan app.SpoofRPFilterPlan
	// The journal is durably published BEFORE modifying even one shared
	// sysctl, so crashes can be resumed without fabricating old values.
	err = store.Update(ctx, func(s *state.Snapshot) error {
		var claims []state.SpoofRPFilterClaim
		var settings []state.SpoofRPFilterSetting
		plan, claims, settings, err = m.planned(*s, id, iface, mode)
		if err != nil {
			return err
		}
		s.SpoofRPFilterClaims = claims
		s.SpoofRPFilterSettings = settings
		return nil
	})
	if err != nil {
		return plan, fmt.Errorf("rp_filter pre-effect State publication failed (kernel values may be unchanged): %w", err)
	}
	if err := m.reconcileLocked(ctx, store); err != nil {
		return plan, fmt.Errorf("rp_filter confirmed journal remains retryable; inspect and rerun apply or restore: %w", err)
	}
	return plan, nil
}

func (m ManagedRPFilter) Release(ctx context.Context, store state.Store, id domain.LinkID) error {
	// Ordinary Remove with no approved host-policy claim is a true no-op.
	initial, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(initial.SpoofRPFilterClaims, func(c state.SpoofRPFilterClaim) bool { return c.LinkID == id }) && len(initial.SpoofRPFilterSettings) == 0 {
		return nil
	}
	release, err := m.lock(ctx)
	if err != nil {
		return err
	}
	defer release()
	err = store.Update(ctx, func(s *state.Snapshot) error {
		found := false
		for _, claim := range s.SpoofRPFilterClaims {
			if claim.LinkID == id {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		if record, active := s.Find(id); active {
			if record.Desired.Backend != domain.BackendSpoof {
				return errors.New("rp_filter owner is not a Spoof Link")
			}
		} else if receipt, present := s.FindSpoofRemovalReceipt(id); !present || receipt.Link.Backend != domain.BackendSpoof {
			return errors.New("rp_filter owner has no canonical committed Spoof removal receipt")
		}
		claims := make([]state.SpoofRPFilterClaim, 0, len(s.SpoofRPFilterClaims)-1)
		for _, c := range s.SpoofRPFilterClaims {
			if c.LinkID != id {
				claims = append(claims, c)
			}
		}
		settings := copyRPSettings(s.SpoofRPFilterSettings)
		composeRPFilterPlans(claims, settings)
		s.SpoofRPFilterClaims, s.SpoofRPFilterSettings = claims, settings
		return nil
	})
	if err != nil {
		return fmt.Errorf("cannot publish rp_filter owner release: %w", err)
	}
	return m.reconcileLocked(ctx, store)
}

func (m ManagedRPFilter) Reconcile(ctx context.Context, store state.Store) error {
	// Never create State or a lock directory merely by restoring an empty
	// installation; neither status nor boot restore grants new host policy.
	initial, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if len(initial.SpoofRPFilterClaims) == 0 && len(initial.SpoofRPFilterSettings) == 0 {
		return nil
	}
	release, err := m.lock(ctx)
	if err != nil {
		return err
	}
	defer release()
	// A committed, removed Link needs no further relaxed host filtering even
	// if the process crashed before its original post-Remove cleanup.
	err = store.Update(ctx, func(s *state.Snapshot) error {
		remaining := make([]state.SpoofRPFilterClaim, 0, len(s.SpoofRPFilterClaims))
		changed := false
		for _, claim := range s.SpoofRPFilterClaims {
			if _, active := s.Find(claim.LinkID); active {
				remaining = append(remaining, claim)
				continue
			}
			if _, receipt := s.FindSpoofRemovalReceipt(claim.LinkID); !receipt {
				return errors.New("unattributed rp_filter owner cannot be reconciled")
			}
			changed = true
		}
		if changed {
			settings := copyRPSettings(s.SpoofRPFilterSettings)
			composeRPFilterPlans(remaining, settings)
			s.SpoofRPFilterClaims, s.SpoofRPFilterSettings = remaining, settings
		}
		return nil
	})
	if err != nil {
		return err
	}
	return m.reconcileLocked(ctx, store)
}

// If all=2 masks an incoming NIC's strict policy, write the NIC before
// lowering all=0. When all=1 masks a Loose NIC, write all first instead.
// This minimizes unintended transient STRICT filtering during Off changes.
func orderRPFilterWrites(settings []state.SpoofRPFilterSetting) []state.SpoofRPFilterSetting {
	ordered := append([]state.SpoofRPFilterSetting(nil), settings...)
	globalLast := false
	for _, setting := range settings {
		if setting.Interface == "all" && setting.Previous == 2 && setting.Desired == 0 {
			globalLast = true
		}
	}
	if globalLast {
		slices.SortStableFunc(ordered, func(a, b state.SpoofRPFilterSetting) int {
			if a.Interface == b.Interface {
				return 0
			}
			if a.Interface == "all" {
				return 1
			}
			if b.Interface == "all" {
				return -1
			}
			return strings.Compare(a.Interface, b.Interface)
		})
	}
	return ordered
}

func (m ManagedRPFilter) reconcileLocked(ctx context.Context, store state.Store) error {
	snapshot, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if len(snapshot.SpoofRPFilterSettings) == 0 {
		return nil
	}
	// Prove every prospective write is from known baseline/current targets
	// BEFORE making any host mutation. No generic sysctl or firewall flush.
	for _, setting := range snapshot.SpoofRPFilterSettings {
		current, err := m.read(setting.Interface)
		if err != nil {
			return err
		}
		if current != setting.Original && current != setting.Previous && current != setting.Desired {
			return fmt.Errorf("%s rp_filter diverged outside STL (actual=%d; recorded original=%d previous=%d desired=%d); no automatic overwrite", setting.Interface, current, setting.Original, setting.Previous, setting.Desired)
		}
	}
	for _, setting := range orderRPFilterWrites(snapshot.SpoofRPFilterSettings) {
		current, err := m.read(setting.Interface)
		if err != nil {
			return err
		}
		if current != setting.Desired {
			if err := m.write(ctx, setting.Interface, setting.Desired); err != nil {
				return err
			}
		}
	}
	// Once each new target has been read back, discard settled last-owner
	// baselines and narrow permitted future reconciliations to current value.
	return store.Update(ctx, func(s *state.Snapshot) error {
		used := map[string]bool{}
		for _, c := range s.SpoofRPFilterClaims {
			used[c.Interface] = true
			// A Loose claim can depend on all=2 without changing it.
			// Retain that baseline for honest drift detection at Restore.
			used["all"] = true
		}
		kept := make([]state.SpoofRPFilterSetting, 0, len(s.SpoofRPFilterSettings))
		for _, setting := range s.SpoofRPFilterSettings {
			actual, err := m.read(setting.Interface)
			if err != nil || actual != setting.Desired {
				return fmt.Errorf("%s rp_filter changed during verified publication: %w", setting.Interface, err)
			}
			if !used[setting.Interface] && setting.Desired == setting.Original {
				continue
			}
			setting.Previous = setting.Desired
			kept = append(kept, setting)
		}
		s.SpoofRPFilterSettings = kept
		return nil
	})
}

var _ app.SpoofRPFilterManager = ManagedRPFilter{}
