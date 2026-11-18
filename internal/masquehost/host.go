// Package masquehost is the fixed production host adapter for the optional
// MASQUE provider. It never creates its own Link/State Engine, uses only
// canonical per-Link identities, and never changes default routes or firewall.
package masquehost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	masquebackend "github.com/ach1992/simple-tun-link/internal/backend/masque"
	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type Host struct {
	root       string
	executable string
}

func New(root, executable string) (*Host, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" ||
		!filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return nil, errors.New("MASQUE host requires canonical State root and STL executable")
	}
	return &Host{root: root, executable: executable}, nil
}

func unitName(id domain.LinkID) string        { return "simple-tun-link-masque-" + string(id) + ".service" }
func unitDescription(id domain.LinkID) string { return "STL-MASQUE-MANAGED-" + string(id) }

func (h *Host) run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("MASQUE host operation cancelled")
	}
	path := ""
	switch tool {
	case "systemctl", "systemd-run":
		path = "/usr/bin/" + tool
	case "ip":
		// On usrmerged Debian/Ubuntu, /usr/sbin/ip is a symlink to
		// /usr/bin/ip. Use the canonical root-owned regular executable;
		// never weaken no-symlink runtime admission.
		path = "/usr/bin/ip"
	default:
		return nil, errors.New("invalid MASQUE local host command")
	}
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0o022 != 0 || stat.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("MASQUE trusted host tool unavailable")
	}
	bound, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bound, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	cmd.WaitDelay = time.Second
	limited := &boundedBuffer{limit: 64 << 10}
	stderr := &boundedBuffer{limit: 8 << 10}
	cmd.Stdout = limited
	cmd.Stderr = stderr
	err = cmd.Run()
	if limited.overflow || stderr.overflow {
		return nil, errors.New("MASQUE host command output exceeded safe diagnostics bound")
	}
	if err != nil {
		// CLI stdout/stderr can contain external actor, file and credential
		// context. Keep errors classified without revealing raw payloads.
		if bound.Err() != nil {
			return nil, fmt.Errorf("MASQUE %s command timed out: %w", tool, bound.Err())
		}
		var code *exec.ExitError
		if errors.As(err, &code) {
			return nil, fmt.Errorf("MASQUE %s command returned exit %d", tool, code.ExitCode())
		}
		return nil, fmt.Errorf("MASQUE %s command failed: %w", tool, err)
	}
	return limited.Bytes(), nil
}

type boundedBuffer struct {
	value    []byte
	limit    int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remain := b.limit - len(b.value); remain < len(p) {
		b.overflow = true
		if remain > 0 {
			b.value = append(b.value, p[:remain]...)
		}
	} else {
		b.value = append(b.value, p...)
	}
	return n, nil
}
func (b *boundedBuffer) Bytes() []byte { return append([]byte(nil), b.value...) }

func parseUnitProperties(raw []byte) (map[string]string, error) {
	v := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, errors.New("invalid MASQUE systemd property report")
		}
		if _, exists := v[key]; exists {
			return nil, errors.New("duplicate MASQUE systemd property")
		}
		v[key] = value
	}
	return v, nil
}

func (h *Host) unitStatus(ctx context.Context, link domain.Link) (exists, owned, active bool, err error) {
	name := unitName(link.ID)
	raw, err := h.run(ctx, "systemctl", "--system", "show", name,
		"--property=Id,LoadState,Transient,FragmentPath,Description,ActiveState,SubState,MainPID,ExecStart,ControlGroup",
		"--no-pager", "--all")
	if err != nil {
		return false, false, false, err
	}
	data, err := parseUnitProperties(raw)
	if err != nil {
		return false, false, false, err
	}
	if data["LoadState"] == "not-found" {
		if data["ActiveState"] != "" && data["ActiveState"] != "inactive" {
			return false, false, false, errors.New("MASQUE absent service has inconsistent active state")
		}
		return false, false, false, nil
	}
	exists = true
	configPath, err := h.materialPath(link.ID)
	if err != nil {
		return true, false, false, err
	}
	configPath = filepath.Join(configPath, "agent.json")
	command := h.executable + " masque-helper " + link.MASQUE.Role + " --config " + configPath
	owned = data["Id"] == name && data["LoadState"] == "loaded" &&
		data["Transient"] == "yes" &&
		data["FragmentPath"] == "/run/systemd/transient/"+name &&
		data["Description"] == unitDescription(link.ID) &&
		strings.Contains(data["ExecStart"], command)
	if !owned {
		return true, false, false, nil
	}
	active = data["ActiveState"] == "active" && data["SubState"] == "running"
	if !active {
		return true, true, false, nil
	}
	pid, err := strconv.Atoi(data["MainPID"])
	if err != nil || pid <= 1 || data["ControlGroup"] != "/system.slice/"+name {
		return true, false, false, errors.New("MASQUE service PID or cgroup identity invalid")
	}
	rawArgs, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return true, false, false, errors.New("MASQUE original service process cannot be inspected")
	}
	args := strings.Split(strings.TrimSuffix(string(rawArgs), "\x00"), "\x00")
	want := []string{h.executable, "masque-helper", link.MASQUE.Role, "--config", configPath}
	if len(args) != len(want) {
		return true, false, false, errors.New("MASQUE systemd service process has wrong argv")
	}
	for i, arg := range args {
		if arg != want[i] {
			return true, false, false, errors.New("MASQUE systemd service executable identity differs")
		}
	}
	return true, true, true, nil
}

func (h *Host) inspectTun(ctx context.Context, link domain.Link) (exists, owned bool, index int, address netip.Prefix, route bool, err error) {
	name, err := masque.AgentInterfaceName(link.ID)
	if err != nil {
		return false, false, 0, netip.Prefix{}, false, err
	}
	ifacePath := filepath.Join("/sys/class/net", name)
	_, err = os.Lstat(ifacePath)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, 0, netip.Prefix{}, false, nil
	}
	if err != nil {
		return false, false, 0, netip.Prefix{}, false, err
	}
	exists = true
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return true, false, 0, netip.Prefix{}, false, err
	}
	index = iface.Index
	alias, err := os.ReadFile(filepath.Join(ifacePath, "ifalias"))
	if err != nil {
		return true, false, index, netip.Prefix{}, false, err
	}
	owned = strings.TrimSpace(string(alias)) == "stl:masque:"+string(link.ID)
	addrs, err := iface.Addrs()
	if err != nil {
		return true, owned, index, netip.Prefix{}, false, err
	}
	seen := 0
	for _, a := range addrs {
		if prefix, parseErr := netip.ParsePrefix(a.String()); parseErr == nil && prefix.Addr().Is4() {
			address = prefix
			seen++
		}
	}
	if seen != 1 {
		return true, owned, index, address, false, nil
	}
	// A host-wide table route cannot be assumed from a matching alias.
	raw, err := h.run(ctx, "ip", "-4", "-json", "route", "get", link.Addresses.Peer.Addr().String())
	if err != nil {
		return true, owned, index, address, false, err
	}
	var v []struct {
		Dev       string `json:"dev"`
		Source    string `json:"prefsrc"`
		AltSource string `json:"src"`
	}
	if json.Unmarshal(raw, &v) != nil || len(v) != 1 {
		return true, owned, index, address, false, errors.New("MASQUE exact private peer route inventory invalid")
	}
	src := v[0].Source
	if src == "" {
		src = v[0].AltSource
	}
	route = v[0].Dev == name && src == link.Addresses.Local.Addr().String()
	return true, owned, index, address, route, nil
}

func (h *Host) Inspect(ctx context.Context, link domain.Link) (masquebackend.HostObservation, error) {
	var out masquebackend.HostObservation
	if link.Backend != domain.BackendMASQUE || link.Validate() != nil {
		return out, errors.New("invalid MASQUE host Link")
	}
	var err error
	out.UnitExists, out.UnitOwned, out.UnitActive, err = h.unitStatus(ctx, link)
	if err != nil {
		return out, err
	}
	out.InterfaceExists, out.InterfaceOwned, out.InterfaceIndex, out.LocalAddress, out.PeerRoute, err = h.inspectTun(ctx, link)
	if err != nil {
		return out, err
	}
	if out.UnitActive && out.UnitOwned && out.InterfaceOwned && out.PeerRoute && out.LocalAddress == link.Addresses.Local {
		_, _, materialErr := h.inspectMaterial(link)
		out.RuntimeReady = materialErr == nil
	}
	return out, nil
}

// No peer reachability probe is required for a locally managed Link. The
// selected physical SOURCE must nonetheless be bound on THIS host; a route
// lookup against a remote host is not evidence of local address ownership.
func verifyLocalUnderlay(ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("MASQUE physical source invalid")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.New("MASQUE local physical interface inventory unavailable")
	}
	found := 0
	for _, nic := range interfaces {
		addrs, listErr := nic.Addrs()
		if listErr != nil {
			return errors.New("MASQUE local physical address inventory incomplete")
		}
		for _, address := range addrs {
			prefix, parseErr := netip.ParsePrefix(address.String())
			if parseErr == nil && prefix.Addr() == ip {
				found++
			}
		}
	}
	if found != 1 {
		return errors.New("MASQUE physical source address not uniquely assigned to this host")
	}
	return nil
}

func (h *Host) Preflight(ctx context.Context, link domain.Link, removing bool) error {
	if h == nil || os.Geteuid() != 0 || link.Backend != domain.BackendMASQUE || link.Validate() != nil {
		return errors.New("MASQUE host root/Link admission failed")
	}
	pidOne, err := os.ReadFile("/proc/1/comm")
	if err != nil || string(pidOne) != "systemd\n" {
		return errors.New("MASQUE requires the host systemd manager (no alternate service takeover)")
	}
	if _, _, err = h.inspectMaterial(link); err != nil {
		return err
	}
	if !removing {
		if err = verifyLocalUnderlay(link.Underlay.Local); err != nil {
			return err
		}
	}
	exe, err := os.Stat(h.executable)
	if err != nil || !exe.Mode().IsRegular() || exe.Mode().Perm()&0o022 != 0 || exe.Mode().Perm()&0o111 == 0 {
		return errors.New("MASQUE STL executable is not an attested installed regular file")
	}
	if !removing && link.MASQUE.Role == "listen" {
		// A foreign listener is not an available socket even if no matching
		// STL transient unit exists. Actual binding is rechecked by service.
	}
	return ctx.Err()
}

func (h *Host) Start(ctx context.Context, link domain.Link) (core.Rollback, error) {
	if err := h.Preflight(ctx, link, false); err != nil {
		return nil, err
	}
	before, err := h.Inspect(ctx, link)
	if err != nil {
		return nil, err
	}
	if before.RuntimeReady {
		return nil, nil
	}
	if before.InterfaceExists || before.UnitExists && !before.UnitOwned || before.UnitActive {
		return nil, errors.New("MASQUE existing host effect cannot be adopted or replaced")
	}
	unit := unitName(link.ID)
	if before.UnitExists {
		_, err = h.run(ctx, "systemctl", "--system", "restart", unit, "--no-pager")
	} else {
		d, dirErr := h.materialPath(link.ID)
		if dirErr != nil {
			return nil, dirErr
		}
		_, err = h.run(ctx, "systemd-run", "--system", "--collect",
			"--unit="+unit, "--description="+unitDescription(link.ID),
			"--property=Type=exec", "--property=Restart=on-failure", "--property=RestartSec=3s",
			"--property=UMask=0077", "--property=NoNewPrivileges=yes",
			h.executable, "masque-helper", link.MASQUE.Role, "--config", filepath.Join(d, "agent.json"))
	}
	// Even an unsuccessful manager command might have dispatched an effect.
	// Re-read the exact unit and preserve ambiguity rather than stop an
	// unrelated/newer process by name.
	if err != nil {
		after, inspectErr := h.Inspect(ctx, link)
		if inspectErr != nil || after.UnitExists && !after.UnitOwned {
			return nil, fmt.Errorf("MASQUE start dispatched but ownership unverified: %w", core.ErrIndeterminateHostEffect)
		}
		if after.UnitExists {
			return func(undoCtx context.Context) error {
				_, stopErr := h.Stop(undoCtx, link)
				return stopErr
			}, fmt.Errorf("MASQUE service start failed after owned creation: %w", err)
		}
		return nil, err
	}
	undo := func(undoCtx context.Context) error {
		_, e := h.Stop(undoCtx, link)
		return e
	}
	for i := 0; i < 25; i++ {
		now, e := h.Inspect(ctx, link)
		if e != nil {
			return undo, e
		}
		if now.RuntimeReady {
			return undo, nil
		}
		if now.UnitExists && !now.UnitOwned || now.InterfaceExists && !now.InterfaceOwned {
			return nil, fmt.Errorf("MASQUE original host effect was replaced: %w", core.ErrIndeterminateHostEffect)
		}
		select {
		case <-ctx.Done():
			return undo, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return undo, errors.New("MASQUE service did not create an attested local TUN before deadline")
}

func (h *Host) Stop(ctx context.Context, link domain.Link) (core.Rollback, error) {
	prior, err := h.Inspect(ctx, link)
	if err != nil {
		return nil, err
	}
	if !prior.UnitExists && !prior.InterfaceExists {
		return nil, nil
	}
	if !prior.UnitOwned || prior.InterfaceExists && !prior.InterfaceOwned {
		return nil, errors.New("MASQUE stop cannot prove original service/interface identity")
	}
	if err := h.Preflight(ctx, link, true); err != nil {
		return nil, err
	}
	_, err = h.run(ctx, "systemctl", "--system", "stop", unitName(link.ID), "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("MASQUE stop dispatched with uncertain effect: %w", core.ErrIndeterminateHostEffect)
	}
	undo := func(undoCtx context.Context) error {
		_, startErr := h.Start(undoCtx, link)
		return startErr
	}
	for i := 0; i < 30; i++ {
		current, e := h.Inspect(ctx, link)
		if e != nil {
			return nil, fmt.Errorf("MASQUE stop observation incomplete: %w", core.ErrIndeterminateHostEffect)
		}
		if !current.UnitExists && !current.InterfaceExists {
			return undo, nil
		}
		if current.UnitExists && !current.UnitOwned || current.InterfaceExists && !current.InterfaceOwned {
			return nil, fmt.Errorf("MASQUE stop raced with foreign owner: %w", core.ErrIndeterminateHostEffect)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("MASQUE stop timed out after dispatch: %w", core.ErrIndeterminateHostEffect)
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("MASQUE stop did not prove unit/TUN disappearance: %w", core.ErrIndeterminateHostEffect)
}

var _ masquebackend.Host = (*Host)(nil)
