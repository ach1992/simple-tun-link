//go:build linux

package spoofhost

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
	spoofbackend "github.com/ach1992/simple-tun-link/internal/backend/spoof"
	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type Host struct{ root, executable string }

func New(root, executable string) (*Host, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" ||
		!filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return nil, errors.New("Spoof requires exact absolute State root and installed executable")
	}
	return &Host{root: root, executable: executable}, nil
}
func UnitName(id domain.LinkID) string        { return "simple-tun-link-spoof-" + string(id) + ".service" }
func unitDescription(id domain.LinkID) string { return "STL-SPOOF-MANAGED-" + string(id) }
func (h *Host) run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("Spoof host command cancelled")
	}
	path := ""
	switch tool {
	case "systemctl", "systemd-run":
		path = "/usr/bin/" + tool
	case "ip":
		path = "/usr/bin/ip"
	default:
		return nil, errors.New("unexpected Spoof host command")
	}
	timeout, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(timeout, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	data, err := cmd.CombinedOutput()
	if len(data) > 64*1024 {
		return nil, errors.New("Spoof host output exceeds diagnostics buffer")
	}
	if err != nil {
		return nil, fmt.Errorf("Spoof %s %v failed: %w: %s", tool, args, err, strings.TrimSpace(string(data)))
	}
	return data, nil
}
func parseProperties(data []byte) (map[string]string, error) {
	props := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || name == "" {
			return nil, errors.New("invalid Spoof systemd property")
		}
		if _, seen := props[name]; seen {
			return nil, errors.New("duplicate Spoof systemd property")
		}
		props[name] = value
	}
	return props, nil
}
func (h *Host) unitStatus(ctx context.Context, link domain.Link) (exists, owned, active bool, pid int, err error) {
	name := UnitName(link.ID)
	raw, err := h.run(ctx, "systemctl", "--system", "show", name,
		"--property=Id,LoadState,Transient,FragmentPath,Description,ActiveState,SubState,MainPID,ExecStart,ControlGroup",
		"--no-pager", "--all")
	if err != nil {
		return false, false, false, 0, err
	}
	v, err := parseProperties(raw)
	if err != nil {
		return false, false, false, 0, err
	}
	if v["LoadState"] == "not-found" {
		return false, false, false, 0, nil
	}
	exists = true
	config, err := configPath(h.root, link.ID)
	if err != nil {
		return true, false, false, 0, err
	}
	command := h.executable + " spoof-helper --config " + config
	owned = v["Id"] == name && v["LoadState"] == "loaded" && v["Transient"] == "yes" &&
		v["FragmentPath"] == "/run/systemd/transient/"+name && v["Description"] == unitDescription(link.ID) &&
		strings.Contains(v["ExecStart"], command)
	if !owned {
		return true, false, false, 0, nil
	}
	if v["ActiveState"] != "active" || v["SubState"] != "running" {
		return true, true, false, 0, nil
	}
	pid, err = strconv.Atoi(v["MainPID"])
	if err != nil || pid <= 1 {
		return true, false, false, 0, errors.New("Spoof systemd MainPID invalid")
	}
	args, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return true, false, false, 0, fmt.Errorf("Spoof original helper cannot be inspected: %w", err)
	}
	parts := strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
	expected := []string{h.executable, "spoof-helper", "--config", config}
	if len(parts) != len(expected) {
		return true, false, false, 0, errors.New("Spoof original helper argv changed")
	}
	for i := range expected {
		if parts[i] != expected[i] {
			return true, false, false, 0, errors.New("Spoof original helper executable identity changed")
		}
	}
	return true, true, true, pid, nil
}
func (h *Host) inspectTUN(ctx context.Context, link domain.Link) (exists, owned, addressReady, route bool, err error) {
	name, err := carrier.TunnelName(link.ID)
	if err != nil {
		return false, false, false, false, err
	}
	if _, err = os.Lstat(filepath.Join("/sys/class/net", name)); os.IsNotExist(err) {
		return false, false, false, false, nil
	} else if err != nil {
		return false, false, false, false, err
	}
	exists = true
	nic, err := net.InterfaceByName(name)
	if err != nil {
		return true, false, false, false, err
	}
	alias, err := os.ReadFile(filepath.Join("/sys/class/net", name, "ifalias"))
	if err != nil {
		return true, false, false, false, err
	}
	owned = strings.TrimSpace(string(alias)) == "stl:spoof:"+string(link.ID)
	addresses, err := nic.Addrs()
	if err != nil {
		return true, owned, false, false, err
	}
	count := 0
	for _, v := range addresses {
		p, e := netip.ParsePrefix(v.String())
		if e == nil && p.Addr().Is4() {
			count++
			addressReady = p == link.Addresses.Local
		}
	}
	addressReady = addressReady && count == 1 && nic.Flags&net.FlagUp != 0
	raw, err := h.run(ctx, "ip", "-4", "-json", "route", "get", link.Addresses.Peer.Addr().String())
	if err != nil {
		return true, owned, addressReady, false, err
	}
	var routes []struct {
		Dev       string `json:"dev"`
		Src       string `json:"src"`
		Preferred string `json:"prefsrc"`
	}
	if json.Unmarshal(raw, &routes) != nil || len(routes) != 1 {
		return true, owned, addressReady, false, errors.New("Spoof private route inventory invalid")
	}
	source := routes[0].Preferred
	if source == "" {
		source = routes[0].Src
	}
	route = routes[0].Dev == name && source == link.Addresses.Local.Addr().String()
	return exists, owned, addressReady, route, nil
}
func (h *Host) Inspect(ctx context.Context, link domain.Link) (spoofbackend.HostObservation, error) {
	var out spoofbackend.HostObservation
	if link.Backend != domain.BackendSpoof || link.Validate() != nil {
		return out, errors.New("Spoof host Link invalid")
	}
	var err error
	out.UnitExists, out.UnitOwned, out.UnitActive, out.HelperPID, err = h.unitStatus(ctx, link)
	if err != nil {
		return out, err
	}
	out.InterfaceExists, out.InterfaceOwned, out.AddressReady, out.PeerRoute, err = h.inspectTUN(ctx, link)
	if err != nil {
		return out, err
	}
	if out.UnitOwned && out.UnitActive && out.InterfaceOwned && out.AddressReady && out.PeerRoute {
		out.RuntimeReady = h.verifyMaterialConfig(link) == nil
	}
	return out, nil
}
func (h *Host) verifyMaterialConfig(link domain.Link) error {
	material, _, err := ReadMaterial(h.root, link.ID, link.Spoof.MaterialSHA256)
	if err != nil {
		return err
	}
	if err = ConfirmLocalIdentity(link, material); err != nil {
		return err
	}
	stored, err := ReadConfig(h.root, link.ID)
	if err != nil {
		return err
	}
	expected, err := normalizedConfig(link)
	if err != nil || stored.Link != expected.Link {
		return errors.New("Spoof helper configuration differs from confirmed Link")
	}
	return nil
}
func (h *Host) Preflight(ctx context.Context, link domain.Link, removing bool) error {
	if h == nil || os.Geteuid() != 0 || link.Validate() != nil || link.Backend != domain.BackendSpoof {
		return errors.New("Spoof root/Link admission failed")
	}
	pidOne, err := os.ReadFile("/proc/1/comm")
	if err != nil || string(pidOne) != "systemd\n" {
		return errors.New("Spoof managed helper requires host systemd")
	}
	if err = h.verifyMaterialConfig(link); err != nil {
		return err
	}
	exe, err := os.Stat(h.executable)
	if err != nil || !exe.Mode().IsRegular() || exe.Mode().Perm()&0o022 != 0 || exe.Mode().Perm()&0o111 == 0 {
		return errors.New("Spoof executable must be installed root-owned regular executable")
	}
	if !removing {
		if len(link.Spoof.SourceFile) == 0 {
			return errors.New("Spoof Source file not configured")
		}
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
		return nil, errors.New("Spoof foreign/partial helper cannot be adopted")
	}
	unit := UnitName(link.ID)
	if before.UnitExists {
		_, err = h.run(ctx, "systemctl", "--system", "restart", unit, "--no-pager")
	} else {
		path, _ := configPath(h.root, link.ID)
		_, err = h.run(ctx, "systemd-run", "--system", "--collect", "--unit="+unit,
			"--description="+unitDescription(link.ID), "--property=Type=exec",
			"--property=Restart=on-failure", "--property=RestartSec=3s",
			"--property=UMask=0077", "--property=NoNewPrivileges=yes",
			h.executable, "spoof-helper", "--config", path)
	}
	undo := func(c context.Context) error { _, e := h.Stop(c, link); return e }
	if err != nil {
		after, e := h.Inspect(ctx, link)
		if e != nil || after.UnitExists && !after.UnitOwned {
			return nil, fmt.Errorf("Spoof start effect uncertain: %w", core.ErrIndeterminateHostEffect)
		}
		if after.UnitExists {
			return undo, err
		}
		return nil, err
	}
	for i := 0; i < 50; i++ {
		now, e := h.Inspect(ctx, link)
		if e != nil {
			return undo, e
		}
		if now.RuntimeReady {
			return undo, nil
		}
		if now.UnitExists && !now.UnitOwned || now.InterfaceExists && !now.InterfaceOwned && !(now.UnitOwned && now.UnitActive) {
			return nil, fmt.Errorf("Spoof ownership changed during start: %w", core.ErrIndeterminateHostEffect)
		}
		select {
		case <-ctx.Done():
			return undo, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return undo, errors.New("Spoof helper did not produce owned TUN/route locally; peer reachability is not required")
}
func (h *Host) Stop(ctx context.Context, link domain.Link) (core.Rollback, error) {
	before, err := h.Inspect(ctx, link)
	if err != nil {
		return nil, err
	}
	if !before.UnitExists && !before.InterfaceExists {
		return nil, nil
	}
	if !before.UnitOwned || before.InterfaceExists && !before.InterfaceOwned {
		return nil, errors.New("Spoof cannot stop unverified original helper/TUN")
	}
	if err := h.Preflight(ctx, link, true); err != nil {
		return nil, err
	}
	_, err = h.run(ctx, "systemctl", "--system", "stop", UnitName(link.ID), "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("Spoof stop dispatched but outcome unknown: %w", core.ErrIndeterminateHostEffect)
	}
	undo := func(c context.Context) error { _, e := h.Start(c, link); return e }
	for i := 0; i < 40; i++ {
		after, e := h.Inspect(ctx, link)
		if e != nil {
			return nil, fmt.Errorf("Spoof stopped helper inspection incomplete: %w", core.ErrIndeterminateHostEffect)
		}
		if !after.UnitExists && !after.InterfaceExists {
			return undo, nil
		}
		if after.UnitExists && !after.UnitOwned || after.InterfaceExists && !after.InterfaceOwned {
			return nil, fmt.Errorf("Spoof ownership changed after stop: %w", core.ErrIndeterminateHostEffect)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("Spoof stop timed out: %w", core.ErrIndeterminateHostEffect)
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("Spoof stop could not prove owned unit/TUN absence: %w", core.ErrIndeterminateHostEffect)
}

var _ spoofbackend.Host = (*Host)(nil)
