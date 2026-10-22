package wss

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"golang.org/x/sys/unix"
)

// This digest is for the upstream official wstunnel v11.0.0 Linux amd64
// executable, independently verified by scripts/e2e/wss-v11-compat.sh.
const PinnedAMD64SHA256 = "6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49"
const PinnedARM64SHA256 = "c0fa96ec1ceb9275137939159f095d1063b0365641e9d63f84d032c23c7c81ed"
const DefaultExecutable = "/usr/local/libexec/stl/wstunnel"

// Host is the admitted per-Link nft guard and systemd-managed sidecar runtime.
// The owning WireGuard backend invokes it ONLY under Engine resource locks.
type Host struct {
	StateRoot string
	Binary    string
	SHA256    string
	Runner    linux.BoundedRunner
}

func (h Host) binary() string {
	if h.Binary != "" {
		return h.Binary
	}
	return DefaultExecutable
}
func (h Host) digest() string {
	if h.SHA256 != "" {
		return h.SHA256
	}
	if runtime.GOARCH == "arm64" {
		return PinnedARM64SHA256
	}
	return PinnedAMD64SHA256
}
func (h Host) runner() linux.BoundedRunner {
	if h.Runner != nil {
		return h.Runner
	}
	return linux.ExecRunner{}
}
func (h Host) guard(link domain.Link) (linux.WSSWGIngressPlan, error) {
	return linux.NewWSSWGIngressPlan(link.ID, link.WireGuard.ListenPort)
}
func (h Host) GuardPresent(ctx context.Context, link domain.Link) (bool, error) {
	guard, err := h.guard(link)
	if err != nil {
		return false, err
	}
	// Absence is established with a successful full-table inventory, NEVER
	// by guessing that a failed exact-table query means "not found".
	out, err := h.runner().RunBounded(ctx, linux.CaptureLimits{Stdout: 8 << 20, Stderr: 64 << 10}, "nft", "-j", "list", "tables")
	if err != nil {
		return false, fmt.Errorf("nft table inventory unavailable: %w", err)
	}
	// nft -j list tables MUST yield one supported metadata entry plus
	// a non-null table array. encoding/json alone silently accepts null,
	// absent members, duplicate keys and unexpected object types.
	if err := linux.ValidateWSSWGJSONMembers(out.Stdout); err != nil {
		return false, fmt.Errorf("ambiguous nft table inventory: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(out.Stdout))
	decoder.DisallowUnknownFields()
	var inventory struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := decoder.Decode(&inventory); err != nil || inventory.Nftables == nil {
		return false, fmt.Errorf("incomplete nft table inventory")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false, fmt.Errorf("nft inventory has trailing content")
	}
	found := false
	meta := 0
	seen := map[string]bool{}
	for _, entry := range inventory.Nftables {
		if len(entry) != 1 {
			return false, fmt.Errorf("ambiguous nft table inventory entry")
		}
		for kind, raw := range entry {
			switch kind {
			case "metainfo":
				var m struct {
					Version           string `json:"version"`
					ReleaseName       string `json:"release_name"`
					JSONSchemaVersion int    `json:"json_schema_version"`
				}
				if decodeStrictWSSJSON(raw, &m) != nil || m.Version == "" ||
					m.JSONSchemaVersion != 1 || meta != 0 {
					return false, fmt.Errorf("unsupported nft inventory metadata")
				}
				meta++
			case "table":
				var row struct {
					Family string `json:"family"`
					Name   string `json:"name"`
					Handle uint64 `json:"handle,omitempty"`
				}
				if decodeStrictWSSJSON(raw, &row) != nil || row.Name == "" ||
					!slices.Contains([]string{"inet", "ip", "ip6", "arp", "bridge", "netdev"}, row.Family) {
					return false, fmt.Errorf("invalid nft table inventory row")
				}
				key := row.Family + "\x00" + row.Name
				if seen[key] {
					return false, fmt.Errorf("duplicate nft table identity")
				}
				seen[key] = true
				if row.Name == guard.TableName() && row.Family == "inet" {
					found = true
				}
			default:
				return false, fmt.Errorf("nft table inventory contains unsupported object")
			}
		}
	}
	if meta != 1 {
		return false, fmt.Errorf("missing nft table inventory metadata")
	}
	if !found {
		return false, nil
	}
	table, err := h.runner().RunBounded(ctx, linux.CaptureLimits{Stdout: 1 << 20, Stderr: 64 << 10},
		"nft", "-j", "list", "table", "inet", guard.TableName())
	if err != nil {
		return false, fmt.Errorf("WSS guard table drifted after inventory: %w", err)
	}
	if err := guard.VerifyNFTJSON(table.Stdout); err != nil {
		return false, fmt.Errorf("foreign or malformed WSS nft table: %w", err)
	}
	return true, nil
}

func decodeStrictWSSJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON object")
	}
	return nil
}

func (h Host) unitName(link domain.Link) string        { return "stl-wss-" + string(link.ID)[4:] + ".service" }
func (h Host) unitDescription(link domain.Link) string { return "STL-WSS-" + string(link.ID) }

type unitState struct{ loaded, active bool }

func (h Host) inspectUnit(ctx context.Context, link domain.Link) (unitState, error) {
	out, err := h.runner().RunBounded(ctx, linux.CaptureLimits{Stdout: 64 << 10, Stderr: 64 << 10},
		"systemctl", "show", h.unitName(link),
		"--property=LoadState,ActiveState,Description,Transient,ExecStart,Environment,Type,Restart,RestartUSec,NoNewPrivileges,PrivateTmp,ProtectSystem,ProtectHome,CollectMode",
		"--no-pager")
	if err != nil {
		return unitState{}, fmt.Errorf("cannot inspect WSS helper unit: %w", err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out.Stdout)), "\n") {
		if line == "" {
			continue
		}
		pieces := strings.SplitN(line, "=", 2)
		if len(pieces) != 2 {
			return unitState{}, fmt.Errorf("unexpected systemd unit observation")
		}
		if _, exists := values[pieces[0]]; exists {
			return unitState{}, fmt.Errorf("ambiguous systemd unit observation")
		}
		values[pieces[0]] = pieces[1]
	}
	if values["LoadState"] == "not-found" {
		// A truncated query or conflicting asynchronous state is not
		// evidence of a fully collected transient unit.
		for _, k := range []string{"LoadState", "ActiveState", "Transient", "ExecStart", "Environment", "CollectMode"} {
			if _, ok := values[k]; !ok {
				return unitState{}, fmt.Errorf("incomplete systemd not-found observation")
			}
		}
		if values["ActiveState"] != "inactive" || values["Transient"] != "no" ||
			values["ExecStart"] != "" || values["Environment"] != "" ||
			values["CollectMode"] != "inactive" {
			return unitState{}, fmt.Errorf("systemd not-found observation is contradictory")
		}
		return unitState{}, nil
	}
	if values["LoadState"] != "loaded" || values["Transient"] != "yes" ||
		values["Description"] != h.unitDescription(link) {
		return unitState{}, fmt.Errorf("foreign or unexpected WSS unit identity")
	}
	// A matching unit name, binary pathname or service description alone
	// is NOT authority to stop/restart a potentially foreign process.
	// Require the exact non-secret argv AND TLS trust-root environment.
	cmd, err := h.command(link)
	if err != nil {
		return unitState{}, fmt.Errorf("cannot inspect the protected WSS unit identity")
	}
	defer clear(cmd.ServerRestrictions)
	if !matchesExactWSSExecStart(values["ExecStart"], cmd) {
		return unitState{}, fmt.Errorf("WSS unit argv differs from Link identity")
	}
	if strings.TrimSpace(values["Environment"]) != strings.Join(cmd.Env, " ") {
		return unitState{}, fmt.Errorf("WSS unit TLS trust environment differs from Link identity")
	}
	if err := verifyWSSUnitSecurityProperties(values); err != nil {
		return unitState{}, err
	}
	if values["ActiveState"] != "active" && values["ActiveState"] != "inactive" &&
		values["ActiveState"] != "failed" && values["ActiveState"] != "activating" {
		return unitState{}, fmt.Errorf("unexpected WSS helper service state")
	}
	return unitState{loaded: true, active: values["ActiveState"] == "active"}, nil
}

func verifyWSSUnitSecurityProperties(values map[string]string) error {
	for key, want := range map[string]string{
		"Type": "exec", "Restart": "on-failure", "RestartUSec": "2s",
		"NoNewPrivileges": "yes", "PrivateTmp": "yes",
		"ProtectSystem": "strict", "ProtectHome": "yes",
		"CollectMode": "inactive-or-failed",
	} {
		if values[key] != want {
			return fmt.Errorf("WSS helper unit security/restart property differs: %s", key)
		}
	}
	return nil
}

// ExecStart is systemd's typed show-property representation, not a shell
// command. Values after argv[] are runtime status metadata, never extra argv.
// All STL-generated WSS arguments are single whitespace-free elements.
func matchesExactWSSExecStart(observed string, expected Command) bool {
	if expected.Binary == "" || len(expected.Args) == 0 {
		return false
	}
	if strings.Count(observed, "argv[]=") != 1 {
		return false
	}
	if !strings.Contains(observed, "path="+expected.Binary+" ") {
		return false
	}
	remainder := strings.SplitN(observed, "argv[]=", 2)[1]
	if i := strings.Index(remainder, " ;"); i >= 0 {
		remainder = remainder[:i]
	}
	actual := strings.Fields(strings.TrimSpace(remainder))
	wanted := append([]string{expected.Binary}, expected.Args...)
	return slices.Equal(actual, wanted)
}

func (h Host) HelperPresent(ctx context.Context, link domain.Link) (bool, error) {
	s, err := h.inspectUnit(ctx, link)
	return s.active, err
}

// HelperLoaded reports even an inactive/failed but still registered transient
// unit. It must be stopped and collected before credential retirement.
func (h Host) HelperLoaded(ctx context.Context, link domain.Link) (bool, error) {
	s, err := h.inspectUnit(ctx, link)
	return s.loaded, err
}

func (h Host) Preflight(ctx context.Context, link domain.Link, guardPresent bool) error {
	carrier := composition.CarrierForLink(link)
	path, err := composition.Build(link, carrier)
	if err != nil {
		return err
	}
	if _, err := InspectCredentials(link, carrier, h.StateRoot); err != nil {
		return fmt.Errorf("WSS credentials: %w", err)
	}
	if _, err := InspectPinnedExecutable(h.binary(), h.digest()); err != nil {
		return fmt.Errorf("WSS approved helper: %w", err)
	}
	guard, err := h.guard(link)
	if err != nil {
		return err
	}
	if guardPresent {
		actual, err := h.GuardPresent(ctx, link)
		if err != nil {
			return err
		}
		if !actual {
			return fmt.Errorf("expected committed WSS guard is absent")
		}
		if err := guard.ProbeWSSWGFirewallCoexistenceWithOwnedGuard(ctx, h.runner()); err != nil {
			return fmt.Errorf("WSS existing-guard host firewall reinspection: %w", err)
		}
	} else if err := guard.ProbeWSSWGFirewallCoexistence(ctx, h.runner()); err != nil {
		return err
	}
	if path.Role == composition.Listen {
		claim := domain.ResourceClaim{Kind: domain.ResourceTCPListenPort,
			Key: strconv.Itoa(int(path.WSSLocalTCP.Port()))}
		unit, err := h.inspectUnit(ctx, link)
		if err != nil {
			return err
		}
		if !unit.active {
			probe := linux.TCPListenerProbe{Runner: h.runner()}
			foreign, err := probe.InspectResource(ctx, claim)
			if err != nil {
				return err
			}
			if len(foreign) != 0 {
				return fmt.Errorf("WSS TCP port is already occupied")
			}
		}
	}
	return nil
}
func (h Host) runNFT(ctx context.Context, batch string) error {
	if len(batch) == 0 || len(batch) > 4096 {
		return fmt.Errorf("invalid bounded nft batch")
	}
	scoped, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(scoped, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	// Do not write raw nft stderr into generic logs; foreign rules may
	// carry confidential comments. No shell interpolation is used.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("scoped nft transaction failed: %w", err)
	}
	return nil
}
func (h Host) EnsureGuard(ctx context.Context, link domain.Link) (core.Rollback, error) {
	present, err := h.GuardPresent(ctx, link)
	if err != nil {
		return nil, err
	}
	if present {
		return func(context.Context) error { return nil }, nil
	}
	guard, _ := h.guard(link)
	batch, err := guard.NFTBatch()
	if err != nil {
		return nil, err
	}
	if err := h.runNFT(ctx, batch); err != nil {
		// A dispatched nft transaction can succeed despite its client
		// returning an error. The journal preserves uncertain ownership.
		probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_, _ = h.GuardPresent(probeCtx, link)
		cancel()
		return nil, fmt.Errorf("%w: nft guard dispatch outcome is uncertain", core.ErrIndeterminateHostEffect)
	}
	// Once the atomic CREATE succeeded, returning an undo is mandatory
	// even if the next readback cannot be completed.
	undo := func(c context.Context) error {
		_, err := h.RemoveGuard(c, link)
		return err
	}
	ok, err := h.GuardPresent(ctx, link)
	if err != nil {
		return undo, err
	}
	if !ok {
		return undo, fmt.Errorf("created nft ingress rule not observable")
	}
	return undo, nil
}
func (h Host) RemoveGuard(ctx context.Context, link domain.Link) (core.Rollback, error) {
	guard, err := h.guard(link)
	if err != nil {
		return nil, err
	}
	present, err := h.GuardPresent(ctx, link)
	if err != nil {
		return nil, err
	}
	if !present {
		return func(context.Context) error { return nil }, nil
	}
	if err := h.runNFT(ctx, "delete table inet "+guard.TableName()+"\n"); err != nil {
		return nil, fmt.Errorf("%w: nft guard delete outcome uncertain", core.ErrIndeterminateHostEffect)
	}
	undo := func(c context.Context) error { _, err := h.EnsureGuard(c, link); return err }
	present, err = h.GuardPresent(ctx, link)
	if err != nil {
		return undo, err
	}
	if present {
		return undo, fmt.Errorf("WSS guard still present after Remove")
	}
	return undo, nil
}

// The secret is read from a descriptor-verified Link-owned directory, then
// cleared after constructing the never-logged restricted server policy.
func (h Host) token(link domain.Link) (string, error) {
	fd, err := credentials.OpenProtected(h.StateRoot, false)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	folder, err := openOwnedPrivateDir(fd, "wss")
	if err != nil {
		return "", err
	}
	defer unix.Close(folder)
	owned, err := openOwnedPrivateDir(folder, string(link.ID))
	if err != nil {
		return "", err
	}
	defer unix.Close(owned)
	name := "authorization-token"
	if link.WSS.Role == "dial" {
		name = "authorization-headers"
	}
	raw, err := readPrivateFile(owned, name)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	if name == "authorization-token" {
		if len(raw) != 65 || raw[64] != '\n' {
			return "", fmt.Errorf("invalid private authorization token")
		}
		return string(raw[:64]), nil
	}
	const prefix = "Authorization: Bearer "
	if !bytes.HasPrefix(raw, []byte(prefix)) || len(raw) != len(prefix)+65 || raw[len(raw)-1] != '\n' {
		return "", fmt.Errorf("invalid private authorization header")
	}
	return string(raw[len(prefix) : len(raw)-1]), nil
}

// Write generated restrictions once, without replacing an existing secret.
// A failed prior write is reconciled by exact byte equality, never by chmod
// or adoption of a different file/inode.
func (h Host) ensureRestrictions(link domain.Link, data []byte) error {
	folder := filepath.Join(h.StateRoot, "credentials", "wss", string(link.ID))
	name := filepath.Join(folder, "restrictions.yaml")
	if err := WritePrivateNoReplace(name, data); err != nil {
		return err
	}
	return nil
}
func (h Host) command(link domain.Link) (Command, error) {
	token, err := h.token(link)
	if err != nil {
		return Command{}, err
	}
	if !validAuthorizationToken(token) {
		return Command{}, fmt.Errorf("invalid WSS token")
	}
	cmd, err := Build(link, composition.CarrierForLink(link), h.binary(), h.StateRoot, token)
	token = "" // drop the temporary string reference
	return cmd, err
}

func (h Host) StartHelper(ctx context.Context, link domain.Link) (core.Rollback, error) {
	if err := h.Preflight(ctx, link, true); err != nil {
		return nil, err
	}
	unit, err := h.inspectUnit(ctx, link)
	if err != nil {
		return nil, err
	}
	if unit.active {
		return func(context.Context) error { return nil }, nil
	}
	command, err := h.command(link)
	if err != nil {
		return nil, err
	}
	defer clear(command.ServerRestrictions)
	if len(command.ServerRestrictions) != 0 {
		if err := h.ensureRestrictions(link, command.ServerRestrictions); err != nil {
			return nil, err
		}
	}
	// Revalidate immediately before handing over execution to systemd.
	if _, err := InspectPinnedExecutable(h.binary(), h.digest()); err != nil {
		return nil, err
	}
	if unit.loaded {
		_, err = h.runner().Run(ctx, "systemctl", "restart", h.unitName(link))
	} else {
		args := []string{
			"--unit=" + strings.TrimSuffix(h.unitName(link), ".service"),
			"--description=" + h.unitDescription(link),
			"--collect", "--property=Restart=on-failure", "--property=RestartSec=2s",
			"--property=Type=exec", "--property=NoNewPrivileges=yes",
			"--property=PrivateTmp=yes", "--property=ProtectSystem=strict",
			"--property=ProtectHome=yes",
		}
		for _, env := range command.Env {
			if !strings.HasPrefix(env, "SSL_CERT_FILE=") {
				return nil, fmt.Errorf("unsupported WSS environment")
			}
			args = append(args, "--setenv="+env)
		}
		args = append(args, command.Binary)
		args = append(args, command.Args...)
		_, err = h.runner().Run(ctx, "systemd-run", args...)
	}
	if err != nil {
		probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_, _ = h.inspectUnit(probeCtx, link)
		cancel()
		return nil, fmt.Errorf("%w: WSS helper start outcome is uncertain", core.ErrIndeterminateHostEffect)
	}
	undo := func(c context.Context) error { _, err := h.StopHelper(c, link); return err }
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		active, err := h.HelperPresent(ctx, link)
		if err != nil {
			return undo, err
		}
		if active {
			return undo, nil
		}
		select {
		case <-ctx.Done():
			return undo, ctx.Err()
		case <-deadline.C:
			return undo, fmt.Errorf("WSS helper readiness exceeded startup deadline")
		case <-tick.C:
		}
	}
}
func (h Host) StopHelper(ctx context.Context, link domain.Link) (core.Rollback, error) {
	unit, err := h.inspectUnit(ctx, link)
	if err != nil {
		return nil, err
	}
	if !unit.loaded {
		return func(context.Context) error { return nil }, nil
	}
	_, err = h.runner().Run(ctx, "systemctl", "stop", h.unitName(link))
	if err != nil {
		return nil, fmt.Errorf("%w: WSS helper stop outcome uncertain", core.ErrIndeterminateHostEffect)
	}
	undo := func(c context.Context) error {
		if !unit.active {
			return nil
		}
		_, err := h.StartHelper(c, link)
		return err
	}
	// --collect is asynchronous on real systemd. An inactive/failed unit
	// still reserves this identity and may have a queued Restart job; only
	// the exact unit's verified disappearance permits key retirement.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		loaded, err := h.HelperLoaded(ctx, link)
		if err != nil {
			return undo, err
		}
		if !loaded {
			return undo, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: WSS Stop cancellation before unit collection", core.ErrIndeterminateHostEffect)
		case <-deadline.C:
			return nil, fmt.Errorf("%w: WSS Stop did not collect loaded unit", core.ErrIndeterminateHostEffect)
		case <-ticker.C:
		}
	}
}

// WritePrivateNoReplace is for already verified owner-private credential
// paths only; no general-purpose file publication is exposed here.
func WritePrivateNoReplace(path string, data []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(data) == 0 || len(data) > 1<<20 {
		return fmt.Errorf("invalid protected credential publication")
	}
	parent := filepath.Dir(path)
	var stat unix.Stat_t
	if err := unix.Lstat(parent, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o700 {
		return fmt.Errorf("credential directory must already be owner-private")
	}
	name := filepath.Base(path)
	dirfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat(dirfd, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if errors.Is(err, unix.EEXIST) {
		current, readErr := readPrivateFile(dirfd, name)
		if readErr != nil {
			return readErr
		}
		defer clear(current)
		if !bytes.Equal(current, data) {
			return fmt.Errorf("different protected credential already exists")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("private credential creation failed: %w", err)
	}
	file := os.NewFile(uintptr(fd), "private-wss-credential")
	count, writeErr := file.Write(data)
	if writeErr != nil || count != len(data) {
		file.Close()
		return fmt.Errorf("private credential write incomplete")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("credential sync failed: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Fsync(dirfd); err != nil {
		return err
	}
	return nil
}

// HelperDiagnostics are secret-free observations; a running process does
// not assert mTLS success or a kernel WireGuard handshake.
type HelperDiagnostics struct {
	Guard              bool   `json:"guard"`
	Helper             bool   `json:"helper"`
	Authentication     string `json:"authentication"`
	WireGuardHandshake string `json:"wireguard_handshake"`
}

func (h Host) Diagnose(ctx context.Context, link domain.Link) (HelperDiagnostics, error) {
	guard, err := h.GuardPresent(ctx, link)
	if err != nil {
		return HelperDiagnostics{}, err
	}
	helper, err := h.HelperPresent(ctx, link)
	if err != nil {
		return HelperDiagnostics{}, err
	}
	return HelperDiagnostics{Guard: guard, Helper: helper,
		Authentication: "not_observed", WireGuardHandshake: "not_observed"}, nil
}

var _ = sha256.Sum256
var _ = hex.EncodeToString

// InspectPinnedExecutableForOperator is read-only menu admission. Runtime
// revalidates the executable identity under the canonical Engine Link lock.
func InspectPinnedExecutableForOperator(h Host) (ExecutableIdentity, error) {
	return InspectPinnedExecutable(h.binary(), h.digest())
}
