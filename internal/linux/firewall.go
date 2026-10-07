package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

const firewallWaitSeconds = "5"

// InboundFirewallRule is the narrow host-firewall surface needed by tunnel
// backends: permit one peer/protocol tuple (and, for UDP, one destination port)
// on one concrete underlay interface. STL does not manage general firewall
// policy, forwarding, NAT, or arbitrary user rules.
type InboundFirewallRule struct {
	Peer            netip.Addr
	Local           netip.Addr
	InputInterface  string
	Protocol        uint8
	DestinationPort uint16
}

func (r InboundFirewallRule) Validate() error {
	if !r.Peer.IsValid() || r.Peer.IsUnspecified() || r.Peer.IsMulticast() {
		return fmt.Errorf("firewall peer must be a concrete unicast address")
	}
	if !r.Local.IsValid() || r.Local.IsUnspecified() || r.Local.IsMulticast() {
		return fmt.Errorf("firewall local address must be a concrete unicast address")
	}
	if r.Local.BitLen() != r.Peer.BitLen() {
		return fmt.Errorf("firewall local and peer addresses must use the same family")
	}
	if err := validateFirewallInterface(r.InputInterface); err != nil {
		return err
	}
	if r.Protocol == 0 {
		return fmt.Errorf("firewall IP protocol is required")
	}
	if r.Protocol == 17 {
		if r.DestinationPort == 0 {
			return fmt.Errorf("UDP firewall rule requires a destination port")
		}
	} else if r.DestinationPort != 0 {
		return fmt.Errorf("destination port is only valid for UDP firewall rules")
	}
	return nil
}

func validateFirewallInterface(name string) error {
	if name == "" || len(name) > 15 {
		return fmt.Errorf("firewall input interface must be a valid Linux interface name")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_', r == '-', r == '.', r == ':':
		default:
			return fmt.Errorf("firewall input interface contains unsupported characters")
		}
	}
	return nil
}

// IPTablesFirewall applies only exact INPUT allow rules. It uses the xtables
// compatibility commands because current Debian/Ubuntu installations may map
// those commands to either the legacy or nftables backend while retaining the
// same narrow rule semantics. All mutation remains argv-based and ownership is
// carried in an exact comment marker.
type IPTablesFirewall struct {
	Runner          Runner
	Locks           *state.LockManager
	IPTablesBinary  string
	IP6TablesBinary string
}

// EnsureInbound ensures one exact STL-owned allow rule. The returned undo
// removes only a rule added by this call. No chain flush, policy change, or
// unrelated rule mutation is ever performed.
func (f IPTablesFirewall) EnsureInbound(ctx context.Context, id domain.LinkID, rule InboundFirewallRule) (func(context.Context) error, bool, error) {
	if err := id.Validate(); err != nil {
		return nil, false, err
	}
	if err := rule.Validate(); err != nil {
		return nil, false, err
	}
	if f.Runner == nil {
		return nil, false, fmt.Errorf("firewall runner is required")
	}
	if f.Locks == nil {
		return nil, false, fmt.Errorf("firewall lock manager is required")
	}

	claim := firewallClaim(id, rule)
	release, err := f.Locks.Acquire(ctx, []domain.ResourceClaim{claim})
	if err != nil {
		return nil, false, err
	}
	defer release()

	binary := f.binary(rule.Peer)
	args := firewallRuleArgs(id, rule)
	exists, err := f.ruleExists(ctx, binary, args)
	if err != nil {
		return nil, false, err
	}
	if exists {
		return func(context.Context) error { return nil }, false, nil
	}

	insertArgs := append([]string{"-w", firewallWaitSeconds, "-I", "INPUT", "1"}, args...)
	if _, err := f.Runner.Run(ctx, binary, insertArgs...); err != nil {
		return nil, false, fmt.Errorf("add STL firewall rule: %w", err)
	}
	verified, verifyErr := f.ruleExists(ctx, binary, args)
	if verifyErr != nil || !verified {
		rollbackErr := f.deleteExact(context.WithoutCancel(ctx), binary, args)
		if verifyErr != nil {
			return nil, false, errors.Join(fmt.Errorf("verify STL firewall rule: %w", verifyErr), rollbackErr)
		}
		return nil, false, errors.Join(fmt.Errorf("verify STL firewall rule: rule not found after add"), rollbackErr)
	}

	undo := func(undoCtx context.Context) error {
		if err := undoCtx.Err(); err != nil {
			return err
		}
		undoRelease, err := f.Locks.Acquire(undoCtx, []domain.ResourceClaim{claim})
		if err != nil {
			return err
		}
		defer undoRelease()
		return f.deleteIfPresent(undoCtx, binary, args)
	}
	return undo, true, nil
}

// RemoveInbound removes only the exact STL-owned rule identified by the same
// Link ID and canonical rule fields used at creation time.
func (f IPTablesFirewall) RemoveInbound(ctx context.Context, id domain.LinkID, rule InboundFirewallRule) (bool, error) {
	if err := id.Validate(); err != nil {
		return false, err
	}
	if err := rule.Validate(); err != nil {
		return false, err
	}
	if f.Runner == nil {
		return false, fmt.Errorf("firewall runner is required")
	}
	if f.Locks == nil {
		return false, fmt.Errorf("firewall lock manager is required")
	}

	claim := firewallClaim(id, rule)
	release, err := f.Locks.Acquire(ctx, []domain.ResourceClaim{claim})
	if err != nil {
		return false, err
	}
	defer release()

	binary := f.binary(rule.Peer)
	args := firewallRuleArgs(id, rule)
	exists, err := f.ruleExists(ctx, binary, args)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if err := f.deleteExact(ctx, binary, args); err != nil {
		return false, err
	}
	stillExists, err := f.ruleExists(ctx, binary, args)
	if err != nil {
		// The delete already happened. Re-add the exact owned rule so an
		// inspection failure cannot silently leave state half-reconciled.
		restoreArgs := append([]string{"-w", firewallWaitSeconds, "-I", "INPUT", "1"}, args...)
		_, restoreErr := f.Runner.Run(context.WithoutCancel(ctx), binary, restoreArgs...)
		return false, errors.Join(fmt.Errorf("verify removed STL firewall rule: %w", err), restoreErr)
	}
	if stillExists {
		return false, fmt.Errorf("STL firewall rule still exists after exact delete")
	}
	return true, nil
}

func (f IPTablesFirewall) binary(peer netip.Addr) string {
	if peer.Is6() {
		if f.IP6TablesBinary != "" {
			return f.IP6TablesBinary
		}
		return "ip6tables"
	}
	if f.IPTablesBinary != "" {
		return f.IPTablesBinary
	}
	return "iptables"
}

func (f IPTablesFirewall) ruleExists(ctx context.Context, binary string, ruleArgs []string) (bool, error) {
	checkArgs := append([]string{"-w", firewallWaitSeconds, "-C", "INPUT"}, ruleArgs...)
	_, err := f.Runner.Run(ctx, binary, checkArgs...)
	if err == nil {
		return true, nil
	}
	var commandErr *CommandError
	if errors.As(err, &commandErr) && commandErr.ExitCode == 1 && !commandErr.TimedOut && !commandErr.Canceled {
		return false, nil
	}
	return false, fmt.Errorf("inspect STL firewall rule: %w", err)
}

func (f IPTablesFirewall) deleteIfPresent(ctx context.Context, binary string, ruleArgs []string) error {
	exists, err := f.ruleExists(ctx, binary, ruleArgs)
	if err != nil || !exists {
		return err
	}
	return f.deleteExact(ctx, binary, ruleArgs)
}

func (f IPTablesFirewall) deleteExact(ctx context.Context, binary string, ruleArgs []string) error {
	deleteArgs := append([]string{"-w", firewallWaitSeconds, "-D", "INPUT"}, ruleArgs...)
	if _, err := f.Runner.Run(ctx, binary, deleteArgs...); err != nil {
		return fmt.Errorf("remove STL firewall rule: %w", err)
	}
	return nil
}

func firewallRuleArgs(id domain.LinkID, rule InboundFirewallRule) []string {
	bits := 32
	if rule.Peer.Is6() {
		bits = 128
	}
	args := []string{
		"-i", rule.InputInterface,
		"-s", netip.PrefixFrom(rule.Peer, bits).String(),
		"-d", netip.PrefixFrom(rule.Local, bits).String(),
		"-p", strconv.Itoa(int(rule.Protocol)),
	}
	if rule.Protocol == 17 {
		args = append(args, "-m", "udp", "--dport", strconv.Itoa(int(rule.DestinationPort)))
	}
	args = append(args,
		"-m", "comment", "--comment", firewallMarker(id, rule),
		"-j", "ACCEPT",
	)
	return args
}

func firewallClaim(id domain.LinkID, rule InboundFirewallRule) domain.ResourceClaim {
	return domain.ResourceClaim{Kind: domain.ResourceFirewall, Key: firewallMarker(id, rule)}
}

func firewallMarker(id domain.LinkID, rule InboundFirewallRule) string {
	canonical := strings.Join([]string{
		rule.Peer.String(),
		rule.Local.String(),
		rule.InputInterface,
		strconv.Itoa(int(rule.Protocol)),
		strconv.Itoa(int(rule.DestinationPort)),
	}, "|")
	sum := sha256.Sum256([]byte(canonical))
	return "stl:" + string(id) + ":" + hex.EncodeToString(sum[:8])
}
