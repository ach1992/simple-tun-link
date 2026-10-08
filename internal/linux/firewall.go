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

// EnsureInbound ensures one exact STL-owned allow rule. New rules are appended
// so pre-existing administrator policy keeps precedence. The returned undo
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

	if err := f.appendExact(ctx, binary, args); err != nil {
		rollbackErr := f.restoreRuleAbsent(context.WithoutCancel(ctx), binary, args)
		return nil, false, errors.Join(err, wrapFirewallError("restore pre-add firewall state", rollbackErr))
	}

	verified, verifyErr := f.ruleExists(ctx, binary, args)
	if verifyErr != nil || !verified {
		rollbackErr := f.restoreRuleAbsent(context.WithoutCancel(ctx), binary, args)
		if verifyErr != nil {
			return nil, false, errors.Join(
				fmt.Errorf("verify STL firewall rule: %w", verifyErr),
				wrapFirewallError("restore pre-add firewall state", rollbackErr),
			)
		}
		return nil, false, errors.Join(
			fmt.Errorf("verify STL firewall rule: rule not found after add"),
			wrapFirewallError("restore pre-add firewall state", rollbackErr),
		)
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
// Link ID and canonical rule fields used at creation time. If the delete
// command or its verification is ambiguous, the operation reports failure and
// attempts to restore the exact pre-operation owned rule.
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
		restoreErr := f.restoreRulePresent(context.WithoutCancel(ctx), binary, args)
		return false, errors.Join(err, wrapFirewallError("restore pre-delete firewall state", restoreErr))
	}

	stillExists, verifyErr := f.ruleExists(ctx, binary, args)
	if verifyErr != nil {
		restoreErr := f.restoreRulePresent(context.WithoutCancel(ctx), binary, args)
		return false, errors.Join(
			fmt.Errorf("verify removed STL firewall rule: %w", verifyErr),
			wrapFirewallError("restore pre-delete firewall state", restoreErr),
		)
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

// ruleExists treats only a successful -C as positive proof of exact presence.
// Any -C failure is ambiguous across supported xtables implementations, so a
// successful read-only INPUT listing must independently prove that the STL
// ownership marker is absent before this function can report absence.
func (f IPTablesFirewall) ruleExists(ctx context.Context, binary string, ruleArgs []string) (bool, error) {
	checkArgs := append([]string{"-w", firewallWaitSeconds, "-C", "INPUT"}, ruleArgs...)
	_, checkErr := f.Runner.Run(ctx, binary, checkArgs...)
	if checkErr == nil {
		return true, nil
	}

	marker, err := firewallMarkerFromArgs(ruleArgs)
	if err != nil {
		return false, err
	}
	listResult, listErr := f.Runner.Run(ctx, binary, "-w", firewallWaitSeconds, "-S", "INPUT")
	if listErr != nil {
		return false, errors.Join(
			fmt.Errorf("check exact STL firewall rule: %w", checkErr),
			fmt.Errorf("list INPUT firewall rules: %w", listErr),
		)
	}
	if firewallListingHasMarker(listResult.Stdout, marker) {
		return false, errors.Join(
			fmt.Errorf("check exact STL firewall rule: %w", checkErr),
			fmt.Errorf("STL firewall ownership marker is present but exact rule could not be verified"),
		)
	}
	return false, nil
}

func (f IPTablesFirewall) deleteIfPresent(ctx context.Context, binary string, ruleArgs []string) error {
	exists, err := f.ruleExists(ctx, binary, ruleArgs)
	if err != nil || !exists {
		return err
	}
	if err := f.deleteExact(ctx, binary, ruleArgs); err != nil {
		restoreErr := f.restoreRulePresent(context.WithoutCancel(ctx), binary, ruleArgs)
		return errors.Join(err, wrapFirewallError("restore pre-delete firewall state", restoreErr))
	}
	stillExists, verifyErr := f.ruleExists(ctx, binary, ruleArgs)
	if verifyErr != nil {
		restoreErr := f.restoreRulePresent(context.WithoutCancel(ctx), binary, ruleArgs)
		return errors.Join(
			fmt.Errorf("verify removed STL firewall rule: %w", verifyErr),
			wrapFirewallError("restore pre-delete firewall state", restoreErr),
		)
	}
	if stillExists {
		return fmt.Errorf("STL firewall rule still exists after exact delete")
	}
	return nil
}

func (f IPTablesFirewall) appendExact(ctx context.Context, binary string, ruleArgs []string) error {
	appendArgs := append([]string{"-w", firewallWaitSeconds, "-A", "INPUT"}, ruleArgs...)
	if _, err := f.Runner.Run(ctx, binary, appendArgs...); err != nil {
		return fmt.Errorf("append STL firewall rule: %w", err)
	}
	return nil
}

func (f IPTablesFirewall) deleteExact(ctx context.Context, binary string, ruleArgs []string) error {
	deleteArgs := append([]string{"-w", firewallWaitSeconds, "-D", "INPUT"}, ruleArgs...)
	if _, err := f.Runner.Run(ctx, binary, deleteArgs...); err != nil {
		return fmt.Errorf("remove STL firewall rule: %w", err)
	}
	return nil
}

// restoreRuleAbsent reconciles an ambiguous add/verification failure back to
// the pre-add state. An exact delete is safe because absence was established
// before the attempted add and the rule carries this operation's ownership
// marker. A delete error is tolerated only when read-only inspection
// independently proves the owned marker is absent afterward.
func (f IPTablesFirewall) restoreRuleAbsent(ctx context.Context, binary string, ruleArgs []string) error {
	deleteErr := f.deleteExact(ctx, binary, ruleArgs)
	exists, inspectErr := f.ruleExists(ctx, binary, ruleArgs)
	if inspectErr != nil {
		return errors.Join(deleteErr, fmt.Errorf("verify STL firewall rollback: %w", inspectErr))
	}
	if exists {
		return errors.Join(deleteErr, fmt.Errorf("STL firewall rule remains after rollback"))
	}
	return nil
}

// restoreRulePresent reconciles an ambiguous delete/verification failure back
// to the pre-delete state. It never appends when presence is uncertain: the
// exact rule must first be positively absent under the same fail-closed
// inspection semantics.
func (f IPTablesFirewall) restoreRulePresent(ctx context.Context, binary string, ruleArgs []string) error {
	exists, err := f.ruleExists(ctx, binary, ruleArgs)
	if err != nil {
		return fmt.Errorf("inspect STL firewall rule before restore: %w", err)
	}
	if exists {
		return nil
	}

	appendErr := f.appendExact(ctx, binary, ruleArgs)
	if appendErr != nil {
		exists, inspectErr := f.ruleExists(context.WithoutCancel(ctx), binary, ruleArgs)
		if inspectErr != nil {
			return errors.Join(appendErr, fmt.Errorf("verify STL firewall restore: %w", inspectErr))
		}
		if exists {
			return nil
		}
		return appendErr
	}

	exists, verifyErr := f.ruleExists(ctx, binary, ruleArgs)
	if verifyErr != nil {
		return fmt.Errorf("verify restored STL firewall rule: %w", verifyErr)
	}
	if !exists {
		return fmt.Errorf("verify restored STL firewall rule: rule not found after restore")
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

func firewallMarkerFromArgs(ruleArgs []string) (string, error) {
	for i := 0; i+1 < len(ruleArgs); i++ {
		if ruleArgs[i] == "--comment" {
			if ruleArgs[i+1] == "" {
				break
			}
			return ruleArgs[i+1], nil
		}
	}
	return "", fmt.Errorf("STL firewall rule is missing ownership marker")
}

func firewallListingHasMarker(stdout []byte, marker string) bool {
	for _, line := range strings.Split(string(stdout), "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "--comment" {
				continue
			}
			if strings.Trim(fields[i+1], "\"'") == marker {
				return true
			}
		}
	}
	return false
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

func wrapFirewallError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
