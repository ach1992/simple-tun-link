package linux

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type firewallRunner struct {
	mu       sync.Mutex
	rules    map[string]bool
	commands [][]string
	fail     map[string]error
}

func newFirewallRunner() *firewallRunner {
	return &firewallRunner{rules: map[string]bool{}, fail: map[string]error{}}
}

func (r *firewallRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	command := append([]string{name}, args...)
	r.commands = append(r.commands, append([]string(nil), command...))
	key := strings.Join(command, " ")
	if err := r.fail[key]; err != nil {
		return CommandResult{}, err
	}
	if len(args) < 4 {
		return CommandResult{}, errors.New("unexpected firewall command")
	}
	op := args[2]
	ruleKey := strings.Join(append([]string{name}, args[4:]...), " ")
	switch op {
	case "-C":
		if r.rules[ruleKey] {
			return CommandResult{}, nil
		}
		return CommandResult{}, &CommandError{Command: name, ExitCode: 1, cause: errors.New("rule absent")}
	case "-I":
		// Insert has an extra position argument after INPUT.
		ruleKey = strings.Join(append([]string{name}, args[5:]...), " ")
		r.rules[ruleKey] = true
		return CommandResult{}, nil
	case "-D":
		delete(r.rules, ruleKey)
		return CommandResult{}, nil
	default:
		return CommandResult{}, errors.New("unexpected firewall operation")
	}
}

func testFirewall(t *testing.T, runner *firewallRunner) IPTablesFirewall {
	t.Helper()
	return IPTablesFirewall{
		Runner: runner,
		Locks:  state.NewLockManager(t.TempDir()),
	}
}

func testFirewallRule() InboundFirewallRule {
	return InboundFirewallRule{
		Peer:            netip.MustParseAddr("203.0.113.9"),
		Local:           netip.MustParseAddr("192.0.2.10"),
		InputInterface:  "eth0",
		Protocol:        17,
		DestinationPort: 51820,
	}
}

func TestIPTablesFirewallEnsuresExactOwnedRuleIdempotently(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()

	undo, changed, err := fw.EnsureInbound(context.Background(), id, rule)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first ensure reported unchanged")
	}
	_, changed, err = fw.EnsureInbound(context.Background(), id, rule)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("second ensure should be idempotent")
	}

	insertCount := 0
	for _, command := range runner.commands {
		joined := strings.Join(command, " ")
		if strings.Contains(joined, " -I INPUT 1 ") {
			insertCount++
		}
		if strings.Contains(joined, " -F ") || strings.Contains(joined, " -P ") || strings.Contains(joined, " OUTPUT ") || strings.Contains(joined, " FORWARD ") {
			t.Fatalf("firewall manager used forbidden broad mutation: %q", joined)
		}
	}
	if insertCount != 1 {
		t.Fatalf("insertCount=%d, want 1", insertCount)
	}
	if err := undo(context.Background()); err != nil {
		t.Fatal(err)
	}
	exists, err := fw.ruleExists(context.Background(), "iptables", firewallRuleArgs(id, rule))
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("rule still exists after undo")
	}
}

func TestIPTablesFirewallUsesExactNarrowArguments(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()
	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err != nil {
		t.Fatal(err)
	}

	marker := firewallMarker(id, rule)
	want := []string{
		"iptables", "-w", "5", "-I", "INPUT", "1",
		"-i", "eth0", "-s", "203.0.113.9/32", "-d", "192.0.2.10/32", "-p", "17",
		"-m", "udp", "--dport", "51820",
		"-m", "comment", "--comment", marker, "-j", "ACCEPT",
	}
	found := false
	for _, command := range runner.commands {
		if reflect.DeepEqual(command, want) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("exact insert command not found; commands=%#v", runner.commands)
	}
}

func TestIPTablesFirewallIPv6UsesIP6Tables(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := InboundFirewallRule{Peer: netip.MustParseAddr("2001:db8::9"), Local: netip.MustParseAddr("2001:db8::10"), InputInterface: "ens3", Protocol: 50}
	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		if command[0] == "ip6tables" {
			return
		}
	}
	t.Fatal("IPv6 rule did not use ip6tables")
}

func TestIPTablesFirewallRemoveUsesExactOwnedRule(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()
	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err != nil {
		t.Fatal(err)
	}
	removed, err := fw.RemoveInbound(context.Background(), id, rule)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("expected exact rule removal")
	}
	removed, err = fw.RemoveInbound(context.Background(), id, rule)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("second remove should be idempotent")
	}
	for _, command := range runner.commands {
		joined := strings.Join(command, " ")
		if strings.Contains(joined, " -D INPUT ") && !strings.Contains(joined, firewallMarker(id, rule)) {
			t.Fatalf("delete did not carry ownership marker: %q", joined)
		}
	}
}

func TestIPTablesFirewallConcurrentEnsureInsertsOnce(t *testing.T) {
	runner := newFirewallRunner()
	root := t.TempDir()
	fw := IPTablesFirewall{Runner: runner, Locks: state.NewLockManager(root)}
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()

	start := make(chan struct{})
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, _, err := fw.EnsureInbound(context.Background(), id, rule)
			errCh <- err
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	insertCount := 0
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command, " "), " -I INPUT 1 ") {
			insertCount++
		}
	}
	if insertCount != 1 {
		t.Fatalf("concurrent insertCount=%d, want 1", insertCount)
	}
}

func TestIPTablesFirewallRejectsBroadOrMalformedRules(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	valid := testFirewallRule()
	cases := []InboundFirewallRule{
		{},
		{Peer: valid.Peer, Local: valid.Local, InputInterface: "all", Protocol: 0},
		{Peer: valid.Peer, Local: valid.Local, InputInterface: "eth0;bad", Protocol: 47},
		{Peer: valid.Peer, Local: valid.Local, InputInterface: "eth0", Protocol: 47, DestinationPort: 1234},
		{Peer: valid.Peer, Local: valid.Local, InputInterface: "eth0", Protocol: 17},
	}
	fw := testFirewall(t, newFirewallRunner())
	for _, rule := range cases {
		if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err == nil {
			t.Fatalf("expected validation failure for %#v", rule)
		}
	}
}

func TestIPTablesFirewallDoesNotTreatUnexpectedCheckFailureAsRuleAbsence(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()
	args := firewallRuleArgs(id, rule)
	check := strings.Join(append([]string{"iptables", "-w", "5", "-C", "INPUT"}, args...), " ")
	runner.fail[check] = &CommandError{Command: "iptables", ExitCode: 2, cause: errors.New("permission denied")}
	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err == nil {
		t.Fatal("unexpected check failure was incorrectly treated as rule absence")
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command, " "), " -I INPUT 1 ") {
			t.Fatal("rule inserted after ambiguous inspection failure")
		}
	}
}
