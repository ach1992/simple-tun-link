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
	mu        sync.Mutex
	rules     []string
	commands  [][]string
	fail      map[string]error
	failAfter map[string]error
}

func newFirewallRunner() *firewallRunner {
	return &firewallRunner{
		fail:      map[string]error{},
		failAfter: map[string]error{},
	}
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
	switch op {
	case "-S":
		if args[3] != "INPUT" {
			return CommandResult{}, errors.New("unexpected firewall chain listing")
		}
		lines := make([]string, 0, len(r.rules))
		for _, ruleKey := range r.rules {
			fields := strings.Fields(ruleKey)
			if len(fields) < 2 || fields[0] != name {
				continue
			}
			lines = append(lines, "-A INPUT "+strings.Join(fields[1:], " "))
		}
		var stdout []byte
		if len(lines) > 0 {
			stdout = []byte(strings.Join(lines, "\n") + "\n")
		}
		result := CommandResult{Stdout: stdout}
		if err := r.failAfter[key]; err != nil {
			return result, err
		}
		return result, nil

	case "-C":
		ruleKey := firewallTestRuleKey(name, args[4:])
		if firewallTestContainsRule(r.rules, ruleKey) {
			if err := r.failAfter[key]; err != nil {
				return CommandResult{}, err
			}
			return CommandResult{}, nil
		}
		if err := r.failAfter[key]; err != nil {
			return CommandResult{}, err
		}
		return CommandResult{}, &CommandError{
			Command:  name,
			ExitCode: 1,
			cause:    errors.New("rule check failed"),
		}

	case "-A":
		ruleKey := firewallTestRuleKey(name, args[4:])
		r.rules = append(r.rules, ruleKey)
		if err := r.failAfter[key]; err != nil {
			return CommandResult{}, err
		}
		return CommandResult{}, nil

	case "-D":
		ruleKey := firewallTestRuleKey(name, args[4:])
		index := firewallTestRuleIndex(r.rules, ruleKey)
		if index < 0 {
			return CommandResult{}, &CommandError{
				Command:  name,
				ExitCode: 1,
				cause:    errors.New("rule absent"),
			}
		}
		r.rules = append(r.rules[:index], r.rules[index+1:]...)
		if err := r.failAfter[key]; err != nil {
			return CommandResult{}, err
		}
		return CommandResult{}, nil

	default:
		return CommandResult{}, errors.New("unexpected firewall operation")
	}
}

func (r *firewallRunner) seedRule(name string, ruleArgs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, firewallTestRuleKey(name, ruleArgs))
}

func (r *firewallRunner) hasRule(name string, ruleArgs []string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return firewallTestContainsRule(r.rules, firewallTestRuleKey(name, ruleArgs))
}

func (r *firewallRunner) snapshotRules() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.rules...)
}

func (r *firewallRunner) countCommandsContaining(fragment string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, command := range r.commands {
		if strings.Contains(strings.Join(command, " "), fragment) {
			count++
		}
	}
	return count
}

func firewallTestRuleKey(name string, ruleArgs []string) string {
	return strings.Join(append([]string{name}, ruleArgs...), " ")
}

func firewallTestContainsRule(rules []string, want string) bool {
	return firewallTestRuleIndex(rules, want) >= 0
}

func firewallTestRuleIndex(rules []string, want string) int {
	for i, rule := range rules {
		if rule == want {
			return i
		}
	}
	return -1
}

func firewallTestCommand(name string, prefix []string, ruleArgs []string) string {
	return strings.Join(append(append([]string{name}, prefix...), ruleArgs...), " ")
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

	if got := runner.countCommandsContaining(" -A INPUT "); got != 1 {
		t.Fatalf("append count=%d, want 1", got)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command, " ")
		if strings.Contains(joined, " -I INPUT ") ||
			strings.Contains(joined, " -F ") ||
			strings.Contains(joined, " -P ") ||
			strings.Contains(joined, " OUTPUT ") ||
			strings.Contains(joined, " FORWARD ") {
			t.Fatalf("firewall manager used forbidden or preemptive mutation: %q", joined)
		}
	}

	if err := undo(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.hasRule("iptables", firewallRuleArgs(id, rule)) {
		t.Fatal("rule still exists after undo")
	}
}

func TestIPTablesFirewallUsesExactNarrowAppendArguments(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()

	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err != nil {
		t.Fatal(err)
	}

	marker := firewallMarker(id, rule)
	want := []string{
		"iptables", "-w", "5", "-A", "INPUT",
		"-i", "eth0", "-s", "203.0.113.9/32", "-d", "192.0.2.10/32", "-p", "17",
		"-m", "udp", "--dport", "51820",
		"-m", "comment", "--comment", marker, "-j", "ACCEPT",
	}
	for _, command := range runner.commands {
		if reflect.DeepEqual(command, want) {
			return
		}
	}
	t.Fatalf("exact append command not found; commands=%#v", runner.commands)
}

func TestIPTablesFirewallAppendsBehindExistingAdministratorPolicy(t *testing.T) {
	runner := newFirewallRunner()
	adminRule := []string{"-s", "203.0.113.9/32", "-j", "DROP"}
	runner.seedRule("iptables", adminRule)

	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()
	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err != nil {
		t.Fatal(err)
	}

	rules := runner.snapshotRules()
	if len(rules) != 2 {
		t.Fatalf("rules=%v, want existing administrator rule plus one STL rule", rules)
	}
	if rules[0] != firewallTestRuleKey("iptables", adminRule) {
		t.Fatalf("administrator rule lost precedence: rules=%v", rules)
	}
	if rules[1] != firewallTestRuleKey("iptables", firewallRuleArgs(id, rule)) {
		t.Fatalf("STL rule was not appended after administrator policy: rules=%v", rules)
	}
}

func TestIPTablesFirewallIPv6UsesIP6TablesAndReadOnlyAbsenceListing(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := InboundFirewallRule{
		Peer:           netip.MustParseAddr("2001:db8::9"),
		Local:          netip.MustParseAddr("2001:db8::10"),
		InputInterface: "ens3",
		Protocol:       50,
	}

	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err != nil {
		t.Fatal(err)
	}

	if runner.countCommandsContaining("ip6tables -w 5 -S INPUT") != 1 {
		t.Fatalf("IPv6 absence was not established through ip6tables INPUT listing: %#v", runner.commands)
	}
	if !runner.hasRule("ip6tables", firewallRuleArgs(id, rule)) {
		t.Fatal("IPv6 exact rule not appended with ip6tables")
	}
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
	if err != nil || !removed {
		t.Fatalf("first remove removed=%v err=%v", removed, err)
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

func TestIPTablesFirewallConcurrentEnsureAppendsOnce(t *testing.T) {
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
	if got := runner.countCommandsContaining(" -A INPUT "); got != 1 {
		t.Fatalf("concurrent append count=%d, want 1", got)
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

func TestIPTablesFirewallDoesNotTreatCheckExitOneAsAbsenceWithoutListingEvidence(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()

	listKey := strings.Join([]string{"iptables", "-w", "5", "-S", "INPUT"}, " ")
	runner.fail[listKey] = &CommandError{
		Command:  "iptables",
		ExitCode: 1,
		cause:    errors.New("listing failed"),
	}

	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err == nil {
		t.Fatal("ambiguous check failure without successful listing was treated as absence")
	}
	if runner.countCommandsContaining(" -A INPUT ") != 0 {
		t.Fatal("rule appended without positive absence evidence")
	}
}

func TestIPTablesFirewallFailsClosedWhenMarkerExistsButExactCheckFails(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()
	args := firewallRuleArgs(id, rule)
	runner.seedRule("iptables", args)

	checkKey := firewallTestCommand("iptables", []string{"-w", "5", "-C", "INPUT"}, args)
	runner.fail[checkKey] = &CommandError{
		Command:  "iptables",
		ExitCode: 1,
		cause:    errors.New("generic check failure"),
	}

	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err == nil {
		t.Fatal("marker-present ambiguous inspection was treated as absence")
	}
	if got := runner.countCommandsContaining(" -A INPUT "); got != 0 {
		t.Fatalf("ambiguous marker-present inspection appended %d rules, want 0", got)
	}
}

func TestIPTablesFirewallRemoveAndUndoFailClosedWhenAbsenceCannotBeEstablished(t *testing.T) {
	t.Run("remove", func(t *testing.T) {
		runner := newFirewallRunner()
		fw := testFirewall(t, runner)
		id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
		rule := testFirewallRule()
		args := firewallRuleArgs(id, rule)
		runner.seedRule("iptables", args)

		checkKey := firewallTestCommand("iptables", []string{"-w", "5", "-C", "INPUT"}, args)
		listKey := strings.Join([]string{"iptables", "-w", "5", "-S", "INPUT"}, " ")
		runner.fail[checkKey] = &CommandError{Command: "iptables", ExitCode: 1, cause: errors.New("generic check failure")}
		runner.fail[listKey] = &CommandError{Command: "iptables", ExitCode: 1, cause: errors.New("listing failed")}

		if removed, err := fw.RemoveInbound(context.Background(), id, rule); err == nil || removed {
			t.Fatalf("RemoveInbound removed=%v err=%v, want fail-closed error", removed, err)
		}
		if !runner.hasRule("iptables", args) {
			t.Fatal("RemoveInbound mutated rule after ambiguous inspection")
		}
		if runner.countCommandsContaining(" -D INPUT ") != 0 {
			t.Fatal("RemoveInbound deleted after ambiguous inspection")
		}
	})

	t.Run("undo", func(t *testing.T) {
		runner := newFirewallRunner()
		fw := testFirewall(t, runner)
		id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
		rule := testFirewallRule()
		args := firewallRuleArgs(id, rule)

		undo, _, err := fw.EnsureInbound(context.Background(), id, rule)
		if err != nil {
			t.Fatal(err)
		}

		checkKey := firewallTestCommand("iptables", []string{"-w", "5", "-C", "INPUT"}, args)
		listKey := strings.Join([]string{"iptables", "-w", "5", "-S", "INPUT"}, " ")
		runner.fail[checkKey] = &CommandError{Command: "iptables", ExitCode: 1, cause: errors.New("generic check failure")}
		runner.fail[listKey] = &CommandError{Command: "iptables", ExitCode: 1, cause: errors.New("listing failed")}

		if err := undo(context.Background()); err == nil {
			t.Fatal("undo unexpectedly succeeded with ambiguous inspection")
		}
		if !runner.hasRule("iptables", args) {
			t.Fatal("undo mutated rule after ambiguous inspection")
		}
	})
}

func TestIPTablesFirewallAmbiguousAppendFailureRollsBackOwnedDelta(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()
	args := firewallRuleArgs(id, rule)

	appendKey := firewallTestCommand("iptables", []string{"-w", "5", "-A", "INPUT"}, args)
	runner.failAfter[appendKey] = &CommandError{
		Command:  "iptables",
		ExitCode: -1,
		Canceled: true,
		cause:    context.Canceled,
	}

	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err == nil {
		t.Fatal("ambiguous append failure unexpectedly succeeded")
	}
	if runner.hasRule("iptables", args) {
		t.Fatal("failed Ensure left its exact owned firewall delta behind")
	}
	if runner.countCommandsContaining(" -D INPUT ") == 0 {
		t.Fatal("failed Ensure did not attempt exact rollback")
	}
}

func TestIPTablesFirewallAmbiguousAppendFailurePropagatesRollbackFailure(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()
	args := firewallRuleArgs(id, rule)

	appendKey := firewallTestCommand("iptables", []string{"-w", "5", "-A", "INPUT"}, args)
	deleteKey := firewallTestCommand("iptables", []string{"-w", "5", "-D", "INPUT"}, args)
	runner.failAfter[appendKey] = &CommandError{
		Command:  "iptables",
		ExitCode: -1,
		TimedOut: true,
		Canceled: true,
		cause:    context.DeadlineExceeded,
	}
	runner.fail[deleteKey] = &CommandError{
		Command:  "iptables",
		ExitCode: 2,
		cause:    errors.New("rollback delete failed"),
	}

	_, _, err := fw.EnsureInbound(context.Background(), id, rule)
	if err == nil {
		t.Fatal("expected ambiguous append plus rollback failure")
	}
	if !strings.Contains(err.Error(), "restore pre-add firewall state") {
		t.Fatalf("rollback failure not surfaced: %v", err)
	}
	if !runner.hasRule("iptables", args) {
		t.Fatal("test did not preserve unreconciled rule after forced rollback failure")
	}
}

func TestIPTablesFirewallAmbiguousDeleteFailureRestoresPreOperationRule(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()
	args := firewallRuleArgs(id, rule)

	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err != nil {
		t.Fatal(err)
	}

	deleteKey := firewallTestCommand("iptables", []string{"-w", "5", "-D", "INPUT"}, args)
	runner.failAfter[deleteKey] = &CommandError{
		Command:  "iptables",
		ExitCode: -1,
		Canceled: true,
		cause:    context.Canceled,
	}

	removed, err := fw.RemoveInbound(context.Background(), id, rule)
	if err == nil || removed {
		t.Fatalf("RemoveInbound removed=%v err=%v, want transactional failure", removed, err)
	}
	if !runner.hasRule("iptables", args) {
		t.Fatal("ambiguous delete failure did not restore exact pre-operation rule")
	}
	if runner.countCommandsContaining(" -I INPUT ") != 0 {
		t.Fatal("restoration used preemptive insertion")
	}
	if got := runner.countCommandsContaining(" -A INPUT "); got != 2 {
		t.Fatalf("append count=%d, want initial append plus one restoration append", got)
	}
}

func TestIPTablesFirewallUndoAmbiguousDeleteFailureRestoresPreOperationRule(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()
	args := firewallRuleArgs(id, rule)

	undo, _, err := fw.EnsureInbound(context.Background(), id, rule)
	if err != nil {
		t.Fatal(err)
	}

	deleteKey := firewallTestCommand("iptables", []string{"-w", "5", "-D", "INPUT"}, args)
	runner.failAfter[deleteKey] = &CommandError{
		Command:  "iptables",
		ExitCode: -1,
		TimedOut: true,
		Canceled: true,
		cause:    context.DeadlineExceeded,
	}

	if err := undo(context.Background()); err == nil {
		t.Fatal("undo unexpectedly succeeded after ambiguous delete result")
	}
	if !runner.hasRule("iptables", args) {
		t.Fatal("failed undo did not restore exact pre-operation rule")
	}
}

func TestIPTablesFirewallPreservesEquivalentExternalRule(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := testFirewallRule()

	external := []string{
		"-i", "eth0",
		"-s", "203.0.113.9/32",
		"-d", "192.0.2.10/32",
		"-p", "17",
		"-m", "udp", "--dport", "51820",
		"-j", "ACCEPT",
	}
	runner.seedRule("iptables", external)

	if _, _, err := fw.EnsureInbound(context.Background(), id, rule); err != nil {
		t.Fatal(err)
	}
	if !runner.hasRule("iptables", external) {
		t.Fatal("external equivalent rule was modified or adopted")
	}
	if !runner.hasRule("iptables", firewallRuleArgs(id, rule)) {
		t.Fatal("STL exact owned rule was not created independently")
	}

	if removed, err := fw.RemoveInbound(context.Background(), id, rule); err != nil || !removed {
		t.Fatalf("RemoveInbound removed=%v err=%v", removed, err)
	}
	if !runner.hasRule("iptables", external) {
		t.Fatal("STL removal deleted equivalent external rule")
	}
}

func TestIPTablesFirewallFindsAnyOwnedInboundMarker(t *testing.T) {
	runner := newFirewallRunner()
	fw := testFirewall(t, runner)
	owner := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	other := domain.LinkID("lnk_fedcba9876543210fedcba9876543210")
	runner.seedRule("iptables", firewallRuleArgs(other, testFirewallRule()))
	if present, err := fw.HasOwnedInbound(context.Background(), owner, false); err != nil || present {
		t.Fatalf("foreign marker matched owner: present=%v err=%v", present, err)
	}
	runner.seedRule("iptables", firewallRuleArgs(owner, testFirewallRule()))
	if present, err := fw.HasOwnedInbound(context.Background(), owner, false); err != nil || !present {
		t.Fatalf("owned marker not found: present=%v err=%v", present, err)
	}
}
