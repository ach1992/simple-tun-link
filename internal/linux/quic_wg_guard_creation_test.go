package linux

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type quicOriginalGuardTestRunner struct {
	quicCoexistenceRunner
	plan               QUICWGIngressPlan
	exact              []byte
	present            bool
	drift              bool
	failInventory      bool
	censuses           int
	cancelAfterCreate  context.CancelFunc
	malformedInventory bool
	wgInterfaces       string
	wgPublic           string
	wgPort             string
	ssListen           string
	ssAll              string
	failVacancy        bool
}

func (r *quicOriginalGuardTestRunner) RunBounded(ctx context.Context, limits CaptureLimits, name string, args ...string) (CommandResult, error) {
	command := name + " " + strings.Join(args, " ")
	switch command {
	case "wg show interfaces", "wg show all public-key", "wg show all listen-port", "ss -H -u -l -n", "ss -H -u -a -n":
		r.calls = append(r.calls, command)
		if r.failVacancy {
			return CommandResult{}, errors.New("SENSITIVE_FOREIGN_SOCKET_DIAGNOSTIC")
		}
		var data string
		switch command {
		case "wg show interfaces":
			data = r.wgInterfaces
		case "wg show all public-key":
			data = r.wgPublic
		case "wg show all listen-port":
			data = r.wgPort
		case "ss -H -u -l -n":
			data = r.ssListen
		case "ss -H -u -a -n":
			data = r.ssAll
		}
		return CommandResult{Stdout: []byte(data)}, nil
	case "nft -j list tables":
		r.calls = append(r.calls, command)
		r.censuses++
		if r.failInventory {
			return CommandResult{}, fmt.Errorf("SENSITIVE_FOREIGN_NFT_STDERR")
		}
		if r.malformedInventory {
			return CommandResult{Stdout: []byte(`{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1}}, {"table":{"family":"inet","name":"other"}}, {"table":{"family":"inet","name":"other"}}]}`)}, nil
		}
		if r.present {
			return CommandResult{Stdout: []byte(fmt.Sprintf(`{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1}},{"table":{"family":"inet","name":%q,"handle":6}}]}`, r.plan.TableName()))}, nil
		}
		return CommandResult{Stdout: []byte(wssHostEmptyRuleset)}, nil
	case "nft -j list table inet " + r.plan.TableName():
		r.calls = append(r.calls, command)
		if r.cancelAfterCreate != nil {
			r.cancelAfterCreate()
		}
		if r.drift {
			return CommandResult{Stdout: []byte(strings.Replace(string(r.exact), quicTestNonce, "abcdef0123456789abcdef0123456789", 1))}, nil
		}
		return CommandResult{Stdout: r.exact}, nil
	default:
		return r.quicCoexistenceRunner.RunBounded(ctx, limits, name, args...)
	}
}

func testQUICIngressPublicKey() string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
}

func originalGuardFixture(t *testing.T) (*quicOriginalGuardTestRunner, QUICWGIngressPlan) {
	t.Helper()
	plan, err := NewQUICWGIngressPlan(wssTestLinkID, 51820, quicTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	runner := &quicOriginalGuardTestRunner{plan: plan, exact: []byte(wgIngressSnapshot(t, plan.spec()))}
	runner.nft = []byte(wssHostEmptyRuleset)
	return runner, plan
}

func TestQUICOriginalGuardRequiresExclusiveCreateAndStrictReadback(t *testing.T) {
	runner, plan := originalGuardFixture(t)
	applied := 0
	err := publishQUICWGIngressOriginal(context.Background(), runner, plan, testQUICIngressPublicKey(), func(ctx context.Context, batch string) error {
		applied++
		if ctx.Err() != nil || runner.present || !strings.HasPrefix(batch, "create table inet "+plan.TableName()+"\n") ||
			!strings.Contains(batch, plan.spec().ruleComment()) || !strings.Contains(batch, "counter drop") ||
			strings.Contains(batch, "flush") || strings.Contains(batch, "delete") {
			t.Fatal("original nft guard transaction could be foreign or destructive")
		}
		runner.present = true
		return nil
	})
	if err != nil || applied != 1 || runner.censuses != 2 {
		t.Fatalf("original create + readback not established: err=%v applied=%d censuses=%d", err, applied, runner.censuses)
	}
	expected := []string{"nft -j list ruleset", "iptables -V", "ip6tables -V",
		"iptables-legacy-save", "ip6tables-legacy-save", "nft -j list tables",
		"wg show interfaces", "wg show all public-key", "wg show all listen-port",
		"ss -H -u -l -n", "ss -H -u -a -n",
		"nft -j list tables", "nft -j list table inet " + plan.TableName()}
	if !reflect.DeepEqual(expected, runner.calls) {
		t.Fatalf("unexpected host commands: %q", runner.calls)
	}
	if err := publishQUICWGIngressOriginal(context.Background(), runner, plan, testQUICIngressPublicKey(),
		func(context.Context, string) error {
			t.Fatal("existing identical guard was adopted/overwritten")
			return nil
		}); err == nil {
		t.Fatal("same-byte existing table accepted as original")
	}
	if !reflect.DeepEqual(expected, runner.calls[:len(expected)]) {
		t.Fatal("original one-time witness was mutated")
	}
}

func TestQUICOriginalGuardFailClosedOnUntrustedBeforeAndAfterEffects(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(*quicOriginalGuardTestRunner)
		afterApply bool
		uncertain  bool
	}{
		{"preexisting same-byte foreign", func(r *quicOriginalGuardTestRunner) { r.present = true }, false, false},
		{"inventory error", func(r *quicOriginalGuardTestRunner) { r.failInventory = true }, false, false},
		{"duplicate inventory", func(r *quicOriginalGuardTestRunner) { r.malformedInventory = true }, false, false},
		{"foreign early hook", func(r *quicOriginalGuardTestRunner) {
			r.nft = []byte(wssHostInventory(t, "foreign", "INPUT", "input", -300, "accept", true))
		}, false, false},
		{"foreign live WG key", func(r *quicOriginalGuardTestRunner) {
			r.wgInterfaces = "foreign0"
			r.wgPublic = "foreign0 " + testQUICIngressPublicKey() + "\n"
			r.wgPort = "foreign0 49111\n"
		}, false, false},
		{"foreign live WG port", func(r *quicOriginalGuardTestRunner) {
			r.wgInterfaces = "foreign0"
			r.wgPublic = "foreign0 " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))) + "\n"
			r.wgPort = "foreign0 51820\n"
		}, false, false},
		{"migrated live WG socket", func(r *quicOriginalGuardTestRunner) {
			r.ssListen = "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n"
		}, false, false},
		{"foreign connected UDP socket", func(r *quicOriginalGuardTestRunner) {
			r.ssAll = "ESTAB 0 0 127.0.0.1:51820 127.0.0.1:8333\n"
		}, false, false},
		{"malformed connected UDP census", func(r *quicOriginalGuardTestRunner) {
			r.ssAll = "INCOMPLETE\n"
		}, false, false},
		{"unavailable WG/socket census", func(r *quicOriginalGuardTestRunner) {
			r.failVacancy = true
		}, false, false},
		{"post-create altered nonce", func(r *quicOriginalGuardTestRunner) { r.drift = true }, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, p := originalGuardFixture(t)
			tc.mutate(r)
			applied := 0
			err := publishQUICWGIngressOriginal(context.Background(), r, p, testQUICIngressPublicKey(), func(context.Context, string) error { applied++; r.present = true; return nil })
			if err == nil || applied != map[bool]int{true: 1, false: 0}[tc.afterApply] {
				t.Fatalf("untrusted host admitted or effect at wrong time: %v, attempts %d", err, applied)
			}
			if errors.Is(err, ErrQUICWGGuardEffectUncertain) != tc.uncertain {
				t.Fatalf("wrong pre-effect vs dispatched-uncertain classification: %v", err)
			}
			if strings.Contains(err.Error(), "SENSITIVE_FOREIGN_NFT_STDERR") ||
				strings.Contains(err.Error(), "SENSITIVE_FOREIGN_SOCKET_DIAGNOSTIC") {
				t.Fatal("foreign stderr leaked")
			}
		})
	}
	r, p := originalGuardFixture(t)
	err := publishQUICWGIngressOriginal(context.Background(), r, p, testQUICIngressPublicKey(), func(context.Context, string) error {
		r.present = true
		return errors.New("SENSITIVE_FOREIGN_KERNEL_FAILURE")
	})
	if !errors.Is(err, ErrQUICWGGuardEffectUncertain) || strings.Contains(err.Error(), "SENSITIVE_FOREIGN_KERNEL_FAILURE") || !r.present {
		t.Fatalf("dispatched uncertain CREATE was adopted or lost: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r, p = originalGuardFixture(t)
	r.cancelAfterCreate = cancel
	err = publishQUICWGIngressOriginal(ctx, r, p, testQUICIngressPublicKey(), func(context.Context, string) error { r.present = true; return nil })
	if !errors.Is(err, ErrQUICWGGuardEffectUncertain) {
		t.Fatalf("canceled readback accepted: %v", err)
	}
	cancel()
	r, p = originalGuardFixture(t)
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if err := publishQUICWGIngressOriginal(ctx, r, p, testQUICIngressPublicKey(), func(context.Context, string) error { t.Fatal("canceled host mutation"); return nil }); err == nil || len(r.calls) != 0 {
		t.Fatal("canceled guard ran host commands")
	}
}

func TestQUICOriginalGuardRequiresCompleteValidatedPlan(t *testing.T) {
	r, p := originalGuardFixture(t)
	invalid := p
	invalid.OriginalNonce = ""
	if err := publishQUICWGIngressOriginal(context.Background(), r, invalid, testQUICIngressPublicKey(), func(context.Context, string) error { t.Fatal("invalid guard mutated host"); return nil }); err == nil || len(r.calls) != 0 {
		t.Fatal("invalid nonce admitted")
	}
	if err := publishQUICWGIngressOriginal(context.Background(), r, p, "invalid", func(context.Context, string) error { t.Fatal("invalid WG key accepted"); return nil }); err == nil || len(r.calls) != 0 {
		t.Fatal("untrusted original WG identity queried host")
	}
	if err := publishQUICWGIngressOriginal(nil, r, p, testQUICIngressPublicKey(), nil); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := publishQUICWGIngressOriginal(context.Background(), nil, p, testQUICIngressPublicKey(), func(context.Context, string) error { return nil }); err == nil {
		t.Fatal("nil runner accepted")
	}
}
