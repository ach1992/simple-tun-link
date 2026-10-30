package quichelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func journalFixture(t *testing.T, message any) []byte {
	t.Helper()
	raw, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]string{"_TRANSPORT": "stdout", "_SYSTEMD_UNIT": "stl-quic-fixture.service", "_SYSTEMD_INVOCATION_ID": strings.Repeat("a", 32), "_BOOT_ID": strings.Repeat("b", 32), "__REALTIME_TIMESTAMP": "123456789", "MESSAGE": string(raw)}
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func TestManagedDiagnosticsRetainUsefulFailureClassesWithoutSecretText(t *testing.T) {
	const secret = "NEVER-PUBLISH-TOKEN-PRIVATE-KEY-OR-PAIRING-URI"
	for _, tc := range []struct{ msg, detail, reason string }{
		{"failed to initialize client", "authentication error, HTTP status code: 404 " + secret, "quic_authorization_rejected"},
		{"failed to initialize client", "CRYPTO_ERROR: tls: unknown certificate authority " + secret, "quic_tls_verification_failed"},
		{"failed to initialize server", "listen udp: address already in use " + secret, "quic_udp_port_occupied"},
		{"UDP forwarding error", "i/o timeout " + secret, "quic_transport_timeout"},
		{"UDP error", "rejected", "quic_forwarding_rejected"},
		{"UDP error", secret, "quic_helper_failure"},
	} {
		raw := journalFixture(t, map[string]string{"level": "fatal", "msg": tc.msg, "error": tc.detail, "auth": secret, "uri": "hysteria://" + secret, "id": secret})
		events, err := parseHelperEvents(raw, "stl-quic-fixture.service", strings.Repeat("a", 32), strings.Repeat("b", 32))
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 || events[0].ReasonCode != tc.reason || events[0].NextStep == "" {
			t.Fatalf("useful failure classification lost: %+v", events)
		}
		public, err := json.Marshal(events)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(public), secret) || strings.Contains(fmt.Sprint(events), secret) {
			t.Fatal("diagnostic event exposed secret-bearing input")
		}
	}
	raw := journalFixture(t, map[string]string{"level": "info", "msg": "connected to server", "error": secret, "uri": secret})
	events, err := parseHelperEvents(raw, "stl-quic-fixture.service", strings.Repeat("a", 32), strings.Repeat("b", 32))
	if err != nil || len(events) != 1 || events[0].Event != "transport_connected" {
		t.Fatal("positive transport event missing", err)
	}
}

func TestManagedDiagnosticsRejectCrossUnitBootInvocationAndDuplicateAttribution(t *testing.T) {
	raw := journalFixture(t, map[string]string{"level": "info", "msg": "client connected"})
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(raw), "stl-quic-fixture.service", "foreign.service", 1)),
		[]byte(strings.Replace(string(raw), strings.Repeat("a", 32), strings.Repeat("c", 32), 1)),
		[]byte(strings.Replace(string(raw), strings.Repeat("b", 32), strings.Repeat("d", 32), 1)),
		[]byte(strings.Replace(string(raw), "stdout", "syslog", 1)),
		append([]byte(`{"_BOOT_ID":"foreign",`), raw[1:]...),
		raw[:len(raw)-1],
	} {
		if _, err := parseHelperEvents(bad, "stl-quic-fixture.service", strings.Repeat("a", 32), strings.Repeat("b", 32)); err == nil {
			t.Fatal("unattributed/ambiguous journal event accepted")
		}
	}
}

func TestManagedErrorsKeepCauseAndStageWithoutRenderingRawStderr(t *testing.T) {
	secret := errors.New("stderr includes token and private key SECRET-DO-NOT-PRINT")
	manager := &managerFailure{Kind: "command_exit", ExitCode: 203, cause: secret}
	err := managedError(domain.Link{ID: fixtureID}, "helper_start", "start_uncertain", "helper start outcome uncertain", errors.Join(core.ErrIndeterminateHostEffect, manager), true)
	if !errors.Is(err, core.ErrIndeterminateHostEffect) || !errors.Is(err, secret) {
		t.Fatal("private error identity or uncertain-host classification was lost")
	}
	public := stlerr.Public(err)
	raw, e := json.Marshal(public)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), "SECRET") || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("typed error exposed private cause")
	}
	if public.ReasonCode != "quic_manager_command_exit" || !strings.Contains(public.Detail, "203") || public.Evidence == nil || public.Evidence.Stage != "helper_start" || public.Evidence.HostMutation != "outcome_uncertain" {
		t.Fatalf("safe stage/exit evidence missing: %+v", public)
	}
}
