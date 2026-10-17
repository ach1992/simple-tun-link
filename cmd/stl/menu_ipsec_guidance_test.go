//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestMenuMissingIPsecSAHasSpecificReadOnlyNextStep(t *testing.T) {
	link, _ := makeLifecycleDesired(t, "f", "10.70.102.0/31")
	link.Backend, link.Encapsulation = domain.BackendIPsec, domain.EncapESP
	missing := stlerr.New(stlerr.CodeInspect, "diagnose_ipsec", string(link.ID), "ipsec", "IPsec SA absent")
	missing.ReasonCode = "ipsec_sa_not_established"
	missing.NextStep = "After both ends import, select My tunnels -> Connect IPsec."
	check := healthDiagnosticFailure(link, missing)
	if check.Status != "blocked" || check.ReasonCode != "ipsec_sa_not_established" ||
		!strings.Contains(check.NextStep, "Connect IPsec") || check.Observed != nil {
		t.Fatalf("all-Link status lost known IPsec state: %+v", check)
	}
	generic := stlerr.New(stlerr.CodeInspect, "diagnose_ipsec", string(link.ID), "ipsec", "unverified owner")
	if got := healthDiagnosticFailure(link, generic); got.ReasonCode == "ipsec_sa_not_established" {
		t.Fatal("unverified identity was misreported as a known absent SA")
	}
	raw, err := json.Marshal(linkReadErrorResponse{SchemaVersion: jsonSchemaVersion, Error: missing})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	menuPublicDiagnosticFailure(&out, raw)
	result := out.String()
	for _, want := range []string{"ipsec_sa_not_established", "Connect IPsec", "IPsec SA absent"} {
		if !strings.Contains(result, want) {
			t.Fatalf("missing actionable %q", want)
		}
	}
	if strings.Contains(result, "stl://") || strings.Contains(result, "private_key") {
		t.Fatal("public menu disclosed sensitive information")
	}
}

func TestMenuManageOnlyOffersConnectForIPsec(t *testing.T) {
	opts, fake, _ := manageFixture(t, 1)
	code, out, errText := scriptedManage(opts, "3\n1\n7\n0\n8\n")
	if code != 0 || errText != "" || strings.Contains(out, "7 Connect IPsec") ||
		!strings.Contains(out, "Connect IPsec is available for saved IPsec tunnels only") ||
		len(fake.applies) != 1 {
		t.Fatalf("GRE menu exposed or executed IPsec command: code=%d errors=%q", code, errText)
	}
}

// A genuine PTY is necessary to test the fresh action confirmation gate;
// strings.Reader cannot and must not activate IKE by prewritten menu input.
func TestMenuIPsecConnectExactTTYOptInAndNoImplicitReconnect(t *testing.T) {
	link := fixtureReadLink("lnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		"10.80.90.0/31", "10.80.90.1/31", domain.BackendIPsec)
	link.Encapsulation = domain.EncapESP
	root := filepath.Join(t.TempDir(), "state")
	storeReadLinks(t, root, link)
	opts := &runtimeOptions{stateRoot: root}
	for _, tc := range []struct {
		name        string
		response    string
		hasSA       bool
		wantConnect int
		wantCheck   int
	}{
		{"cancel", "", false, 0, 0},
		{"explicit typed CONNECT", "CONNECT", false, 1, 1},
		{"already has verified SA", "", true, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connectCalls, checkCalls := 0, 0
			actions := menuIPsecConnectActions{
				status: func(id domain.LinkID, _ *runtimeOptions) (linkStatusResponse, []byte, int) {
					if id != link.ID {
						t.Fatal("wrong status Link")
					}
					return linkStatusResponse{
						SchemaVersion: jsonSchemaVersion, Link: summarizeLink(link), InterfaceVerified: true,
						IPsecState: &ipsecbackend.DiagnosticState{
							ConnectionConfigured: true, SecurityAssociationPresent: tc.hasSA,
							Interface: "stl-test-guard", IfIndex: 17, XFRMID: 127,
						},
					}, nil, 0
				},
				connect: func(args []string, out, errOut io.Writer, _ *runtimeOptions) int {
					connectCalls++
					expected := []string{"connect-ipsec", string(link.ID), "--confirm", string(link.ID)}
					if !reflect.DeepEqual(args, expected) {
						t.Fatal("wrong canonical Connect operation")
					}
					fmt.Fprintln(out, "IKE initiation accepted")
					return 0
				},
				check: func(id domain.LinkID, out, errOut io.Writer, _ *runtimeOptions) int {
					if id != link.ID {
						t.Fatal("checked wrong Link")
					}
					checkCalls++
					fmt.Fprintln(out, "peer answered 5/5 replies")
					return 0
				},
			}
			master, slave := openMenuPTY(t)
			done := make(chan int, 1)
			go func() {
				done <- menuConnectIPsecWithActions(slave, bufio.NewReader(slave), slave, slave, opts, link, actions)
			}()
			if !tc.hasSA {
				rendered := readMenuPTYUntil(t, master, "To initiate IKEv2, type CONNECT (Enter cancels):")
				if strings.Contains(rendered, link.DisplayName) || strings.Contains(rendered, "stl://") {
					t.Fatal("preview disclosed private metadata")
				}
				if _, err := io.WriteString(master, tc.response+"\n"); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case code := <-done:
				if code != 0 {
					t.Fatalf("menu returned %d", code)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("menu did not finish")
			}
			// Reads may be buffered by the PTY; actions are definitive.
			if connectCalls != tc.wantConnect || checkCalls != tc.wantCheck {
				t.Fatalf("unintended IKE or Ping: connect=%d check=%d", connectCalls, checkCalls)
			}
		})
	}
	// Redirected automation may display the exact supported CLI but cannot
	// use menu text to trigger a background IKE mutation.
	connectCalls := 0
	actions := menuIPsecConnectActions{
		status: func(domain.LinkID, *runtimeOptions) (linkStatusResponse, []byte, int) {
			t.Fatal("non-TTY reached status")
			return linkStatusResponse{}, nil, 1
		},
		connect: func([]string, io.Writer, io.Writer, *runtimeOptions) int { connectCalls++; return 0 },
		check:   func(domain.LinkID, io.Writer, io.Writer, *runtimeOptions) int { t.Fatal("non-TTY checked"); return 0 },
	}
	var out, errOut bytes.Buffer
	if code := menuConnectIPsecWithActions(strings.NewReader("CONNECT\n"),
		bufio.NewReader(strings.NewReader("CONNECT\n")), &out, &errOut, opts, link, actions); code != 0 || connectCalls != 0 || !strings.Contains(out.String(), "stl link connect-ipsec") {
		t.Fatal("redirected menu activated IKE without a human TTY")
	}
}
