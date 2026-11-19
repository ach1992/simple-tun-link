package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestGuidedCreateRuntimeFailureIsClassifiedActionableAndSecretSafe(t *testing.T) {
	const secret = "-----BEGIN PRIVATE KEY----- TEST-DO-NOT-PRINT stl://sensitive"
	cases := []struct {
		name    string
		backend domain.Backend
		kind    runtimeInitKind
		reason  string
		next    string
	}{
		{"MASQUE executable", domain.BackendMASQUE, runtimeInitExecutable, "installed_executable_identity_unverified", "stl version --json"},
		{"WireGuard private store", domain.BackendWireGuard, runtimeInitCredentials, "selected_credential_store_unverified", "permissions"},
		{"WSS adapter", domain.BackendWireGuardWSS, runtimeInitBackend, "selected_backend_initialization_unverified", "prerequisites"},
		{"QUIC systemd", domain.BackendWireGuardQUIC, runtimeInitSystemd, "systemd_runtime_unverified", "systemctl"},
		{"IPsec registration", domain.BackendIPsec, runtimeInitRegistration, "selected_backend_not_registered", "stl doctor ipsec"},
		{"invalid backend selection", domain.BackendMASQUE, runtimeInitSelection, "selected_backend_unavailable", "supported tunnel"},
	}
	id := domain.LinkID("lnk_dddddddddddddddddddddddddddddddd")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			unsafeCause := errors.New(secret)
			resolved, err := menuHandoffCreationOptionsWithAssembler(nil, id, tc.backend,
				func(root string, selected domain.Backend) (*runtimeOptions, error) {
					calls++
					if root != state.DefaultRoot || selected != tc.backend {
						t.Fatal("assembler received wrong root/backend")
					}
					return nil, runtimeInitFailure(tc.kind, unsafeCause)
				})
			if resolved != nil || calls != 1 || !errors.Is(err, unsafeCause) {
				t.Fatal("failed selected assembler did not preserve typed error without runtime")
			}
			var out bytes.Buffer
			if code := menuGuidedCreateRuntimeFailure(&out, tc.backend, err); code == 0 {
				t.Fatal("failed assembler was reported as successful")
			}
			s := out.String()
			for _, needle := range []string{string(tc.backend), tc.reason, tc.next, "No Link Apply"} {
				if !strings.Contains(s, needle) {
					t.Fatalf("missing safe operator detail %q", needle)
				}
			}
			if strings.Contains(s, secret) || strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "stl://") {
				t.Fatal("runtime diagnostic leaked the private cause")
			}
		})
	}
	var out bytes.Buffer
	if code := menuGuidedCreateRuntimeFailure(&out, domain.BackendMASQUE, errors.New(secret)); code == 0 ||
		!strings.Contains(out.String(), "selected_runtime_unverified") || strings.Contains(out.String(), secret) {
		t.Fatal("unknown raw runtime failure must have safe actionable fallback")
	}
}

func TestIPsecNilMenuUsesSelectedAdmissionAndRejectsFailuresWithoutHostEffects(t *testing.T) {
	root := t.TempDir()
	input := strings.NewReader("")
	var out, errOut bytes.Buffer
	calls := 0
	code := menuCreateIPsecWithAssembler(input, bufio.NewReader(input), &out, &errOut, nil,
		domain.EncapESP, func(runtimeRoot string, backend domain.Backend) (*runtimeOptions, error) {
			calls++
			if runtimeRoot != state.DefaultRoot || backend != domain.BackendIPsec {
				t.Fatalf("IPsec wizard assembled unrelated runtime %s at %s", backend, runtimeRoot)
			}
			// Private local test root; no registered exclusive IPsec service
			// means the existing read-only admission must stop the wizard.
			return &runtimeOptions{stateRoot: root}, nil
		})
	if code == 0 || calls != 1 || !strings.Contains(out.String(), "stl doctor ipsec --json") {
		t.Fatalf("unadmitted selected IPsec runtime entered the wizard: code=%d calls=%d", code, calls)
	}
	for _, path := range []string{"masque", "receiver-handoffs", "keys", "links.json"} {
		if _, err := os.Lstat(filepath.Join(root, path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("IPsec preflight created unauthorized object %s: %v", path, err)
		}
	}

	// The IPsec menu must never reconstruct a caller-injected runtime even
	// if the injected backend is unavailable; it must report its admission.
	injected := &runtimeOptions{stateRoot: root}
	input = strings.NewReader("")
	out.Reset()
	code = menuCreateIPsecWithAssembler(input, bufio.NewReader(input), &out, &errOut,
		injected, domain.EncapNATT, func(string, domain.Backend) (*runtimeOptions, error) {
			t.Fatal("caller-owned runtime was replaced")
			return nil, nil
		})
	if code == 0 || injected.stateRoot != root || injected.menuHandoffID != "" {
		t.Fatal("injected IPsec runtime changed or bypassed admission")
	}

	input = strings.NewReader("")
	out.Reset()
	calls = 0
	const secret = "private_service_key_/root/stl/secret-material"
	code = menuCreateIPsecWithAssembler(input, bufio.NewReader(input), &out, &errOut, nil,
		domain.EncapESP, func(string, domain.Backend) (*runtimeOptions, error) {
			calls++
			return nil, runtimeInitFailure(runtimeInitSystemd, errors.New(secret))
		})
	if code == 0 || calls != 1 || !strings.Contains(out.String(), "systemd_runtime_unverified") ||
		!strings.Contains(out.String(), "systemctl is-system-running") || strings.Contains(out.String(), secret) {
		t.Fatal("failed IPsec assembly lacked secret-safe classified recovery")
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("failed IPsec admission created private files")
	}
}

func TestGuidedCreateRejectsAssemblerWithoutSelectedBackend(t *testing.T) {
	id := domain.LinkID("lnk_cccccccccccccccccccccccccccccccc")
	opts, err := menuHandoffCreationOptionsWithAssembler(nil, id, domain.BackendMASQUE,
		func(root string, kind domain.Backend) (*runtimeOptions, error) {
			return &runtimeOptions{stateRoot: root}, nil
		})
	var issue *runtimeInitIssue
	if opts != nil || !errors.As(err, &issue) || issue.kind != runtimeInitRegistration {
		t.Fatal("state-root-only placeholder was accepted without the selected backend")
	}
}

// Exercise the actual factory's registration boundary, not only the fake
// assembler callback. IPsec may intentionally have zero registrations until
// its exclusive service passes host admission; other selected backends must
// register exactly one of their own kind. Native MASQUE is separately covered
// by the installed-source-bound, real-TTY Create acceptance in Issue #142.
func TestSelectedCreateRuntimeFactoryDoesNotRegisterUnrelatedBackends(t *testing.T) {
	for _, backend := range []domain.Backend{
		domain.BackendWireGuard, domain.BackendWireGuardWSS,
		domain.BackendWireGuardQUIC, domain.BackendIPsec,
	} {
		t.Run(string(backend), func(t *testing.T) {
			options, err := assembleRuntimeBackendOptions(filepath.Join(t.TempDir(), "state"), backend)
			if err != nil {
				t.Fatalf("selected backend runtime factory failed: %v", err)
			}
			if options == nil || len(options.backends) > 1 ||
				(backend != domain.BackendIPsec && len(options.backends) != 1) {
				t.Fatalf("selected backend registration count invalid: got %d", len(options.backends))
			}
			for _, registered := range options.backends {
				if registered == nil || registered.Kind() != backend {
					t.Fatal("unrelated backend registered for selected Create")
				}
			}
		})
	}
}
