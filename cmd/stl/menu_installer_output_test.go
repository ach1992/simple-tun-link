package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const operatorSensitiveSentinel = "STL_OPERATOR_PRIVATE_SENTINEL"

// The authenticated first hop can reject a hostile mirror before or during
// the canonical stage. Preserve a bounded, helpful reason without replaying
// raw curl/APT diagnostics or downloaded content.
func TestPinnedMirrorUpdateFailureReasonsAreSafeAndActionable(t *testing.T) {
	cases := []struct {
		line, reason, action string
	}{
		{"[FAILED] Canonical installer exceeds the 1 MiB streaming limit; private", "mirror_canonical_installer_unverified", "1 MiB streaming limit"},
		{"[FAILED] Mirror canonical installer unavailable, incomplete or oversized; private", "mirror_canonical_installer_unverified", "1 MiB streaming limit"},
		{"[FAILED] Mirror canonical installer differs from the independently pinned SHA256; private", "mirror_canonical_installer_unverified", "verified release"},
		{"[FAILED] Mirror release asset exceeds the authenticated streaming-size limit; private", "mirror_release_asset_unverified", "streaming limits"},
		{"[FAILED] Required release file is unavailable on the HTTPS mirror; private", "mirror_release_asset_unverified", "SHA256SUMS"},
		{"[FAILED] The mirror SHA256SUMS does not match this bootstrap release pin; private", "mirror_release_asset_unverified", "SHA256SUMS"},
		{"[FAILED] Release asset SHA256 mismatch; private", "mirror_release_asset_unverified", "manifests"},
	}
	for _, tc := range cases {
		t.Run(tc.reason+"_"+tc.line[:10], func(t *testing.T) {
			var captured menuInstallerOutput
			_, stderr := captured.streams()
			_, _ = io.WriteString(stderr, tc.line+" "+operatorSensitiveSentinel+"\n")
			var out bytes.Buffer
			captured.failure(&out, "update", fmt.Errorf("%s", operatorSensitiveSentinel), context.Background())
			text := out.String()
			if !strings.Contains(text, tc.reason) ||
				!strings.Contains(text, tc.action) ||
				strings.Contains(text, operatorSensitiveSentinel) {
				t.Fatalf("unsafe or incomplete mirror reason: %q", text)
			}
		})
	}
}

// The executable local launcher is authenticated before invocation, but its
// child output still may contain APT paths, URLs, and private host data.
// Only fixed reason vocabulary may reach an operator's terminal.
func TestAuthenticatedLocalLauncherFailuresRemainActionableAndRedacted(t *testing.T) {
	cases := []struct {
		message, stage, reason, next string
	}{
		{"wrong file for aarch64; download the official linux/arm64 local installer", "local_architecture", "local_architecture_incompatible", "uname -m"},
		{"selected optional WSS archive SHA-256 mismatch; core unchanged", "local_companion", "local_companion_unverified", "helper"},
		{"embedded archive SHA256 mismatch; re-download from the verified official release", "local_bundle", "local_bundle_unverified", "SHA256"},
		{"untrusted /root/stl transfer directory; require root ownership and mode 0700", "local_source", "local_source_untrusted", "/root/stl"},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			var capture menuInstallerOutput
			_, stderr := capture.streams()
			_, _ = io.WriteString(stderr, "APT-private data: "+operatorSensitiveSentinel+"\n")
			_, _ = io.WriteString(stderr, "stl local install [FAILED]: "+tc.message+" PRIVATE="+operatorSensitiveSentinel+"\n")
			var out bytes.Buffer
			capture.failure(&out, "update", fmt.Errorf("child failed: %s", operatorSensitiveSentinel), context.Background())
			got := out.String()
			if !strings.Contains(got, tc.stage) || !strings.Contains(got, tc.reason) ||
				!strings.Contains(got, tc.next) || strings.Contains(got, operatorSensitiveSentinel) {
				t.Errorf("unsafe or unhelpful local update report: %q", got)
			}
		})
	}
}

// APT and Bash stdout/stderr are never a safe source of display text. Preserve
// only bounded, authored stage/reason fields and the real child exit status.
func TestInstallerOperatorOutputIsBoundedAndSecretSafe(t *testing.T) {
	var capture menuInstallerOutput
	stdout, stderr := capture.streams()
	_, _ = io.WriteString(stdout, "APT can print a credential: "+operatorSensitiveSentinel+"\n")
	_, _ = io.WriteString(stderr, "stl installer [INFO]: Another APT process holds the lists lock; retrying\n")
	_, _ = io.WriteString(stderr, "[INFO] Installing verified missing packages on host "+operatorSensitiveSentinel+"\n")
	_, _ = io.WriteString(stderr, "stl installer [FAILED]: APT package transaction failed; "+
		operatorSensitiveSentinel+"\n")
	_, _ = io.WriteString(stderr, strings.Repeat(operatorSensitiveSentinel, 600)+"\n")
	var out bytes.Buffer
	// A real process gives an authentic status even when stdout lies.
	cmd := exec.Command("/bin/bash", "-c", "exit 37")
	err := cmd.Run()
	if err == nil {
		t.Fatal("synthetic failing command succeeded")
	}
	capture.failure(&out, "prepare", err, context.Background())
	got := out.String()
	if strings.Contains(got, operatorSensitiveSentinel) ||
		!strings.Contains(got, "apt_package_transaction") ||
		!strings.Contains(got, "apt_transaction_incomplete") ||
		!strings.Contains(got, "Child exit code") ||
		!strings.Contains(got, "37") ||
		!strings.Contains(got, "dpkg --audit") ||
		!strings.Contains(got, "may have changed") {
		t.Fatalf("operator output not safe and useful: %q", got)
	}
	var empty menuInstallerOutput
	stdout, stderr = empty.streams()
	_, _ = io.WriteString(stdout, "some arbitrary "+operatorSensitiveSentinel)
	_, _ = io.WriteString(stderr, "untrusted output with no newline")
	out.Reset()
	empty.failure(&out, "update", fmt.Errorf("private command: %s", operatorSensitiveSentinel), context.Background())
	if strings.Contains(out.String(), operatorSensitiveSentinel) ||
		!strings.Contains(out.String(), "unverified") ||
		!strings.Contains(out.String(), "retained private recovery journal") {
		t.Fatalf("unknown child failure escaped bounded output: %q", out.String())
	}
}

func TestCanonicalAPTPrepareFailureStageAndReason(t *testing.T) {
	tests := []struct {
		name, failure, stage, reason string
	}{
		{"index mirror failure", "APT_INDEX_REFRESH failed; missing selected packages: iptables.", "apt_index_refresh", "apt_index_unverified"},
		{"dependency resolution", "APT_DEPENDENCY_PLAN failed; missing selected packages: iptables.", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"partial package transaction", "APT_PACKAGE_INSTALL failed; missing selected packages: iptables.", "apt_package_transaction", "apt_transaction_incomplete"},
		{"signed candidate failure", "APT candidate InRelease is not signed by the distribution archive", "apt_source_trust", "apt_source_trust_unverified"},
		{"source trust bypass", "APT sources explicitly bypass signature verification", "apt_source_trust", "apt_source_trust_unverified"},
		{"APT index lock", "APT lists lock remained busy after bounded waiting", "apt_index_refresh", "apt_index_unverified"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capture menuInstallerOutput
			_, stderr := capture.streams()
			_, _ = io.WriteString(stderr, "[INFO] Installing verified missing packages on "+
				operatorSensitiveSentinel+"\n")
			_, _ = io.WriteString(stderr, "stl installer [FAILED]: "+tc.failure+" "+
				operatorSensitiveSentinel+"\n")
			var out bytes.Buffer
			capture.failure(&out, "prepare", fmt.Errorf("child failed"), context.Background())
			display := out.String()
			if !strings.Contains(display, tc.stage) || !strings.Contains(display, tc.reason) ||
				strings.Contains(display, operatorSensitiveSentinel) || !strings.Contains(display, "dpkg --audit") {
				t.Fatalf("wrong APT prepare stage/recovery: %q", display)
			}
		})
	}
}

func TestCanonicalAPTPlannerAndTrustVocabularyProjection(t *testing.T) {
	// These are literal failure prefixes emitted by scripts/install.sh. The
	// read-only preview and post-consent operator report must agree without
	// exposing any of the remaining (potentially private) child output.
	tests := []struct {
		name, message, stage, reason string
	}{
		{"unavailable official keyring", "official distribution archive signing keyring unavailable", "apt_source_trust", "apt_source_trust_unverified"},
		{"unverified keyring ownership", "official archive keyring package ownership unverified", "apt_source_trust", "apt_source_trust_unverified"},
		{"incomplete keyring installation", "distribution archive keyring package not fully installed", "apt_source_trust", "apt_source_trust_unverified"},
		{"missing signature verifier", "cannot verify distribution archive signatures", "apt_source_trust", "apt_source_trust_unverified"},
		{"index-to-release inventory", "APT index-to-release inventory could not be inspected", "apt_source_trust", "apt_source_trust_unverified"},
		{"ambiguous release identity", "APT candidate source maps to ambiguous release identities", "apt_source_trust", "apt_source_trust_unverified"},
		{"candidate policy unavailable", "APT candidate-to-index policy could not be read", "apt_source_trust", "apt_source_trust_unverified"},
		{"foreign candidate", "APT candidate includes a non-distribution package source", "apt_source_trust", "apt_source_trust_unverified"},
		{"unsigned release", "APT candidate InRelease is missing or untrusted", "apt_source_trust", "apt_source_trust_unverified"},
		{"Ubuntu metadata", "official Ubuntu archive metadata does not match the host", "apt_source_trust", "apt_source_trust_unverified"},
		{"Debian metadata", "official Debian archive metadata does not match the host", "apt_source_trust", "apt_source_trust_unverified"},
		{"no verified candidate index", "APT candidate package version has no verified distribution index", "apt_source_trust", "apt_source_trust_unverified"},
		{"source file unreadable", "APT source inventory could not be read", "apt_source_trust", "apt_source_trust_unverified"},
		{"source inventory unreadable", "APT source inventory could not be inspected", "apt_source_trust", "apt_source_trust_unverified"},
		{"unrecognized package", "APT returned an unrecognized install identity", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"unrecognized version", "APT returned an unrecognized candidate version", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"duplicate planned identity", "APT plan includes duplicate package identity", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"omitted planned package", "APT plan omitted a required selected package", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"unsafe sized plan", "APT plan is empty or exceeds safe preview limits", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"changed candidate", "APT preferred candidate differs from the consented version", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"drift before refresh", "APT dependency plan changed since confirmation; no APT attempted", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"drift after refresh", "APT dependency plan changed after index refresh; package install cancelled", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"drift before prepare", "APT plan changed since confirmation; no APT attempted", "apt_dependency_plan", "apt_dependency_plan_unverified"},
		{"empty approved plan", "approved APT install plan is empty; nothing installed", "apt_dependency_plan", "apt_dependency_plan_unverified"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := "stl installer [FAILED]: " + tc.message + "; " + operatorSensitiveSentinel + "\n"
			var capture menuInstallerOutput
			_, stderr := capture.streams()
			_, _ = io.WriteString(stderr, "[INFO] Installing verified missing packages on Debian 13: "+operatorSensitiveSentinel+"\n")
			_, _ = io.WriteString(stderr, line)
			if capture.stage != tc.stage || capture.reason != tc.reason {
				t.Errorf("menu mismatch: stage=%q reason=%q; want %q %q", capture.stage, capture.reason, tc.stage, tc.reason)
			}
			var out bytes.Buffer
			capture.failure(&out, "prepare", fmt.Errorf("child failed"), context.Background())
			display := out.String()
			if !strings.Contains(display, tc.stage) || !strings.Contains(display, tc.reason) ||
				!strings.Contains(display, "dpkg --audit") || strings.Contains(display, operatorSensitiveSentinel) {
				t.Errorf("unsafe or incomplete operator report: %q", display)
			}
			reason, next := packageInventoryGuidance(packageInventoryFailure(line, nil))
			if reason != tc.reason || strings.Contains(reason+next, operatorSensitiveSentinel) {
				t.Errorf("preview mismatch: reason=%q next=%q; want %q", reason, next, tc.reason)
			}
			if tc.stage == "apt_source_trust" && !strings.Contains(next, "signature") {
				t.Errorf("preview source recovery weakened: %q", next)
			}
		})
	}
}

func TestCanonicalAPTPreTransactionInfoDoesNotClaimInstall(t *testing.T) {
	tests := []struct {
		name, after, stage, reason string
		cancel                     bool
	}{
		{"unknown after INFO", "", "unverified", "installer_execution_unverified", false},
		{"cancelled after INFO", "", "unverified", "installer_interrupted", true},
		{"index failure after INFO", "APT_INDEX_REFRESH failed; missing selected packages: iptables.", "apt_index_refresh", "apt_index_unverified", false},
		{"plan drift after INFO", "APT dependency plan changed after index refresh; package install cancelled", "apt_dependency_plan", "apt_dependency_plan_unverified", false},
		{"source rejection after INFO", "APT candidate includes a non-distribution package source", "apt_source_trust", "apt_source_trust_unverified", false},
		{"actual install failure", "APT_PACKAGE_INSTALL failed; missing selected packages: iptables.", "apt_package_transaction", "apt_transaction_incomplete", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capture menuInstallerOutput
			stdout, stderr := capture.streams()
			_, _ = io.WriteString(stdout, "private APT output "+operatorSensitiveSentinel+"\n")
			_, _ = io.WriteString(stderr, "[INFO] Installing verified missing packages on Debian 13: "+operatorSensitiveSentinel+"\n")
			if tc.after != "" {
				_, _ = io.WriteString(stderr, "stl installer [FAILED]: "+tc.after+" "+operatorSensitiveSentinel+"\n")
			} else if capture.stage != "" || capture.reason != "" {
				t.Fatalf("pre-install informational message invented stage=%q reason=%q", capture.stage, capture.reason)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if tc.cancel {
				cancel()
			}
			var out bytes.Buffer
			capture.failure(&out, "prepare", fmt.Errorf("child failed"), ctx)
			cancel()
			display := out.String()
			if !strings.Contains(display, tc.stage) || !strings.Contains(display, tc.reason) ||
				!strings.Contains(display, "dpkg --audit") || !strings.Contains(display, "may have changed") ||
				strings.Contains(display, operatorSensitiveSentinel) {
				t.Fatalf("incorrect/unsafe pretransaction report: %q", display)
			}
		})
	}
}

func TestCanonicalAPTIncompleteAndSpoofedOutputIsConservative(t *testing.T) {
	tests := []struct {
		name, output string
	}{
		{"APT lists wait without failure", "stl installer [INFO]: Another APT process holds the lists lock; waiting 5 seconds before retry 2/12.\n"},
		{"pre-transaction INFO without failure", "[INFO] Installing verified missing packages on Debian 13: " + operatorSensitiveSentinel + "\n"},
		{"failure line without terminal newline", "stl installer [FAILED]: APT_PACKAGE_INSTALL failed; " + operatorSensitiveSentinel},
		{"oversized incomplete failure line", "stl installer [FAILED]: " + strings.Repeat(operatorSensitiveSentinel, 80) + "\n"},
		{"untrusted raw APT line", "APT candidate includes a non-distribution package source " + operatorSensitiveSentinel + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capture menuInstallerOutput
			_, stderr := capture.streams()
			_, _ = io.WriteString(stderr, tc.output)
			if capture.stage != "" || capture.reason != "" {
				t.Fatalf("unproven failure was classified as stage=%q reason=%q", capture.stage, capture.reason)
			}
			var out bytes.Buffer
			capture.failure(&out, "prepare", fmt.Errorf("child stopped"), context.Background())
			display := out.String()
			if !strings.Contains(display, "unverified") ||
				!strings.Contains(display, "installer_execution_unverified") ||
				!strings.Contains(display, "dpkg --audit") ||
				strings.Contains(display, operatorSensitiveSentinel) {
				t.Fatalf("incomplete/spoofed output escaped safe unknown handling: %q", display)
			}
			if strings.Contains(tc.output, "APT candidate includes") {
				reason, _ := packageInventoryGuidance(packageInventoryFailure(tc.output, nil))
				if reason != "requirements_inventory_unverified" {
					t.Fatalf("untrusted child APT output spoofed preview failure: %q", reason)
				}
			}
		})
	}
}

func TestCanonicalUpdateProcessShowsFullOperatorDiagnostics(t *testing.T) {
	tmp := t.TempDir()
	script := filepath.Join(tmp, "fixture.sh")
	content := "#!/bin/bash\n" +
		"printf '%s\\n' 'stdout " + operatorSensitiveSentinel + "'\n" +
		"printf '%s\\n' 'stl installer [FAILED]: partial failure; inspect retained recovery directory: " +
		operatorSensitiveSentinel + "' >&2\n" +
		"exit 43\n"
	if err := os.WriteFile(script, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", filepath.Join(tmp, "untrusted-shell-startup.sh"))
	// A Bash startup hook must not execute before the canonical updater.
	if err := os.WriteFile(filepath.Join(tmp, "untrusted-shell-startup.sh"),
		[]byte("touch "+filepath.Join(tmp, "INJECTED")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := menuRunCanonicalUpdateProcess(context.Background(), script, "v0.1.9", &output)
	if err == nil {
		t.Fatal("failure was treated as successful update")
	}
	got := output.String()
	if !strings.Contains(got, "stdout "+operatorSensitiveSentinel) ||
		!strings.Contains(got, "stl installer [FAILED]: partial failure; inspect retained recovery directory: "+operatorSensitiveSentinel) ||
		!strings.Contains(got, "Child exit code") ||
		!strings.Contains(got, "43") ||
		!strings.Contains(got, "retained_recovery_requires_inspection") ||
		!strings.Contains(got, "Do not retry blindly") {
		t.Fatalf("bad update failure projection: %q", got)
	}
	if _, statErr := os.Stat(filepath.Join(tmp, "INJECTED")); !os.IsNotExist(statErr) {
		t.Fatalf("inherited Bash startup hook executed: %v", statErr)
	}
	if err := os.WriteFile(script, []byte("#!/bin/bash\n"+
		"printf '%s\\n' 'success with "+operatorSensitiveSentinel+" stdout'\n"+
		"printf '%s\\n' 'success with "+operatorSensitiveSentinel+" stderr' >&2\n"+
		"exit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := menuRunCanonicalUpdateProcess(context.Background(), script, "v0.1.9", &output); err != nil ||
		!strings.Contains(output.String(), "success with "+operatorSensitiveSentinel+" stdout") ||
		!strings.Contains(output.String(), "success with "+operatorSensitiveSentinel+" stderr") {
		t.Fatalf("successful update lost operator output: %v %q", err, output.String())
	}
}

func TestPackagePrepareDisplaysDetailedInstallerOutput(t *testing.T) {
	input := strings.NewReader("PREPARE\n")
	reader := bufio.NewReader(input)
	var out, errOut bytes.Buffer
	var calls int
	selected := tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}
	ops := menuPackagePreparationOps{
		preview: func(_ context.Context, choice tunnelOption) (selectedPackagePreview, error) {
			if choice != selected {
				t.Fatalf("unexpected preview selector: %+v", choice)
			}
			return selectedPackagePreview{missing: "iproute2", packages: "iproute2 iptables kmod",
				aptInstall: "iproute2=6.0.0-1"}, nil
		},
		canPrepare: func(io.Reader, io.Writer) bool { return true },
		install: func(ctx context.Context, stdout, stderr io.Writer, _ ...string) error {
			calls++
			cmd := exec.CommandContext(ctx, "/bin/bash", "-c",
				"printf '%s\\n' 'APT stdout "+operatorSensitiveSentinel+"'; "+
					"printf '%s\\n' 'stl installer [FAILED]: APT package transaction failed; "+
					operatorSensitiveSentinel+"' >&2; exit 63")
			cmd.Stdout, cmd.Stderr = stdout, stderr
			return cmd.Run()
		},
	}
	result := menuPrepareSelectedPackagesWithOps(input, reader, &out, &errOut, selected, nil, ops)
	rendered := out.String() + errOut.String()
	if result.canContinue || result.approvedSelectedPlan || calls != 1 ||
		!strings.Contains(rendered, "APT stdout "+operatorSensitiveSentinel) ||
		!strings.Contains(rendered, "stl installer [FAILED]: APT package transaction failed; "+operatorSensitiveSentinel) ||
		!strings.Contains(rendered, "Child exit code") ||
		!strings.Contains(rendered, "63") ||
		!strings.Contains(rendered, "apt_transaction_incomplete") ||
		!strings.Contains(rendered, "dpkg --audit") ||
		!strings.Contains(rendered, "may persist") {
		t.Fatalf("PREPARE failure was unsafe: result=%+v calls=%d output=%q", result, calls, rendered)
	}
}

// A visible terminal stream retains complete raw bytes, including a long
// diagnostic line that exceeds the 1 KiB classifier budget, while keeping
// the classified summary of the *actual* child failure.
func TestInstallerOperatorStreamsNeverTruncateRealDiagnostics(t *testing.T) {
	var captured menuInstallerOutput
	var stdout, stderr bytes.Buffer
	out, errOut := captured.streamsVisible(&stdout, &stderr)
	payload := "STL-APT-DETAIL-" + strings.Repeat("A", 8192) + "\n"
	if n, err := io.WriteString(out, payload); err != nil || n != len(payload) {
		t.Fatalf("stdout lost data: bytes=%d err=%v", n, err)
	}
	failure := "stl installer [FAILED]: APT_INDEX_REFRESH failed; package indexes inaccessible\n"
	if _, err := io.WriteString(errOut, failure); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != payload || stderr.String() != failure {
		t.Fatalf("operator logs were silently dropped: stdout=%d stderr=%q", stdout.Len(), stderr.String())
	}
	var summary bytes.Buffer
	captured.failure(&summary, "install", &exec.ExitError{}, context.Background())
	if !strings.Contains(summary.String(), "apt_index_refresh") ||
		!strings.Contains(summary.String(), "apt_index_unverified") {
		t.Fatalf("raw output replaced the structured summary: %q", summary.String())
	}
}

func TestVisibleInstallerStreamsSerializeConcurrentStdoutAndStderr(t *testing.T) {
	var captured menuInstallerOutput
	var output bytes.Buffer // bytes.Buffer is not safe for concurrent writes.
	stdout, stderr := captured.streamsVisible(&output, &output)
	var workers sync.WaitGroup
	for i := 0; i < 100; i++ {
		workers.Add(2)
		go func(i int) {
			defer workers.Done()
			if _, err := fmt.Fprintf(stdout, "out-%03d\\n", i); err != nil {
				t.Errorf("stdout %d: %v", i, err)
			}
		}(i)
		go func(i int) {
			defer workers.Done()
			if _, err := fmt.Fprintf(stderr, "err-%03d\\n", i); err != nil {
				t.Errorf("stderr %d: %v", i, err)
			}
		}(i)
	}
	workers.Wait()
	for i := 0; i < 100; i++ {
		for _, prefix := range []string{"out", "err"} {
			want := fmt.Sprintf("%s-%03d\\n", prefix, i)
			if strings.Count(output.String(), want) != 1 {
				t.Fatalf("parallel installer output lost or duplicated %q", want)
			}
		}
	}
}

func TestDirectCanonicalInstallerFailuresRetainRealStageAndDetailedText(t *testing.T) {
	testCases := []struct{ name, childLine, stage, reason, next string }{
		{
			"Mirror oversized SHA256SUMS",
			"stl installer [FAILED]: mirror_download_oversized: SHA256SUMS exceeds verified release transfer limit; no fallback to GitHub",
			"mirror_release_assets", "mirror_release_asset_unverified", "SHA256SUMS",
		},
		{
			"Mirror asset unavailable",
			"stl installer [FAILED]: mirror_download_failed: LICENSE unavailable, incomplete or oversized; no fallback to GitHub",
			"mirror_release_assets", "mirror_release_asset_unverified", "SHA256SUMS",
		},
		{
			"Mirror manifest integrity mismatch",
			"stl installer [FAILED]: mirror_checksum_mismatch: SHA256SUMS differs from pinned digest",
			"mirror_release_assets", "mirror_release_asset_unverified", "SHA256SUMS",
		},
		{
			"Mirror binary digest mismatch (source-neutral category)",
			"stl installer [FAILED]: checksum mismatch for stl_v9.9.9_linux_amd64",
			"release_integrity", "release_integrity_unverified", "official GitHub or HTTPS Mirror",
		},
		{
			"Official binary digest mismatch (source-neutral category)",
			"stl installer [FAILED]: checksum mismatch for stl_v9.9.9_linux_amd64",
			"release_integrity", "release_integrity_unverified", "official GitHub or HTTPS Mirror",
		},
		{
			"Official malformed SHA256 entry",
			"stl installer [FAILED]: missing/duplicate or malformed SHA256 entry for BUILD-MANIFEST.txt",
			"release_integrity", "release_integrity_unverified", "SHA256SUMS",
		},
		{
			"Mirror malformed SHA256 entry (source-neutral category)",
			"stl installer [FAILED]: missing/duplicate or malformed SHA256 entry for LICENSE",
			"release_integrity", "release_integrity_unverified", "SHA256SUMS",
		},
		{
			"Official release download failure",
			"stl installer [FAILED]: cannot download complete bounded official release file: SHA256SUMS",
			"official_release_assets", "official_release_asset_unverified", "TLS/DNS",
		},
		{
			"Previously installed version",
			"stl installer [FAILED]: installed_version_mismatch: prior=v0.1.23 target=v0.1.24; install cannot replace a different installer-owned release; use an explicit update",
			"installed_version", "installed_version_mismatch", "explicit verified Update",
		},
		{
			"Root-private snapshot rejected",
			"STL_ROOT_SNAPSHOT_SHA256_MISMATCH: Privileged private snapshot SHA256 mismatch after sudo. No installer executed.",
			"privileged_snapshot", "privileged_installer_snapshot_unverified", "hash verification",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var child menuInstallerOutput
			var out bytes.Buffer
			_, stderr := child.streamsVisible(&out, &out)
			if _, err := io.WriteString(stderr, tc.childLine+"\n"); err != nil {
				t.Fatal(err)
			}
			child.failure(&out, "update", errors.New("child command exited"), context.Background())
			all := out.String()
			for _, expected := range []string{tc.childLine, tc.stage, tc.reason, tc.next} {
				if !strings.Contains(all, expected) {
					t.Errorf("required diagnostic %q absent from %q", expected, all)
				}
			}
		})
	}
}
