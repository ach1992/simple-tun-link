package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const operatorSensitiveSentinel = "STL_OPERATOR_PRIVATE_SENTINEL"

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

func TestCanonicalUpdateProcessNeverShowsRawChildStreams(t *testing.T) {
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
	if strings.Contains(got, operatorSensitiveSentinel) ||
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
		strings.Contains(output.String(), operatorSensitiveSentinel) {
		t.Fatalf("raw update success output leaked or failed: %v %q", err, output.String())
	}
}

func TestPackagePrepareNeverForwardsRawInstallerOutput(t *testing.T) {
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
		strings.Contains(rendered, operatorSensitiveSentinel) ||
		!strings.Contains(rendered, "Child exit code") ||
		!strings.Contains(rendered, "63") ||
		!strings.Contains(rendered, "apt_transaction_incomplete") ||
		!strings.Contains(rendered, "dpkg --audit") ||
		!strings.Contains(rendered, "may persist") {
		t.Fatalf("PREPARE failure was unsafe: result=%+v calls=%d output=%q", result, calls, rendered)
	}
}
