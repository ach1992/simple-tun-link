package quic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"golang.org/x/sys/unix"
)

func TestGenerationPinLivesThroughCommitAndCloseHasNoLifecycleEffect(t *testing.T) {
	root, plan, port, expected, nonce, dir := stageInspectionFixture(t, Listen)
	pin, err := openPinnedGeneration(context.Background(), root, plan, port, fixtureHysteriaPath, nonce, expected, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if got := pin.Identity(); !validMaterialIdentity(got) || got.CertificateSHA256 != expected.Credentials.CertificateSHA256 {
		t.Fatal("retained material lacks exact public identity")
	}
	fd := int(pin.files[0].file.Fd())
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		t.Fatal("original file was not retained")
	}
	if err := pin.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pin.Close(); err != nil {
		t.Fatal("idempotent descriptor close failed")
	}
	if unix.Fstat(fd, &st) != unix.EBADF {
		t.Fatal("close did not release descriptor")
	}
	if err := pin.Verify(context.Background()); err == nil {
		t.Fatal("closed pin remained usable")
	}
	if _, err := os.Stat(filepath.Join(dir, generationReceiptName)); err != nil {
		t.Fatal("descriptor release removed original material")
	}
}

func TestRecordedRemovalPinNeverGrantsCurrentLaunchTrust(t *testing.T) {
	root, plan, port, expected, nonce, _ := stageInspectionFixture(t, Listen)
	denied := func(string) (pinnedexec.Identity, error) {
		return pinnedexec.Identity{}, errors.New("current launch trust unavailable")
	}
	pin, err := openPinnedGenerationMode(context.Background(), root, plan, port, fixtureHysteriaPath, nonce, expected, denied, true)
	if err != nil {
		t.Fatal("exact original removal must not depend on current launch validity:", err)
	}
	defer pin.Close()
	if err := pin.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := pin.VerifyForLaunch(context.Background()); err == nil {
		t.Fatal("recorded removal identity became launch authority")
	}
	if launched, err := openPinnedGeneration(context.Background(), root, plan, port, fixtureHysteriaPath, nonce, expected, denied); err == nil {
		launched.Close()
		t.Fatal("current launch check was bypassed")
	}
}

func TestRetainedGenerationRejectsParentReplacementAndCancellation(t *testing.T) {
	root, plan, port, expected, nonce, _ := stageInspectionFixture(t, Dial)
	pin, err := openPinnedGeneration(context.Background(), root, plan, port, fixtureHysteriaPath, nonce, expected, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pin.Verify(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled retained check proceeded")
	}
	if err := os.Rename(filepath.Join(root, "credentials"), filepath.Join(root, "old-credentials")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "credentials"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pin.Verify(context.Background()); err == nil {
		t.Fatal("canonical parent replacement accepted")
	}
}
