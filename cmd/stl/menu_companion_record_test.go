package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
)

// Independent fixture of the canonical install.sh record formats. In these
// tests the executable inspector is stubbed as already byte-pinned; separate
// pinnedexec tests cover the actual binary descriptor/hash validation.
func menuCanonicalRecordFixture(spec menuCompanionSpec) []byte {
	switch spec.action {
	case "companion-wss":
		pin := wss.PinnedAMD64SHA256
		if runtime.GOARCH == "arm64" {
			pin = wss.PinnedARM64SHA256
		}
		return []byte(fmt.Sprintf("format=1\nproject=simple-tun-link\ncompanion=wstunnel\nversion=11.0.0\narchive_sha256=%s\nsha256=%s\n", spec.digest, pin))
	case "companion-quic":
		pin := quic.PinnedAMD64SHA256
		if runtime.GOARCH == "arm64" {
			pin = quic.PinnedARM64SHA256
		}
		return []byte(fmt.Sprintf("format=1\nproject=simple-tun-link\ncompanion=hysteria\nversion=2.13.0\nsha256=%s\n", pin))
	}
	panic("unknown test companion")
}

func menuRecordFixture(t *testing.T, kind menuCompanionKind) (menuCompanionSpec, []byte) {
	t.Helper()
	spec, ok := menuPinnedCompanion(kind, runtime.GOARCH)
	if !ok {
		t.Skip("no approved companion for this architecture")
	}
	dir := t.TempDir()
	spec.binary = filepath.Join(dir, "pinned-executable-fixture")
	spec.record = filepath.Join(dir, "installed-companion-record")
	if err := os.WriteFile(spec.binary, []byte("stand-in for already verified pinned executable"), 0755); err != nil {
		t.Fatal(err)
	}
	expected := menuCanonicalRecordFixture(spec)
	if err := os.WriteFile(spec.record, expected, 0600); err != nil {
		t.Fatal(err)
	}
	if generated, err := menuExpectedCompanionRecord(spec); err != nil || !bytes.Equal(generated, expected) {
		t.Fatalf("Go record format differs from canonical installer: %v", err)
	}
	return spec, expected
}

func TestMenuOwnedCompanionRecordReuseForCreateAndImport(t *testing.T) {
	for _, kind := range []menuCompanionKind{menuCompanionWSS, menuCompanionQUIC} {
		for _, operation := range []string{"create", "import"} {
			for _, scenario := range []string{
				"canonical", "missing", "malformed", "wrong_project", "foreign_component",
				"wrong_version", "wrong_hash", "extra_fields", "symlink", "hardlink",
				"unsafe_mode", "directory", "unsafe_parent", "symlink_parent",
				"untrusted_executable",
			} {
				t.Run(string(kind)+"/"+operation+"/"+scenario, func(t *testing.T) {
					spec, record := menuRecordFixture(t, kind)
					exeContents, err := os.ReadFile(spec.binary)
					if err != nil {
						t.Fatal(err)
					}
					modify := func(content []byte) {
						t.Helper()
						if err := os.WriteFile(spec.record, content, 0600); err != nil {
							t.Fatal(err)
						}
					}
					switch scenario {
					case "missing":
						if err := os.Remove(spec.record); err != nil {
							t.Fatal(err)
						}
					case "malformed":
						modify([]byte("format=2\n"))
					case "wrong_project":
						modify(bytes.Replace(record, []byte("project=simple-tun-link"), []byte("project=foreign"), 1))
					case "foreign_component":
						modify(bytes.Replace(record, []byte("companion="), []byte("companion=foreign-"), 1))
					case "wrong_version":
						modify(bytes.Replace(record, []byte("version="), []byte("version=0."), 1))
					case "wrong_hash":
						modify(bytes.Replace(record, []byte("sha256="), []byte("sha256=0"), 1))
					case "extra_fields":
						modify(append(bytes.Clone(record), []byte("foreign=1\n")...))
					case "symlink":
						other := filepath.Join(filepath.Dir(spec.record), "target-record")
						if err := os.Rename(spec.record, other); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(other, spec.record); err != nil {
							t.Fatal(err)
						}
					case "hardlink":
						if err := os.Link(spec.record, filepath.Join(filepath.Dir(spec.record), "other-link")); err != nil {
							t.Fatal(err)
						}
					case "unsafe_mode":
						if err := os.Chmod(spec.record, 0644); err != nil {
							t.Fatal(err)
						}
					case "directory":
						if err := os.Remove(spec.record); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(spec.record, 0700); err != nil {
							t.Fatal(err)
						}
					case "unsafe_parent":
						if err := os.Chmod(filepath.Dir(spec.record), 0777); err != nil {
							t.Fatal(err)
						}
					case "symlink_parent":
						dir := filepath.Dir(spec.record)
						alias := filepath.Join(t.TempDir(), "alias")
						if err := os.Symlink(dir, alias); err != nil {
							t.Fatal(err)
						}
						spec.record = filepath.Join(alias, filepath.Base(spec.record))
					}
					var inspected, installs, downloads, canInstall int
					inspectPinnedExecutable := func() error {
						inspected++
						if scenario == "untrusted_executable" {
							return errors.New("untrusted executable pin")
						}
						return nil
					}
					ops := productionMenuCompanionOps(inspectPinnedExecutable, spec)
					ops.canInstall = func(io.Reader, io.Writer) bool { canInstall++; return false }
					ops.download = func(context.Context, menuCompanionSpec, string) error {
						downloads++
						return errors.New("must not download")
					}
					ops.copyLocal = func(menuCompanionSpec, string, string) error {
						downloads++
						return errors.New("must not copy")
					}
					ops.install = func(context.Context, io.Writer, io.Writer, ...string) error {
						installs++
						return errors.New("must not run installer")
					}
					input := strings.NewReader("1\nINSTALL\n")
					var out bytes.Buffer
					got := menuEnsureCompanion(input, bufio.NewReader(input), &out, spec, ops)
					if want := scenario == "canonical"; got != want {
						t.Fatalf("unexpected %s %s admission result=%v want=%v: %q", kind, scenario, got, want, out.String())
					}
					if inspected != 1 || installs != 0 || downloads != 0 || canInstall != 0 {
						t.Fatalf("reuse bypassed proof or tried host effects: inspections=%d installs=%d downloads=%d rootGate=%d",
							inspected, installs, downloads, canInstall)
					}
					if scenario != "canonical" && !strings.Contains(out.String(), "will not overwrite") {
						t.Fatalf("untrusted record not given safe recovery: %q", out.String())
					}
					if now, err := os.ReadFile(spec.binary); err != nil || !bytes.Equal(now, exeContents) {
						t.Fatalf("rejected identity overwrote executable: %v", err)
					}
				})
			}
		}
	}
}

func TestMenuCompanionRecordRejectsWrongOwnerOrUnpinnedSpec(t *testing.T) {
	for _, kind := range []menuCompanionKind{menuCompanionWSS, menuCompanionQUIC} {
		t.Run(string(kind), func(t *testing.T) {
			spec, _ := menuRecordFixture(t, kind)
			if err := menuInspectOwnedCompanionRecord(spec, uint32(os.Geteuid())); err != nil {
				t.Fatalf("canonical owned record rejected: %v", err)
			}
			if err := menuInspectOwnedCompanionRecord(spec, uint32(os.Geteuid()+1)); err == nil {
				t.Fatal("foreign ownership accepted")
			}
			spec.version = "unapproved"
			if err := menuInspectOwnedCompanionRecord(spec, uint32(os.Geteuid())); err == nil {
				t.Fatal("unapproved version metadata accepted")
			}
		})
	}
}

func TestMenuCompanionInstallerPostflightRequiresRecord(t *testing.T) {
	for _, kind := range []menuCompanionKind{menuCompanionWSS, menuCompanionQUIC} {
		for _, withRecord := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/record=%v", kind, withRecord), func(t *testing.T) {
				spec, _ := menuRecordFixture(t, kind)
				expected := menuCanonicalRecordFixture(spec)
				if err := os.Remove(spec.record); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(spec.binary); err != nil {
					t.Fatal(err)
				}
				installed := false
				ops := productionMenuCompanionOps(func() error {
					if !installed {
						return errors.New("pinned helper absent")
					}
					return nil // verified executable after canonical install
				}, spec)
				ops.stageParent = t.TempDir()
				ops.canInstall = func(io.Reader, io.Writer) bool { return true }
				ops.download = func(_ context.Context, _ menuCompanionSpec, target string) error {
					return os.WriteFile(target, []byte("staged verified companion fixture"), 0600)
				}
				installs := 0
				ops.install = func(_ context.Context, _, _ io.Writer, _ ...string) error {
					installs++
					if err := os.WriteFile(spec.binary, []byte("pinned helper published by installer"), 0755); err != nil {
						return err
					}
					if withRecord {
						if err := os.WriteFile(spec.record, expected, 0600); err != nil {
							return err
						}
					}
					installed = true
					return nil
				}
				input := strings.NewReader("1\nINSTALL\n")
				var out bytes.Buffer
				ok := menuEnsureCompanion(input, bufio.NewReader(input), &out, spec, ops)
				if ok != withRecord || installs != 1 {
					t.Fatalf("post-install record guarantee failed, ok=%v installs=%d output=%q", ok, installs, out.String())
				}
				if !withRecord && !strings.Contains(out.String(), "identity is not verified") {
					t.Fatalf("missing installer record reported success: %q", out.String())
				}
			})
		}
	}
}
