package linux

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A publication SOURCE is a security-relevant identity just as much as its
// no-clobber DESTINATION. None of these tests use a privileged host/service.
func TestInitialUnitHardlinkRejectsUnverifiedStagingSource(t *testing.T) {
	for _, tc := range []string{"foreign-regular", "same-text-new-inode", "edit-in-place", "symlink", "fifo"} {
		t.Run(tc, func(t *testing.T) {
			dir, path, _, runner, p := newCompensationFixture(t, false, false)
			unexpected := []byte("[Unit]\nDescription=other manager's independent source\n")
			var savedOriginal string
			var target string
			triggered := false
			p.beforeUnitMutation = func(phase string) {
				if phase != "create-source-link" {
					return
				}
				triggered = true
				stages, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
				if err != nil || len(stages) != 1 {
					t.Fatalf("did not find source staging before hardlink: %v %v", stages, err)
				}
				stage := stages[0]
				data, err := os.ReadFile(stage)
				if err != nil {
					t.Fatal(err)
				}
				if tc == "edit-in-place" {
					if err := os.WriteFile(stage, unexpected, 0o644); err != nil {
						t.Fatal(err)
					}
					return
				}
				savedOriginal = filepath.Join(dir, "original-intended-source")
				if err := os.Rename(stage, savedOriginal); err != nil {
					t.Fatal(err)
				}
				switch tc {
				case "foreign-regular":
					err = os.WriteFile(stage, unexpected, 0o644)
				case "same-text-new-inode":
					unexpected = data
					err = os.WriteFile(stage, data, 0o644)
				case "symlink":
					target = filepath.Join(dir, "unrelated")
					if err := os.WriteFile(target, unexpected, 0o644); err != nil {
						t.Fatal(err)
					}
					err = os.Symlink(target, stage)
				case "fifo":
					makeNoWriterFIFO(t, stage)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan error, 1)
			go func() {
				_, _, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
				result <- err
			}()
			var err error
			select {
			case err = <-result:
			case <-time.After(3 * time.Second):
				t.Fatal("source symlink/FIFO must never hang initial hardlink publication")
			}
			if !triggered || !errors.Is(err, errUnitIdentityConflict) {
				t.Fatalf("invalid initial source not caught before publication: hook=%t err=%v", triggered, err)
			}
			if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("unverified canonical source was linked despite rejection: %v", e)
			}
			expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
			stages, e := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
			if e != nil || len(stages) != 1 || !strings.Contains(err.Error(), stages[0]) {
				t.Fatalf("protected recovery identity not recorded: %v %v err=%v", stages, e, err)
			}
			switch tc {
			case "symlink":
				value, e := os.Readlink(stages[0])
				if e != nil || value != target {
					t.Fatalf("independent symlink source was lost: %q %v", value, e)
				}
			case "fifo":
				info, e := os.Lstat(stages[0])
				if e != nil || info.Mode()&os.ModeNamedPipe == 0 {
					t.Fatalf("independent fifo source was lost: %v %v", info, e)
				}
			default:
				data, e := os.ReadFile(stages[0])
				if e != nil || !bytes.Equal(data, unexpected) {
					t.Fatalf("independent source was unlinked: %q %v", data, e)
				}
			}
			if savedOriginal != "" {
				if _, e := os.Lstat(savedOriginal); e != nil {
					t.Fatalf("original STL source inode lost: %v", e)
				}
			}
		})
	}
}

func TestInitialHardlinkPostPublicationSourceMutationPreservesForeignIdentity(t *testing.T) {
	for _, kind := range []string{"source-edit-in-place", "source-inode-swapped", "canonical-edit-in-place"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, _, runner, p := newCompensationFixture(t, false, false)
			foreign := []byte("[Unit]\nDescription=foreign after hardlink\n")
			triggered := false
			p.afterUnitTransition = func(phase string) {
				if phase != "after-absent-publication-link" {
					return
				}
				triggered = true
				sources, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
				if err != nil || len(sources) != 1 {
					t.Fatalf("missing linked initial source: %v %v", sources, err)
				}
				switch kind {
				case "source-edit-in-place":
					err = os.WriteFile(sources[0], foreign, 0o644)
				case "source-inode-swapped":
					err = os.Rename(sources[0], sources[0]+".original")
					if err == nil {
						err = os.WriteFile(sources[0], foreign, 0o644)
					}
				case "canonical-edit-in-place":
					err = os.WriteFile(path, foreign, 0o644)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			_, _, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
			if !triggered || err == nil {
				t.Fatalf("post-link source change was accepted: hook=%t err=%v", triggered, err)
			}
			var publication *unitPublicationError
			if !errors.As(err, &publication) {
				t.Fatalf("unverified linked state was treated as an untouched filesystem: %v", err)
			}
			for _, command := range runner.commands {
				if strings.Contains(command, "enable ") {
					t.Fatalf("unverified initial unit was enabled: %v", runner.commands)
				}
				if kind != "source-inode-swapped" && strings.Contains(command, "daemon-reload") {
					t.Fatalf("unverified canonical unit was reloaded: %v", runner.commands)
				}
			}
			if kind == "source-inode-swapped" {
				if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
					t.Fatalf("verified owned canonical unit not guardedly compensated: %v", e)
				}
				sources, _ := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
				if len(sources) != 1 {
					t.Fatalf("foreign source was deleted: %v", sources)
				}
				got, e := os.ReadFile(sources[0])
				if e != nil || !bytes.Equal(got, foreign) {
					t.Fatalf("foreign source was lost: %q %v", got, e)
				}
			} else {
				content, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(content, foreign) {
					t.Fatalf("foreign canonical identity was not preserved for recovery: %q %v", content, e)
				}
			}
		})
	}
}

func TestRemovalCompensationNeverHardlinksUnverifiedSource(t *testing.T) {
	dir, path, _, runner, p := newCompensationFixture(t, false, false)
	prior := []byte(managedSystemdMarker + "\n[Unit]\nDescription=prior owned\n")
	foreign := []byte("[Unit]\nDescription=unrelated removal recovery source\n")
	triggered := false
	p.beforeUnitMutation = func(phase string) {
		if phase != "compensate-source-link" {
			return
		}
		triggered = true
		sources, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
		if err != nil || len(sources) != 1 {
			t.Fatalf("missing compensation staging: %v %v", sources, err)
		}
		if err := os.WriteFile(sources[0], foreign, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := p.compensateRemovedUnit(context.Background(), "systemctl", dir, path, prior, nil, false)
	if !triggered || !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("unverified removal recovery source accepted: triggered=%t err=%v", triggered, err)
	}
	if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("removal compensation installed foreign canonical unit: %v", e)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("removal compensation reached systemctl for invalid source: %v", runner.commands)
	}
	stages, e := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
	if e != nil || len(stages) != 1 {
		t.Fatalf("unknown recovery source deleted: %v %v", stages, e)
	}
	data, e := os.ReadFile(stages[0])
	if e != nil || !bytes.Equal(data, foreign) {
		t.Fatalf("unknown compensation source lost: %q %v", data, e)
	}
}

// A source may change after the pre-link verification but immediately before
// os.Link. The destination's EEXIST guarantee cannot validate its source.
func TestInitialHardlinkRejectsLateSourceSwapAfterPrecheck(t *testing.T) {
	for _, sameBytes := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign bytes", true: "byte-identical foreign inode"}[sameBytes], func(t *testing.T) {
			dir, path, _, runner, p := newCompensationFixture(t, false, false)
			foreign := []byte("[Unit]\nDescription=foreign linked after precheck\n")
			var savedOriginal string
			p.afterUnitTransition = func(phase string) {
				if phase != "before-absent-publication-hardlink" {
					return
				}
				stages, e := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
				if e != nil || len(stages) != 1 {
					t.Fatalf("missing pre-link stage: %v %v", stages, e)
				}
				if sameBytes {
					foreign, e = os.ReadFile(stages[0])
					if e != nil {
						t.Fatal(e)
					}
				}
				savedOriginal = filepath.Join(dir, "original-staging-inode")
				if e := os.Rename(stages[0], savedOriginal); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(stages[0], foreign, 0o644); e != nil {
					t.Fatal(e)
				}
			}
			_, _, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
			var publication *unitPublicationError
			if err == nil || !errors.Is(err, errUnitIdentityConflict) || !errors.As(err, &publication) {
				t.Fatalf("foreign late hardlink source not classified post-publication: %v", err)
			}
			linked, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(linked, foreign) {
				t.Fatalf("foreign canonical unit deleted or replaced: %q %v", linked, e)
			}
			if _, e := os.Lstat(savedOriginal); e != nil {
				t.Fatalf("original STL staging inode lost: %v", e)
			}
			stages, e := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
			if e != nil || len(stages) != 1 || !strings.Contains(err.Error(), stages[0]) {
				t.Fatalf("independent staging not preserved and surfaced: %v %v %v", stages, e, err)
			}
			expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
		})
	}
}
