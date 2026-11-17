package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestLongAPTPlanApprovalUsesExactSHAWithoutTruncation(t *testing.T) {
	terms := []string{"iproute2=6.0.0-1"}
	for i := 0; i < 4500; i++ {
		terms = append(terms, fmt.Sprintf("dependency-%05d=1.0.0", i))
	}
	planText := strings.Join(terms, " ")
	if len(planText) <= 16*1024 {
		t.Fatalf("large plan fixture too small: %d", len(planText))
	}
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(planText)))
	var previews, installs int
	selected := tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}
	ops := menuPackagePreparationOps{
		preview: func(context.Context, tunnelOption) (selectedPackagePreview, error) {
			previews++
			if installs > 0 {
				return selectedPackagePreview{packages: "iproute2 iptables kmod"}, nil
			}
			return selectedPackagePreview{packages: "iproute2 iptables kmod",
				missing: "iproute2", aptInstall: planText, aptDigest: sha}, nil
		},
		canPrepare: func(io.Reader, io.Writer) bool { return true },
		install: func(_ context.Context, _, _ io.Writer, args ...string) error {
			installs++
			expected := []string{"prepare", "--backends", "native", "--expected-missing", "iproute2",
				"--expected-apt-plan-sha256", sha}
			if !slices.Equal(args, expected) {
				t.Fatalf("large plan was truncated or unauthorized: %q", args)
			}
			return nil
		},
	}
	input := strings.NewReader("PREPARE\n")
	var out, errOut bytes.Buffer
	approval := menuPrepareSelectedPackagesWithOps(input, bufio.NewReader(input),
		&out, &errOut, selected, nil, ops)
	if !approval.approvedFor(selected) || installs != 1 || previews != 3 {
		t.Fatalf("legitimate large dependency plan was blocked: approval=%+v previews=%d installs=%d errors=%q",
			approval, previews, installs, errOut.String())
	}
}

func TestLongAPTPlanChangesAfterConfirmationCannotStartInstaller(t *testing.T) {
	first := "iproute2=6.0.0-1 " + strings.Repeat("dependency=1.0.0 ", 1400)
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(first)))
	var previews, installs int
	selected := tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}
	ops := menuPackagePreparationOps{
		preview: func(context.Context, tunnelOption) (selectedPackagePreview, error) {
			previews++
			if previews == 2 {
				return selectedPackagePreview{packages: "iproute2 iptables kmod",
					missing: "iproute2", aptInstall: strings.Replace(first, "6.0.0-1", "6.0.0-2", 1),
					aptDigest: sha}, nil
			}
			return selectedPackagePreview{packages: "iproute2 iptables kmod",
				missing: "iproute2", aptInstall: first, aptDigest: sha}, nil
		},
		canPrepare: func(io.Reader, io.Writer) bool { return true },
		install: func(context.Context, io.Writer, io.Writer, ...string) error {
			installs++
			return nil
		},
	}
	input := strings.NewReader("PREPARE\n")
	var out, errOut bytes.Buffer
	approval := menuPrepareSelectedPackagesWithOps(input, bufio.NewReader(input),
		&out, &errOut, selected, nil, ops)
	if approval.approvedFor(selected) || installs != 0 || previews != 2 ||
		!strings.Contains(out.String(), "could not be confirmed") {
		t.Fatalf("changed long plan authorized APT: approval=%+v previews=%d installs=%d errors=%q",
			approval, previews, installs, errOut.String())
	}
}
