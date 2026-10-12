package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestReadOnlyOperatorSurfacesRetainEvidenceBackedModuleReason(t *testing.T) {
	link, _ := makeLifecycleDesired(t, "d", "10.70.23.0/31")
	observed := backend.KernelModuleNotLoaded("fou")
	health := healthDiagnosticFailure(link, observed)
	if health.Status != "blocked" || health.ReasonCode != "kernel_module_not_loaded" ||
		strings.Contains(health.Summary, "PSK") || health.NextStep == "" {
		t.Fatalf("batch health check did not preserve trusted module classification: %+v", health)
	}
	var stdout, stderr bytes.Buffer
	exit := readStatusInspectionError(context.Background(), &stdout, &stderr, true, observed)
	var response linkReadErrorResponse
	if exit != 1 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &response) != nil ||
		response.SchemaVersion != 1 || response.Error == nil ||
		response.Error.Code != stlerr.CodeInspect || response.Error.ReasonCode != "kernel_module_not_loaded" ||
		response.Error.NextStep == "" {
		t.Fatalf("per-Link status error lost safe typed guidance: exit=%d body=%s", exit, stdout.String())
	}
}
