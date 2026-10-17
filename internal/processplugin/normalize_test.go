package processplugin_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin/wire"
)

func nativeScannerFixture(t *testing.T, mutate func(*wire.ScannerReport)) (plugin.Invocation, artifact.Ref, []byte) {
	t.Helper()
	inv := fixtureInvocation()
	report := wire.ScannerReport{
		Format: wire.ScannerReportFormat,
		Scope:  inv.Request.Scope,
		Tool:   wire.ToolInfo{ID: fixtureID, Version: fixtureVersion, Ruleset: "fixture-rules-1"},
		Capabilities: wire.PluginCapabilities{
			Alerts: true, Network: "none",
		},
		Coverage: plugin.Coverage{InputFiles: 2, ParsedFiles: 1, UnparsedFiles: 1, InputBytes: 20},
		Limitations: []string{
			"Rule hits are observations; no taint flow or exploitability is established",
		},
		Alerts: []wire.ScannerAlert{
			{
				ID:           "alert-1",
				RuleID:       "CP001",
				RuleVersion:  "1",
				Title:        "Command execution with a non-literal argument",
				SeverityHint: "high",
				File:         "cmd/server/main.go",
				Line:         17,
				EndLine:      19,
				Column:       4,
				Message:      "os/exec.Command receives a variable",
				Evidence:     []string{"call tree: main -> run"},
				Limitations:  []string{"Location only"},
			},
			{
				ID:           "alert-2",
				RuleID:       "CP002",
				RuleVersion:  "1",
				Title:        "SQL query built from a non-literal expression",
				SeverityHint: "medium",
				File:         "store.go",
				Line:         9,
				EndLine:      9,
				Column:       3,
				Message:      "database/sql Query receives a concatenation",
				Evidence:     []string{"database/sql.Query"},
				Limitations:  []string{"Location only"},
			},
		},
	}
	if mutate != nil {
		mutate(&report)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	native := artifact.Ref{
		ID:        "artifact-" + inv.ID + "-native",
		Kind:      "scanner.alerts",
		Scope:     inv.Request.Scope,
		SHA256:    hex.EncodeToString(sum[:]),
		Bytes:     int64(len(raw)),
		MediaType: "application/json",
		SchemaID:  "codexploit/scanner-alerts/v1",
		Producer: artifact.Producer{
			PluginID:      inv.Request.PluginID,
			PluginVersion: inv.Request.PluginVersion,
			InvocationID:  inv.ID,
			ConfigDigest:  inv.ConfigDigest,
		},
	}
	return inv, native, raw
}

func TestNormalizeMapsAlertsToCandidatesWithoutInventingPaths(t *testing.T) {
	inv, native, raw := nativeScannerFixture(t, nil)
	document, err := processplugin.Normalize(inv, native, raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if document.Kind != "security.facts" || len(document.Candidates) != 2 || len(document.Paths) != 0 || len(document.Nodes) != 0 || len(document.Edges) != 0 {
		t.Fatalf("document = %+v", document)
	}
	candidate := document.Candidates[0]
	if candidate.ID == "" || candidate.Status != "candidate" || candidate.SeverityHint != "high" || candidate.File != "cmd/server/main.go" || candidate.Line != 17 {
		t.Fatalf("candidate = %+v", candidate)
	}
	if !strings.Contains(candidate.Title, "CP001") || len(candidate.PathRefs) != 0 {
		t.Fatalf("candidate lost rule identity or invented a path: %+v", candidate)
	}
	if len(candidate.EvidenceRefs) != 1 || candidate.EvidenceRefs[0] != native.ID {
		t.Fatalf("evidence = %+v", candidate.EvidenceRefs)
	}
	joined := strings.Join(candidate.Limitations, "\n")
	if !strings.Contains(joined, "taint") || !strings.Contains(joined, "Location only") {
		t.Fatalf("limitations = %+v", candidate.Limitations)
	}
	if err := plugin.ValidateDiscovery(document); err != nil {
		t.Fatalf("normalized document violates the schema: %v", err)
	}
}

func TestNormalizeRejectsUnsupportedCapabilitiesAndFormats(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*wire.ScannerReport)
	}{
		{name: "taint", mutate: func(report *wire.ScannerReport) { report.Capabilities.DataFlow = true }},
		{name: "paths", mutate: func(report *wire.ScannerReport) { report.Capabilities.CallReachability = true }},
		{name: "unknown-format", mutate: func(report *wire.ScannerReport) { report.Format = "codexploit/unknown-alerts/v9" }},
		{name: "network", mutate: func(report *wire.ScannerReport) { report.Capabilities.Network = "restricted" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			inv, native, raw := nativeScannerFixture(t, test.mutate)
			if _, err := processplugin.Normalize(inv, native, raw); !errors.Is(err, plugin.ErrUnsupported) {
				t.Fatalf("Normalize = %v, want ErrUnsupported", err)
			}
		})
	}
}

func TestNormalizeRejectsEscapingFilesAndForgedEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*wire.ScannerReport)
	}{
		{name: "parent-file", mutate: func(report *wire.ScannerReport) { report.Alerts[0].File = "../etc/passwd" }},
		{name: "absolute-file", mutate: func(report *wire.ScannerReport) { report.Alerts[0].File = "/etc/passwd" }},
		{name: "backslash-file", mutate: func(report *wire.ScannerReport) { report.Alerts[0].File = `cmd\main.go` }},
		{name: "zero-line", mutate: func(report *wire.ScannerReport) { report.Alerts[0].Line = 0 }},
		{name: "bad-severity", mutate: func(report *wire.ScannerReport) { report.Alerts[0].SeverityHint = "critical" }},
		{name: "duplicate-id", mutate: func(report *wire.ScannerReport) { report.Alerts[1].ID = report.Alerts[0].ID }},
		{name: "wrong-scope", mutate: func(report *wire.ScannerReport) { report.Scope.SnapshotID = "snap-other" }},
		{name: "wrong-tool", mutate: func(report *wire.ScannerReport) { report.Tool.ID = "other.scanner" }},
		{name: "too-many", mutate: func(report *wire.ScannerReport) {
			report.Alerts = append(report.Alerts, report.Alerts[0])
		}},
		{name: "forged-input", mutate: func(report *wire.ScannerReport) { report.Scope.ProjectID = "other-project" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			inv, native, raw := nativeScannerFixture(t, test.mutate)
			if test.name == "too-many" {
				inv.Request.Config = json.RawMessage(`{"max_alerts":1}`)
			}
			if _, err := processplugin.Normalize(inv, native, raw); !errors.Is(err, plugin.ErrInvalid) {
				t.Fatalf("Normalize = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestNormalizeRejectsAChangedNativeReport(t *testing.T) {
	inv, native, raw := nativeScannerFixture(t, nil)
	changed := append([]byte(nil), raw...)
	changed[len(changed)-2] ^= 1
	if _, err := processplugin.Normalize(inv, native, changed); !errors.Is(err, plugin.ErrInvalid) {
		t.Fatalf("Normalize = %v, want ErrInvalid", err)
	}
}
