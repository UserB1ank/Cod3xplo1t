package scanner_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin/wire"
	"github.com/open-mcp-ai/Codexploit/internal/scanner"
)

func sourceTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := []byte(files[name])
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o444, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func scanBudget() plugin.Budget {
	return plugin.Budget{MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20, MaxFiles: 100, MaxFileBytes: 64 << 10, MaxASTNodes: 10000, TimeoutSeconds: 30}
}

func scanOnce(t *testing.T, files map[string]string, config string) (wire.ScannerReport, error) {
	t.Helper()
	return scanner.Scan(context.Background(), sourceTar(t, files), artifact.Scope{ProjectID: "p", SourceID: "s", SnapshotID: "snap-scanner"}, json.RawMessage(config), scanBudget())
}

func TestScannerFindsOnlyTheRealRiskyPatternsInSyntheticSources(t *testing.T) {
	sentinel := filepath.Join(t.TempDir(), "executed")
	vulnerable := `package main

import (
	"fmt"
	"os"
	"os/exec"
)

func run(input string) {
	exec.Command("sh", "-c", input)
	exec.Command("echo", "literal")
	fmt.Println(os.Getenv("HOME"))
}
`
	withSideEffect := `package main

import "os"

func init() {
	_ = os.WriteFile("` + sentinel + `", []byte("executed"), 0o600)
}
`
	report, err := scanOnce(t, map[string]string{
		"main.go":   vulnerable,
		"init.go":   withSideEffect,
		"store.go":  "package main\n\nimport \"database/sql\"\n\nfunc find(db *sql.DB, id string) {\n\tdb.Query(\"SELECT * FROM t WHERE id=\" + id)\n\tdb.Query(\"SELECT 1\")\n}\n",
		"README.md": "synthetic\n",
		"go.mod":    "module example.test/synthetic\n\ngo 1.26\n",
	}, `{}`)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scanner executed target code: %v", err)
	}
	if report.Format != "codexploit/scanner-alerts/v1" || len(report.Alerts) != 2 {
		t.Fatalf("report = %+v", report)
	}
	rules := map[string]bool{}
	for _, alert := range report.Alerts {
		rules[alert.RuleID] = true
		if alert.File == "" || alert.Line < 1 || alert.SeverityHint == "" || alert.ID == "" {
			t.Fatalf("alert = %+v", alert)
		}
	}
	if !rules["CP001"] || !rules["CP002"] {
		t.Fatalf("rules = %+v", rules)
	}
	if report.Coverage.InputFiles != 5 || report.Coverage.ParsedFiles != 3 || report.Coverage.UnparsedFiles != 0 || report.Coverage.DescriptorFiles != 1 || report.Coverage.UnhandledFiles != 1 {
		t.Fatalf("coverage = %+v", report.Coverage)
	}
	if report.Capabilities.DataFlow || !report.Capabilities.Alerts || report.Capabilities.Network != "none" {
		t.Fatalf("capabilities = %+v", report.Capabilities)
	}
	joined := strings.Join(report.Limitations, "\n")
	if !strings.Contains(joined, "not executed") || !strings.Contains(joined, "taint") {
		t.Fatalf("limitations = %+v", report.Limitations)
	}
}

func TestScannerReportsSyntaxErrorsAsUnparsedWithoutInventingAlerts(t *testing.T) {
	report, err := scanOnce(t, map[string]string{
		"broken.go": "package main\nfunc (\n",
		"safe.go":   "package main\n\nfunc safe() { println(\"ok\") }\n",
	}, `{}`)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Alerts) != 0 || report.Coverage.UnparsedFiles != 1 || report.Coverage.ParsedFiles != 1 {
		t.Fatalf("report = %+v", report)
	}
	if !report.Coverage.Truncated && !strings.Contains(strings.Join(report.Limitations, "\n"), "unparsed") {
		t.Fatalf("syntax failure was not disclosed: %+v", report)
	}
}

func TestScannerHonoursTheAlertBudgetAndSaysItTruncated(t *testing.T) {
	report, err := scanOnce(t, map[string]string{
		"main.go": "package main\n\nimport \"os/exec\"\n\nfunc f(a, b, c string) {\n\texec.Command(a)\n\texec.Command(b)\n\texec.Command(c)\n}\n",
	}, `{"max_alerts":2}`)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Alerts) != 2 || !report.Coverage.Truncated || !strings.Contains(strings.Join(report.Limitations, "\n"), "truncated") {
		t.Fatalf("report = %+v", report)
	}
}

func TestScannerRejectsUnsafeTarEntries(t *testing.T) {
	for _, name := range []string{"../escape.go", "/absolute.go", `windows\path.go`} {
		t.Run(name, func(t *testing.T) {
			var buffer bytes.Buffer
			writer := tar.NewWriter(&buffer)
			_ = writer.WriteHeader(&tar.Header{Name: name, Mode: 0o444, Size: 4, Typeflag: tar.TypeReg})
			_, _ = writer.Write([]byte("data"))
			_ = writer.Close()
			if _, err := scanner.Scan(context.Background(), buffer.Bytes(), artifact.Scope{ProjectID: "p", SourceID: "s", SnapshotID: "snap"}, json.RawMessage(`{}`), scanBudget()); !errors.Is(err, scanner.ErrInvalidArchive) {
				t.Fatalf("Scan = %v, want ErrInvalidArchive", err)
			}
		})
	}
}

func TestScannerUsesOnlyTheDeclaredRulesetAndFixedVersion(t *testing.T) {
	report, err := scanOnce(t, map[string]string{"main.go": "package main\n"}, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if report.Tool.ID != scanner.ID || report.Tool.Version != scanner.Version || report.Tool.Ruleset != scanner.RulesetDigest() {
		t.Fatalf("tool = %+v", report.Tool)
	}
}
