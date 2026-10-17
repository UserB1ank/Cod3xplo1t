// Package scanner is the first fixed-version process scanner. It parses Go
// syntax from a frozen source tar and reports risky selector patterns. It never
// builds, tests or executes the target repository.
package scanner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin/wire"
)

const (
	ID      = "codexploit.static-patterns"
	Version = "1.0.0"
	// RulesetVersion changes whenever a rule or this scanner's rule set changes.
	RulesetVersion = "1"
)

var (
	ErrInvalidArchive = errors.New("scanner: invalid source archive")
	ErrInvalidConfig  = errors.New("scanner: invalid configuration")
)

type rule struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

var rules = []rule{
	{
		ID: "CP001", Version: RulesetVersion,
		Title:       "Command execution with a non-literal argument",
		Severity:    "high",
		Description: "os/exec.Command or CommandContext receives an argument that is not a string literal. This is a risky syntactic pattern, not proof that attacker-controlled data reaches it.",
	},
	{
		ID: "CP002", Version: RulesetVersion,
		Title:       "SQL query built from a non-literal expression",
		Severity:    "medium",
		Description: "A database/sql-style Query or Exec call receives a non-literal query expression. No type checking, taint propagation or exploitability is claimed.",
	},
}

// RulesetDigest binds the report to the exact rule table.
func RulesetDigest() string {
	raw, _ := json.Marshal(rules)
	sum := sha256.Sum256(append([]byte("codexploit/scanner-rules/v1\n"), raw...))
	return hex.EncodeToString(sum[:])
}

type config struct {
	MaxAlerts int `json:"max_alerts"`
}

type sourceFile struct {
	name string
	data []byte
}

// Scan parses the frozen source archive and returns a native alert report.
// Budget limits are inclusive: reaching a ceiling is allowed, exceeding it is a
// budget error. A parse failure is counted and disclosed instead of guessed.
func Scan(ctx context.Context, archive []byte, scope artifact.Scope, rawConfig json.RawMessage, budget plugin.Budget) (wire.ScannerReport, error) {
	budget = scanBudget(budget)
	if int64(len(archive)) > budget.MaxInputBytes {
		return wire.ScannerReport{}, plugin.ErrBudget
	}
	cfg := config{MaxAlerts: 200}
	if len(rawConfig) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(rawConfig))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil || cfg.MaxAlerts < 0 || cfg.MaxAlerts > 500 {
			return wire.ScannerReport{}, ErrInvalidConfig
		}
	}
	if cfg.MaxAlerts == 0 {
		cfg.MaxAlerts = 200
	}
	files, size, err := readArchive(ctx, archive, budget)
	if err != nil {
		return wire.ScannerReport{}, err
	}
	report := wire.ScannerReport{
		Format: wire.ScannerReportFormat,
		Scope:  scope,
		Tool:   wire.ToolInfo{ID: ID, Version: Version, Ruleset: RulesetDigest()},
		Capabilities: wire.PluginCapabilities{
			Alerts: true, Network: "none",
		},
		Coverage: plugin.Coverage{InputFiles: len(files), InputBytes: size},
		Limitations: []string{
			"Scanner parses Go syntax only; selector-name heuristics do not establish taint flow, exploitability or the validity of surrounding code",
			"Target build, tests, hooks and install scripts were not executed",
		},
		Alerts: []wire.ScannerAlert{},
	}
	descriptors := 0
	unparsed := 0
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return wire.ScannerReport{}, err
		}
		if !strings.HasSuffix(file.name, ".go") {
			if isDescriptor(file.name) {
				descriptors++
			}
			continue
		}
		fset := token.NewFileSet()
		parsed, parseErr := parser.ParseFile(fset, file.name, file.data, parser.AllErrors|parser.ParseComments)
		if parseErr != nil {
			unparsed++
			continue
		}
		report.Coverage.ParsedFiles++
		alerts := scanFile(fset, file.name, parsed, cfg.MaxAlerts+1-len(report.Alerts))
		for _, alert := range alerts {
			if len(report.Alerts) >= cfg.MaxAlerts {
				if !report.Coverage.Truncated {
					report.Coverage.Truncated = true
					report.Limitations = append(report.Limitations, "The alert budget truncated the scanner output; this is not a statement that the remaining files are clean")
				}
				break
			}
			report.Alerts = append(report.Alerts, alert)
		}
	}
	report.Coverage.DescriptorFiles = descriptors
	report.Coverage.UnparsedFiles = unparsed
	report.Coverage.UnhandledFiles = report.Coverage.InputFiles - report.Coverage.ParsedFiles - report.Coverage.UnparsedFiles - descriptors
	if report.Coverage.UnhandledFiles < 0 {
		return wire.ScannerReport{}, ErrInvalidArchive
	}
	if unparsed > 0 {
		report.Coverage.Truncated = true
		report.Limitations = append(report.Limitations, strconv.Itoa(unparsed)+" Go file(s) could not be parsed and were counted as unparsed")
	}
	return report, nil
}

func scanFile(fset *token.FileSet, name string, file *ast.File, remaining int) []wire.ScannerAlert {
	if remaining <= 0 {
		return nil
	}
	imports := map[string]string{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		alias := path.Base(importPath)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		imports[alias] = importPath
	}
	hasSQL := false
	for _, importPath := range imports {
		if importPath == "database/sql" {
			hasSQL = true
		}
	}
	alerts := []wire.ScannerAlert{}
	ast.Inspect(file, func(node ast.Node) bool {
		if len(alerts) >= remaining {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		position := fset.Position(call.Pos())
		if receiver, ok := selector.X.(*ast.Ident); ok {
			if imports[receiver.Name] == "os/exec" && (selector.Sel.Name == "Command" || selector.Sel.Name == "CommandContext") {
				start := 0
				if selector.Sel.Name == "CommandContext" {
					start = 1
				}
				if len(call.Args) > start && anyNonLiteral(call.Args[start:]) {
					alerts = append(alerts, makeAlert(rules[0], name, position, []string{
						"selector " + receiver.Name + "." + selector.Sel.Name + "(...)",
						fmt.Sprintf("call location %s:%d:%d", name, position.Line, position.Column),
					}))
				}
			}
		}
		if hasSQL {
			start := 0
			switch selector.Sel.Name {
			case "QueryContext", "ExecContext":
				start = 1
			case "Query", "Exec":
			default:
				return true
			}
			if len(call.Args) > start && !isStringLiteral(call.Args[start]) {
				alerts = append(alerts, makeAlert(rules[1], name, position, []string{
					"selector ." + selector.Sel.Name + "(...)",
					fmt.Sprintf("call location %s:%d:%d", name, position.Line, position.Column),
				}))
			}
		}
		return true
	})
	return alerts
}

func makeAlert(rule rule, file string, position token.Position, evidence []string) wire.ScannerAlert {
	identifier := file + "\x00" + strconv.Itoa(position.Line) + "\x00" + strconv.Itoa(position.Column) + "\x00" + rule.ID
	sum := sha256.Sum256([]byte(identifier))
	return wire.ScannerAlert{
		ID:           "alert-" + hex.EncodeToString(sum[:])[:24],
		RuleID:       rule.ID,
		RuleVersion:  rule.Version,
		Title:        rule.Title,
		SeverityHint: rule.Severity,
		File:         file,
		Line:         position.Line,
		EndLine:      position.Line,
		Column:       position.Column,
		Message:      rule.Description,
		Evidence:     evidence,
		Limitations: []string{
			"Selector-name heuristic; no type checking or data-flow analysis",
			"The target repository was parsed, never built or executed",
		},
	}
}

func anyNonLiteral(args []ast.Expr) bool {
	for _, arg := range args {
		if !isStringLiteral(arg) {
			return true
		}
	}
	return false
}

func isStringLiteral(expression ast.Expr) bool {
	literal, ok := expression.(*ast.BasicLit)
	return ok && literal.Kind == token.STRING
}

func isDescriptor(name string) bool {
	switch path.Base(name) {
	case "go.mod", "go.sum", "go.work", "go.work.sum":
		return true
	}
	return false
}

func readArchive(ctx context.Context, archive []byte, budget plugin.Budget) ([]sourceFile, int64, error) {
	reader := tar.NewReader(bytes.NewReader(archive))
	seen := map[string]bool{}
	files := []sourceFile{}
	var total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, ErrInvalidArchive
		}
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || !fs.ValidPath(header.Name) || strings.ContainsAny(header.Name, "\\\x00\n\r:") || path.Clean(header.Name) != header.Name || seen[strings.ToLower(header.Name)] {
			return nil, 0, ErrInvalidArchive
		}
		seen[strings.ToLower(header.Name)] = true
		if len(files) >= budget.MaxFiles || header.Size < 0 || header.Size > budget.MaxFileBytes || total+header.Size > budget.MaxInputBytes {
			return nil, 0, plugin.ErrBudget
		}
		total += header.Size
		var data []byte
		if strings.HasSuffix(header.Name, ".go") {
			data, err = io.ReadAll(io.LimitReader(reader, header.Size+1))
			if err != nil || int64(len(data)) != header.Size {
				return nil, 0, ErrInvalidArchive
			}
		}
		files = append(files, sourceFile{name: header.Name, data: data})
	}
	return files, total, nil
}

func scanBudget(budget plugin.Budget) plugin.Budget {
	if budget.MaxInputBytes <= 0 {
		budget.MaxInputBytes = 64 << 20
	}
	if budget.MaxOutputBytes <= 0 {
		budget.MaxOutputBytes = 16 << 20
	}
	if budget.MaxFiles <= 0 {
		budget.MaxFiles = 2000
	}
	if budget.MaxFileBytes <= 0 {
		budget.MaxFileBytes = 1 << 20
	}
	if budget.TimeoutSeconds <= 0 {
		budget.TimeoutSeconds = 60
	}
	return budget
}

// SortedRuleIDs is used by docs and tests without exposing mutable rule state.
func SortedRuleIDs() []string {
	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}
