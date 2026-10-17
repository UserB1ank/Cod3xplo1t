package plugin

import (
	"archive/tar"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"path"
	"reflect"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
)

type astNode struct {
	Kind        string `json:"kind"`
	Parent      int    `json:"parent"`
	StartLine   int    `json:"start_line"`
	StartColumn int    `json:"start_column"`
	EndLine     int    `json:"end_line"`
	EndColumn   int    `json:"end_column"`
	Value       string `json:"value,omitempty"`
}
type astFile struct {
	File        string    `json:"file"`
	ParseStatus string    `json:"parse_status"`
	Nodes       []astNode `json:"nodes"`
	Diagnostic  string    `json:"diagnostic,omitempty"`
}
type factFile struct {
	File        string         `json:"file"`
	FileID      string         `json:"file_id"`
	ParseStatus string         `json:"parse_status"`
	Symbols     []scg.Symbol   `json:"symbols"`
	Calls       []scg.CallSite `json:"calls"`
	Notes       []string       `json:"limitations"`
}

func (h *Host) parse(ctx context.Context, inv Invocation) ([]artifact.Ref, Coverage, []string, error) {
	coverage := Coverage{}
	limitations := []string{"AST is a native Go syntax-node index with parent links; code facts do not prove taint flow or exploitability"}
	fail := func(err error) ([]artifact.Ref, Coverage, []string, error) { return nil, coverage, limitations, err }
	input, _, err := h.deps.Artifacts.Open(ctx, inv.Request.Scope, inv.Request.Inputs[0].ID, inv.Request.Budget.MaxInputBytes)
	if err != nil {
		return fail(err)
	}
	defer input.Close()
	tr := tar.NewReader(input)
	contents := map[string][]byte{}
	seen := map[string]bool{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(ErrInvalid)
		}
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if !fs.ValidPath(header.Name) || strings.Contains(header.Name, "\\") || header.Typeflag != tar.TypeReg || seen[header.Name] || header.Size < 0 {
			return fail(ErrInvalid)
		}
		seen[header.Name] = true
		coverage.InputFiles++
		coverage.InputBytes += header.Size
		if coverage.InputFiles > inv.Request.Budget.MaxFiles || coverage.InputBytes > inv.Request.Budget.MaxInputBytes {
			return fail(ErrBudget)
		}
		if !strings.HasSuffix(header.Name, ".go") && path.Base(header.Name) != "go.mod" {
			coverage.UnhandledFiles++
			continue
		}
		if header.Size > inv.Request.Budget.MaxFileBytes {
			return fail(ErrBudget)
		}
		data, err := io.ReadAll(io.LimitReader(tr, header.Size+1))
		if err != nil {
			return fail(err)
		}
		if int64(len(data)) != header.Size {
			return fail(ErrInvalid)
		}
		contents[header.Name] = data
	}
	modules := map[string]string{}
	files := []string{}
	for name, data := range contents {
		if path.Base(name) == "go.mod" {
			coverage.DescriptorFiles++
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "module" {
					modules[path.Dir(name)] = strings.Trim(fields[1], "\"")
					break
				}
			}
		} else {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	astFiles := []astFile{}
	factFiles := []factFile{}
	nodeCount := 0
	nodeExceeded := false
	var config struct {
		IncludeComments bool `json:"include_comments"`
	}
	_ = json.Unmarshal(inv.Request.Config, &config)
	frontend := gofrontend.New()
	for _, name := range files {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		moduleDir, moduleName := ".", ""
		best := -1
		for dir, mod := range modules {
			if dir == "." || strings.HasPrefix(name, dir+"/") {
				if len(dir) > best {
					best = len(dir)
					moduleDir, moduleName = dir, mod
				}
			}
		}
		dir := path.Dir(name)
		if moduleDir != "." {
			dir = strings.TrimPrefix(strings.TrimPrefix(dir, moduleDir), "/")
			if dir == "" {
				dir = "."
			}
		}
		pkg := frontend.PackagePath(scg.Module{Name: moduleName}, dir)
		unit, err := frontend.Parse(ctx, scg.FrontendFile{Path: name, Language: "Go", PackagePath: pkg, ModulePath: moduleName, Content: contents[name]})
		if err != nil {
			return fail(err)
		}
		switch unit.Status {
		case scg.ParseOK:
			coverage.ParsedFiles++
		case scg.ParsePartial:
			coverage.PartialFiles++
		default:
			coverage.UnparsedFiles++
		}
		facts := factFile{File: name, FileID: scg.FileID(inv.Request.Scope.SnapshotID, name), ParseStatus: unit.Status, Symbols: []scg.Symbol{}, Calls: []scg.CallSite{}, Notes: append([]string{}, unit.Notes...)}
		for _, decl := range unit.Declarations {
			qualified := decl.Name
			if decl.Kind == scg.KindMethod && decl.Receiver != "" {
				qualified = decl.Receiver + "." + qualified
			}
			if pkg != "" {
				qualified = pkg + "." + qualified
			}
			loc := scg.Location{File: name, Line: decl.StartLine, Col: decl.StartCol}
			facts.Symbols = append(facts.Symbols, scg.Symbol{ID: scg.SymbolID(inv.Request.Scope.SnapshotID, "Go", name, qualified, decl.Signature, loc), SnapshotID: inv.Request.Scope.SnapshotID, ModuleID: scg.ModuleID(inv.Request.Scope.SnapshotID, moduleDir), FileID: facts.FileID, File: name, Language: "Go", Kind: decl.Kind, Name: decl.Name, QualifiedName: qualified, Signature: decl.Signature, Receiver: decl.Receiver, ResultType: decl.ResultType, Exported: decl.Exported, StartLine: decl.StartLine, EndLine: decl.EndLine, StartCol: decl.StartCol, EndCol: decl.EndCol})
		}
		for _, call := range unit.Calls {
			site := scg.CallSite{ID: scg.CallSiteID(inv.Request.Scope.SnapshotID, name, call.Line, call.Col, call.Text), SnapshotID: inv.Request.Scope.SnapshotID, FileID: facts.FileID, File: name, Line: call.Line, Col: call.Col, CalleeText: call.Text, Resolution: scg.Unsupported, Confidence: scg.Unresolved, Detail: "syntax reference; call resolution is a separate analysis stage", Analyzer: frontend.Name(), AnalyzerVersion: frontend.Version()}
			if call.EnclosingDecl >= 0 && call.EnclosingDecl < len(facts.Symbols) {
				site.CallerSymbolID = facts.Symbols[call.EnclosingDecl].ID
			}
			facts.Calls = append(facts.Calls, site)
		}
		fset := token.NewFileSet()
		mode := parser.SkipObjectResolution
		if config.IncludeComments {
			mode |= parser.ParseComments
		}
		tree, _ := parser.ParseFile(fset, name, contents[name], mode)
		native := astFile{File: name, ParseStatus: unit.Status, Nodes: []astNode{}, Diagnostic: unit.Error}
		stack := []int{}
		if tree != nil {
			ast.Inspect(tree, func(node ast.Node) bool {
				if node == nil {
					if len(stack) > 0 {
						stack = stack[:len(stack)-1]
					}
					return false
				}
				if ctx.Err() != nil {
					return false
				}
				if nodeCount >= inv.Request.Budget.MaxASTNodes {
					nodeExceeded = true
					return false
				}
				parent := -1
				if len(stack) > 0 {
					parent = stack[len(stack)-1]
				}
				start, end := fset.Position(node.Pos()), fset.Position(node.End())
				value := ""
				switch n := node.(type) {
				case *ast.Ident:
					value = n.Name
				case *ast.BasicLit:
					value = n.Value
				case *ast.Comment:
					value = n.Text
				}
				native.Nodes = append(native.Nodes, astNode{Kind: reflect.TypeOf(node).Elem().Name(), Parent: parent, StartLine: start.Line, StartColumn: start.Column, EndLine: end.Line, EndColumn: end.Column, Value: value})
				stack = append(stack, len(native.Nodes)-1)
				nodeCount++
				return true
			})
		}
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if nodeExceeded {
			return fail(ErrBudget)
		}
		astFiles = append(astFiles, native)
		factFiles = append(factFiles, facts)
	}
	if coverage.UnhandledFiles > 0 {
		limitations = append(limitations, "Other input files were not parsed; only Go syntax is supported")
	}
	if len(files) == 0 {
		limitations = append(limitations, "No Go source files were present; zero files were scanned")
		return []artifact.Ref{}, coverage, limitations, nil
	}
	astDoc := struct {
		APIVersion string         `json:"api_version"`
		Scope      artifact.Scope `json:"scope"`
		Format     string         `json:"format"`
		Coverage   Coverage       `json:"coverage"`
		Files      []astFile      `json:"files"`
	}{"codexploit/v1", inv.Request.Scope, "go/ast-node-index/v1", coverage, astFiles}
	factsDoc := struct {
		APIVersion  string         `json:"api_version"`
		Scope       artifact.Scope `json:"scope"`
		Coverage    Coverage       `json:"coverage"`
		Files       []factFile     `json:"files"`
		Limitations []string       `json:"limitations"`
	}{"codexploit/v1", inv.Request.Scope, coverage, factFiles, limitations}
	first, err := h.prepare(ctx, inv, "ast", astDoc)
	if err != nil {
		return fail(err)
	}
	inv.Request.Budget.MaxOutputBytes -= first.Bytes
	if inv.Request.Budget.MaxOutputBytes < 1 {
		return fail(ErrBudget)
	}
	second, err := h.prepare(ctx, inv, "facts", factsDoc)
	if err != nil {
		return fail(err)
	}
	return []artifact.Ref{first, second}, coverage, limitations, nil
}
