// Package builtinanalysis adapts the existing static engines to versioned plugins.
package builtinanalysis

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

//go:embed semantic.go paths.go
var source embed.FS

func Executors() []plugin.Executor {
	raw, _ := source.ReadFile("semantic.go")
	pathRaw, _ := source.ReadFile("paths.go")
	raw = append(raw, pathRaw...)
	packageDigest := fmt.Sprintf("%x", sha256.Sum256(append(raw, []byte(plugin.BuiltinPackageDigest()+scg.ImplementationDigest()+asg.ImplementationDigest()+path.ImplementationDigest()+graph.ImplementationDigest()+runtime.Version())...)))
	return []plugin.Executor{
		{Manifest: json.RawMessage(`{"api_version":"codexploit/v1","id":"builtin.security-semantics","version":"1.2.0","name":"Security semantics","description":"Read-only ASG rules over fixed Go parser inputs; no taint analysis.","kind":"analyzer","languages":["Go"],"runtime":{"kind":"builtin"},"consumes":["source.snapshot","code.facts"],"produces":["report.document","security.facts"],"permissions":{"network":"none","source_write":false},"config_schema":{"type":"object","properties":{},"additionalProperties":false}}`), PackageDigest: packageDigest, InputSchemas: []string{"codexploit/source-tar/v1", "codexploit/go-facts/v1"}, InputPlugins: []string{"", plugin.BuiltinID}, Run: semantic},
		{Manifest: json.RawMessage(`{"api_version":"codexploit/v1","id":"builtin.discovery-paths","version":"1.2.0","name":"Candidate paths","description":"Bounded call reachability and candidate observations; no taint or verdict capability.","kind":"analyzer","languages":["Go"],"runtime":{"kind":"builtin"},"consumes":["security.facts","report.document"],"produces":["report.document","discovery.paths"],"permissions":{"network":"none","source_write":false},"config_schema":{"type":"object","properties":{"max_paths":{"type":"integer","minimum":1,"maximum":500},"max_depth":{"type":"integer","minimum":1,"maximum":8}},"additionalProperties":false}}`), PackageDigest: packageDigest, InputSchemas: []string{"codexploit/discovery/v1", "codexploit/builtin-native/v1"}, InputPlugins: []string{plugin.SemanticID, plugin.SemanticID}, Run: paths},
	}
}

func semantic(ctx context.Context, inv plugin.Invocation, inputs [][]byte) ([]byte, error) {
	tree, err := os.MkdirTemp("", "codexploit-static-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tree)
	tr := tar.NewReader(strings.NewReader(string(inputs[0])))
	seen := map[string]bool{}
	var size int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, plugin.ErrInvalid
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !fs.ValidPath(header.Name) || strings.ContainsAny(header.Name, "\\:") || header.Typeflag != tar.TypeReg || seen[header.Name] || header.Size < 0 {
			return nil, plugin.ErrInvalid
		}
		seen[header.Name] = true
		size += header.Size
		if len(seen) > inv.Request.Budget.MaxFiles || size > inv.Request.Budget.MaxInputBytes || header.Size > inv.Request.Budget.MaxFileBytes {
			return nil, plugin.ErrBudget
		}
		target := filepath.Join(tree, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, copyErr := io.CopyN(file, tr, header.Size)
		closeErr := file.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	builder := scg.NewBuilder(gofrontend.New())
	builder.Limits.MaxFiles = inv.Request.Budget.MaxFiles
	builder.Limits.MaxFileBytes = inv.Request.Budget.MaxFileBytes
	builder.Limits.MaxSymbols = inv.Request.Budget.MaxASTNodes
	builder.Limits.MaxCallSites = inv.Request.Budget.MaxASTNodes
	builder.Limits.MaxEdges = inv.Request.Budget.MaxASTNodes
	code, err := builder.BuildTree(ctx, inv.Request.Scope.SnapshotID, tree)
	if err != nil {
		return nil, err
	}
	if len(code.Symbols)+len(code.CallSites)+len(code.Edges) > inv.Request.Budget.MaxASTNodes || code.Coverage.SymbolsSkipped > 0 {
		return nil, plugin.ErrBudget
	}
	var parserFacts struct {
		Files []struct {
			Symbols []scg.Symbol `json:"symbols"`
		} `json:"files"`
	}
	if json.Unmarshal(inputs[1], &parserFacts) != nil {
		return nil, plugin.ErrInvalid
	}
	symbols := map[string]bool{}
	for _, symbol := range code.Symbols {
		symbols[symbol.ID] = true
	}
	for _, file := range parserFacts.Files {
		for _, symbol := range file.Symbols {
			if !symbols[symbol.ID] {
				return nil, plugin.ErrInvalid
			}
		}
	}
	memory := storage.NewMemory()
	if err := memory.ReplaceGraph(ctx, code.SnapshotID, code); err != nil {
		return nil, err
	}
	service := graph.NewService(memory, nil)
	surface, err := asg.NewBuilder(service).Build(ctx, code.SnapshotID)
	if err != nil {
		return nil, err
	}
	coverage := plugin.Coverage{InputFiles: len(seen), ParsedFiles: code.Coverage.FilesParsed - code.Coverage.FilesPartial, PartialFiles: code.Coverage.FilesPartial, UnparsedFiles: code.Coverage.FilesUnparsed, UnhandledFiles: code.Coverage.FilesUnsupported, InputBytes: size}
	for name := range seen {
		if filepath.Base(name) == "go.mod" {
			coverage.DescriptorFiles++
		}
	}
	coverage.UnhandledFiles = coverage.InputFiles - coverage.DescriptorFiles - coverage.ParsedFiles - coverage.PartialFiles - coverage.UnparsedFiles
	coverage.Truncated = code.Coverage.SymbolsSkipped > 0 || surface.Coverage.NodesSkipped+surface.Coverage.EdgesSkipped+surface.Coverage.EntryPointsTruncated > 0
	limitations := append(append([]string{}, code.Limitations...), surface.Limitations...)
	limitations = append(limitations, "Rule observations and call reachability do not establish taint flow, control effectiveness or exploitability")
	return json.Marshal(plugin.NativeReport{Format: "codexploit/semantic-native/v1", Scope: inv.Request.Scope, Graph: code, Surface: surface, Coverage: coverage, Limitations: limitations})
}
