package plugin_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/builtinanalysis"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestBuiltinPathsProduceCandidatesWithoutClaimingDataflow(t *testing.T) {
	old, request, objects, index := hostFixture(t, map[string]string{"go.mod": "module example.invalid/app\n", "main.go": `package main
import ("net/http"; "os/exec")
func sink(s string) { exec.Command(s).Run() }
func Handler(w http.ResponseWriter,r *http.Request){ sink(r.URL.Query().Get("cmd")) }
func main(){http.HandleFunc("/run",Handler)}
`})
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	catalog, err := plugin.NewCatalog(ctx, index)
	if err != nil {
		t.Fatal(err)
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Scopes: index, Artifacts: objects, Executors: builtinanalysis.Executors()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	run := func(request plugin.Request) plugin.Invocation {
		t.Helper()
		inv, err := host.Execute(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		done, err := host.Wait(ctx, request.Scope, inv.ID)
		if err != nil {
			t.Fatal(err)
		}
		if done.Status != "SUCCEEDED" && done.Status != "PARTIAL" {
			t.Fatalf("execution: %+v", done)
		}
		return done
	}
	parsed := run(request)
	var facts artifact.Ref
	for _, ref := range parsed.Outputs {
		if ref.Kind == "code.facts" {
			facts = ref
		}
	}
	semantic, err := catalog.Get(ctx, "builtin.security-semantics", "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	request.ID = "inv-security"
	request.PluginID = semantic.Manifest.ID
	request.PluginVersion = semantic.Manifest.Version
	request.PackageDigest = semantic.PackageDigest
	request.Inputs = append(request.Inputs, facts)
	analyzed := run(request)
	paths, err := catalog.Get(ctx, "builtin.discovery-paths", "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	request.ID = "inv-paths"
	request.PluginID = paths.Manifest.ID
	request.PluginVersion = paths.Manifest.Version
	request.PackageDigest = paths.PackageDigest
	request.Inputs = nil
	for _, ref := range analyzed.Outputs {
		if ref.Kind == "security.facts" {
			request.Inputs = append(request.Inputs, ref)
		}
	}
	for _, ref := range analyzed.Outputs {
		if ref.Kind == "report.document" {
			request.Inputs = append(request.Inputs, ref)
		}
	}
	done := run(request)
	var raw []byte
	for _, ref := range done.Outputs {
		if ref.Kind == "discovery.paths" {
			reader, _, err := objects.Open(ctx, request.Scope, ref.ID, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			raw, err = io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	var document struct {
		Paths []struct {
			ID           string            `json:"id"`
			Kind         string            `json:"path_kind"`
			Completeness string            `json:"completeness"`
			Steps        []json.RawMessage `json:"steps"`
		} `json:"paths"`
		Candidates []struct {
			Status      string   `json:"status"`
			Hint        string   `json:"severity_hint"`
			Evidence    []string `json:"evidence_refs"`
			Limitations []string `json:"limitations"`
		} `json:"candidates"`
	}
	if json.Unmarshal(raw, &document) != nil || len(document.Paths) == 0 || len(document.Candidates) == 0 {
		t.Fatalf("no real candidates: %s", raw)
	}
	observed := false
	for _, p := range document.Paths {
		if p.Kind == "call_reachability" && len(p.Steps) > 0 {
			observed = true
		}
		if p.Kind != "call_reachability" && p.Kind != "hypothesis" {
			t.Fatalf("unsupported evidence class: %s", p.Kind)
		}
		if p.Kind == "hypothesis" && p.Completeness != "partial" {
			t.Fatal("hypothesis presented as complete")
		}
	}
	if !observed {
		t.Fatal("observed Handler to sink call chain was lost")
	}
	for _, candidate := range document.Candidates {
		if candidate.Status != "candidate" || candidate.Hint != "high" || len(candidate.Evidence) == 0 || len(candidate.Limitations) == 0 {
			t.Fatalf("candidate overstated: %s", raw)
		}
	}
	var native artifact.Ref
	for _, ref := range done.Outputs {
		if ref.Kind == "report.document" {
			native = ref
		}
	}
	reader, _, err := objects.Open(ctx, request.Scope, native.ID, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	original, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"path_owner", "missing_ref", "forged_step", "taint_claim"} {
		t.Run(name, func(t *testing.T) {
			var report plugin.NativeReport
			if err := json.Unmarshal(original, &report); err != nil {
				t.Fatal(err)
			}
			p := &report.Paths.Paths[0]
			switch name {
			case "path_owner":
				p.SnapshotID = "other-snapshot"
			case "missing_ref":
				p.SCGRefs = append(p.SCGRefs, "sym-missing")
			case "forged_step":
				p.Steps[0].From = "asgn-forged"
			case "taint_claim":
				p.PathKind = "taint_flow"
			}
			changed, _ := json.Marshal(report)
			ref := native
			ref.SHA256 = fmt.Sprintf("%x", sha256.Sum256(changed))
			ref.Bytes = int64(len(changed))
			if _, err := (plugin.Normalizer{}).Normalize(done, ref, changed); !errors.Is(err, plugin.ErrInvalid) {
				t.Fatalf("forged path accepted: %v", err)
			}
		})
	}
}

func TestNormalizationFailureKeepsOnlyNativeEvidence(t *testing.T) {
	for _, name := range []string{"unknown_format", "malformed"} {
		t.Run(name, func(t *testing.T) {
			old, request, objects, index := hostFixture(t, map[string]string{"main.go": "package main\n"})
			_ = old.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			catalog, err := plugin.NewCatalog(ctx, index)
			if err != nil {
				t.Fatal(err)
			}
			manifest := json.RawMessage(`{"api_version":"codexploit/v1","id":"fixture.normalizer","version":"1.0.0","name":"Normalizer format fixture","description":"Synthetic report fixture","kind":"normalizer","languages":["Go"],"runtime":{"kind":"builtin"},"consumes":["source.snapshot"],"produces":["report.document","security.facts"],"permissions":{"network":"none","source_write":false},"config_schema":{"type":"object","additionalProperties":false}}`)
			raw := []byte(`{"format":"unknown/v99"}`)
			want := "UNSUPPORTED"
			if name == "malformed" {
				raw = []byte("invalid-report")
				want = "FAILED"
			}
			adapter := plugin.Executor{Manifest: manifest, PackageDigest: fmt.Sprintf("%064d", 1), InputSchemas: []string{"codexploit/source-tar/v1"}, Run: func(context.Context, plugin.Invocation, [][]byte) ([]byte, error) { return raw, nil }}
			host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Artifacts: objects, Scopes: index, Executors: []plugin.Executor{adapter}})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			request.PluginID = "fixture.normalizer"
			request.PluginVersion = "1.0.0"
			request.PackageDigest = adapter.PackageDigest
			started, err := host.Execute(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			done, err := host.Wait(ctx, request.Scope, started.ID)
			if err != nil {
				t.Fatal(err)
			}
			if done.Status != want || len(done.Outputs) != 1 || done.Outputs[0].Kind != "report.document" {
				t.Fatalf("failure lost native evidence or exposed claims: %s %s %d", done.Status, done.ErrorCode, len(done.Outputs))
			}
			r, _, err := objects.Open(ctx, request.Scope, done.Outputs[0].ID, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			r.Close()
			if err != nil || string(got) != string(raw) {
				t.Fatal("native evidence changed")
			}
			if _, err := host.Result(ctx, request.Scope, done.ID, 1<<20); !errors.Is(err, plugin.ErrConflict) {
				t.Fatalf("failed result consumable: %v", err)
			}
		})
	}
}

func TestSemanticCoverageAndGraphBudgetRemainExplicit(t *testing.T) {
	old, request, objects, index := hostFixture(t, map[string]string{"go.mod": "module example.invalid/app\n", "main.go": "package main\nfunc main() {}\n", "broken.go": "package main\nfunc Broken( {\n", "app.py": "print('fixture')\n", "notes.txt": "fixture\n"})
	_ = old.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	catalog, err := plugin.NewCatalog(ctx, index)
	if err != nil {
		t.Fatal(err)
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Artifacts: objects, Scopes: index, Executors: builtinanalysis.Executors()})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	parsed, err := host.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = host.Wait(ctx, request.Scope, parsed.ID)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := catalog.Get(ctx, plugin.SemanticID, "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range parsed.Outputs {
		if ref.Kind == "code.facts" {
			request.Inputs = append(request.Inputs, ref)
		}
	}
	request.ID = "inv-partial"
	request.PluginID = semantic.Manifest.ID
	request.PluginVersion = semantic.Manifest.Version
	request.PackageDigest = semantic.PackageDigest
	started, err := host.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(ctx, request.Scope, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "PARTIAL" || done.Coverage.ParsedFiles != 1 || done.Coverage.PartialFiles != 1 || done.Coverage.UnhandledFiles != 2 || done.Coverage.DescriptorFiles != 1 {
		t.Fatalf("coverage misrepresented: %+v", done.Coverage)
	}
	request.ID = "inv-semantic-budget"
	request.Budget.MaxASTNodes = 1
	started, err = host.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	done, err = host.Wait(ctx, request.Scope, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "FAILED" || done.ErrorCode != "budget_exceeded" || len(done.Outputs) != 0 {
		t.Fatalf("budget: %s %s %d", done.Status, done.ErrorCode, len(done.Outputs))
	}
	request.ID = "inv-forged-capability"
	request.Budget = plugin.Budget{}
	request.Config = json.RawMessage(`{"taint_flow":true}`)
	if _, err := host.Execute(ctx, request); !errors.Is(err, plugin.ErrInvalid) {
		t.Fatalf("unsupported taint capability accepted: %v", err)
	}
}

func TestPathPluginExaminesNativeSurfaceBeyondOneGraphPage(t *testing.T) {
	var code strings.Builder
	code.WriteString("package main\nimport(\"net/http\";\"os/exec\")\nfunc sink(s string){exec.Command(s).Run()}\nfunc Handler(w http.ResponseWriter,r *http.Request){sink(r.URL.Query().Get(\"cmd\"))}\nfunc main(){\n")
	for i := range 1100 {
		fmt.Fprintf(&code, "http.HandleFunc(\"/r%d\", Handler)\n", i)
	}
	code.WriteString("}\n")
	old, request, objects, index := hostFixture(t, map[string]string{"main.go": code.String(), "go.mod": "module example.invalid/app\n"})
	_ = old.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	catalog, err := plugin.NewCatalog(ctx, index)
	if err != nil {
		t.Fatal(err)
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Artifacts: objects, Scopes: index, Executors: builtinanalysis.Executors()})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	run := func(req plugin.Request) plugin.Invocation {
		t.Helper()
		started, err := host.Execute(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		done, err := host.Wait(ctx, req.Scope, started.ID)
		if err != nil {
			t.Fatal(err)
		}
		if done.Status != "SUCCEEDED" && done.Status != "PARTIAL" {
			t.Fatalf("execution: %s %s", done.Status, done.ErrorCode)
		}
		return done
	}
	parsed := run(request)
	for _, ref := range parsed.Outputs {
		if ref.Kind == "code.facts" {
			request.Inputs = append(request.Inputs, ref)
		}
	}
	semantic, err := catalog.Get(ctx, plugin.SemanticID, "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	request.ID = "inv-many-semantics"
	request.PluginID = semantic.Manifest.ID
	request.PluginVersion = semantic.Manifest.Version
	request.PackageDigest = semantic.PackageDigest
	request.Budget.MaxOutputBytes = 64 << 20
	analyzed := run(request)
	adapter, err := catalog.Get(ctx, "builtin.discovery-paths", "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	request.Inputs = nil
	for _, ref := range analyzed.Outputs {
		if ref.Kind == "security.facts" {
			request.Inputs = append(request.Inputs, ref)
		}
	}
	for _, ref := range analyzed.Outputs {
		if ref.Kind == "report.document" {
			request.Inputs = append(request.Inputs, ref)
		}
	}
	request.ID = "inv-many-paths"
	request.PluginID = adapter.Manifest.ID
	request.PluginVersion = adapter.Manifest.Version
	request.PackageDigest = adapter.PackageDigest
	request.Config = json.RawMessage(`{"max_paths":1}`)
	done := run(request)
	var report plugin.NativeReport
	for _, ref := range done.Outputs {
		if ref.Kind == "report.document" {
			reader, _, err := objects.Open(ctx, request.Scope, ref.ID, 64<<20)
			if err != nil {
				t.Fatal(err)
			}
			err = json.NewDecoder(reader).Decode(&report)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if report.Paths == nil || report.Paths.Coverage.EntryPointsExamined+report.Paths.Coverage.EntryPointsSkipped != 1100 {
		t.Fatalf("native surface silently lost entries: %+v", report.Paths.Coverage)
	}
	if done.Status != "PARTIAL" || !done.Coverage.Truncated {
		t.Fatal("bounded path output presented as full coverage")
	}
	request.ID = "inv-default-path-budget"
	request.Config = json.RawMessage(`{}`)
	defaults := run(request)
	result, err := host.Result(ctx, request.Scope, defaults.ID, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) > 200 {
		t.Fatalf("documented default path budget ignored: %d", len(result.Paths))
	}
}
