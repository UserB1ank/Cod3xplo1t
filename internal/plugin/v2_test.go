package plugin_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
	"github.com/open-mcp-ai/Codexploit/internal/workflowexec"
)

func TestVersionedStageDefinitionRegistersWithoutInstallingCode(t *testing.T) {
	catalog, err := plugin.NewCatalog(t.Context(), storage.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	record, err := catalog.Register(t.Context(), raw, strings.Repeat("a", 64), "contract fixture")
	if err != nil {
		t.Fatalf("register a stage definition: %v", err)
	}
	if record.ProtocolVersion != plugin.ProcessProtocolV2 || strings.Contains(record.Reason, "not supported") {
		t.Fatalf("supported protocol must remain separate from installation: %+v", record)
	}
	if record.Installed || record.Executable {
		t.Fatal("registration must not install or execute code")
	}
	stored, err := catalog.Get(t.Context(), "example.parse", "0.1.0")
	if err != nil || stored.ManifestDigest != record.ManifestDigest {
		t.Fatalf("fixed definition read: %+v %v", stored, err)
	}
	var changed map[string]any
	if err := json.Unmarshal(raw, &changed); err != nil {
		t.Fatal(err)
	}
	changed["description"] = "changed contract"
	replacement, _ := json.Marshal(changed)
	if _, err := catalog.Register(t.Context(), replacement, strings.Repeat("a", 64), "contract fixture"); !errors.Is(err, plugin.ErrConflict) {
		t.Fatalf("same version replacement: %v", err)
	}
}

func TestWorkerIdentitySurvivesRestartAndSeparatesWorkspaces(t *testing.T) {
	first := t.TempDir()
	id, err := plugin.OpenWorkerID(first)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := plugin.OpenWorkerID(first)
	if err != nil || id != restored {
		t.Fatalf("worker restart identity: %v", err)
	}
	other, err := plugin.OpenWorkerID(t.TempDir())
	if err != nil || other == id {
		t.Fatalf("independent worker identity: %v", err)
	}
}

func TestStageHostRejectsMalformedStandardOutputBeforePublishing(t *testing.T) {
	old, request, objects, index := hostFixture(t, map[string]string{"main.go": "package main\nfunc main() {}\n"})
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), plugin.ProcessProtocolV2, plugin.FileJobProtocol, 1))
	catalog, err := plugin.NewCatalog(t.Context(), index)
	if err != nil {
		t.Fatal(err)
	}
	malformed := []byte(`{"files":[],"symbols":"not-an-array"}`)
	executor := plugin.Executor{Manifest: raw, PackageDigest: strings.Repeat("c", 64), OperationID: "execute", RunOutputs: func(_ context.Context, _ plugin.Invocation, _ [][]byte) (plugin.RawResult, error) {
		one := int64(1)
		return plugin.RawResult{Status: "SUCCEEDED", Coverage: plugin.StageCoverage{Unit: "files", Seen: &one, Analyzed: &one}, Outputs: []plugin.RawOutput{{Port: "code", Kind: "code.facts", SchemaID: "codexploit/code-facts/v2", Bytes: int64(len(malformed)), SHA256: fmt.Sprintf("%x", sha256.Sum256(malformed)), MediaType: "application/json", Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(malformed))), nil }}}}, nil
	}}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Scopes: index, Artifacts: objects, Executors: []plugin.Executor{executor}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	request.PluginID = "example.parse"
	request.PluginVersion = "0.1.0"
	request.PackageDigest = executor.PackageDigest
	request.ID = "invalid-code-facts"
	inv, err := host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "FAILED" || len(done.Outputs) != 0 {
		t.Fatalf("malformed output was published: %+v", done)
	}
	malformed = []byte(`{"files":[{"file_id":"file-main","path":"main.go","language":"Go","parse_status":"parsed","reason":null}],"symbols":[{"id":"symbol-main","file_id":"file-main","kind":"function","name":"main","qualified_name":"main.main","signature":"func main()","location":null}],"calls":[],"native_id_mappings":[]}`)
	request.ID = "valid-code-facts"
	inv, err = host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err = host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil || done.Status != "SUCCEEDED" {
		t.Fatalf("valid standard output: %+v %v", done, err)
	}
	documents, err := host.StandardResults(t.Context(), request.Scope, inv.ID, 1<<20)
	if err != nil || len(documents) != 1 {
		t.Fatalf("standard results: %+v %v", documents, err)
	}
	if documents[0].Producer.PackageDigest != request.PackageDigest || documents[0].Producer.OperationID != "execute" {
		t.Fatal("host provenance missing")
	}
	if d := documents[0].Producer.NormalizerDigest; len(d) != 64 || d == fmt.Sprintf("%x", sha256.Sum256([]byte("codexploit/stage-normalizer/v2"))) {
		t.Fatal("normalizer provenance must fingerprint its implementation, not just the version label")
	}
	batch, err := publication.BatchFromStage("valid-code-facts", documents[0], "rev-0")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := publication.NewPublisher(index).Publish(t.Context(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if revision.ID != "rev-1" {
		t.Fatalf("standard code publication: %+v", revision)
	}
}

func TestStageHostStandardOutputUsesConfiguredBudgetBeyondLegacyCap(t *testing.T) {
	old, request, objects, index := hostFixture(t, map[string]string{"main.go": "package main\nfunc main() {}\n"})
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), plugin.ProcessProtocolV2, plugin.FileJobProtocol, 1))
	catalog, err := plugin.NewCatalog(t.Context(), index)
	if err != nil {
		t.Fatal(err)
	}
	var opened atomic.Bool
	short := []byte("invalid but deliberately opened")
	executor := plugin.Executor{Manifest: raw, PackageDigest: strings.Repeat("e", 64), OperationID: "execute", RunOutputs: func(_ context.Context, _ plugin.Invocation, _ [][]byte) (plugin.RawResult, error) {
		one := int64(1)
		return plugin.RawResult{Status: "SUCCEEDED", Coverage: plugin.StageCoverage{Unit: "files", Seen: &one, Analyzed: &one}, Outputs: []plugin.RawOutput{{Port: "code", Kind: "code.facts", SchemaID: "codexploit/code-facts/v2", Bytes: 64<<20 + 1, SHA256: fmt.Sprintf("%x", sha256.Sum256(short)), MediaType: "application/json", Open: func() (io.ReadCloser, error) {
			opened.Store(true)
			return io.NopCloser(bytes.NewReader(short)), nil
		}}}}, nil
	}}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Scopes: index, Artifacts: objects, Executors: []plugin.Executor{executor}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	request.PluginID = "example.parse"
	request.PluginVersion = "0.1.0"
	request.PackageDigest = executor.PackageDigest
	request.ID = "standard-output-over-legacy-cap"
	request.Budget = plugin.Budget{MaxInputBytes: 500 << 20, MaxOutputBytes: 500 << 20, MaxFiles: 16, TimeoutSeconds: 30}
	inv, err := host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.Load() {
		t.Fatal("host rejected a standard output above the legacy 64 MiB cap before applying the configured budget")
	}
	if done.Status != "FAILED" || done.ErrorCode == "budget_exceeded" || len(done.Outputs) != 0 {
		t.Fatalf("the fixture must fail its content contract after opening, not its size budget: %+v", done)
	}
}

func TestStageHostDisambiguatesCanonicalFactCollisions(t *testing.T) {
	old, request, objects, index := hostFixture(t, map[string]string{"main.go": "package main\nfunc main() {}\n"})
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest = []byte(strings.Replace(string(manifest), plugin.ProcessProtocolV2, plugin.FileJobProtocol, 1))
	catalog, err := plugin.NewCatalog(t.Context(), index)
	if err != nil {
		t.Fatal(err)
	}
	code := []byte(`{
		"files":[{"file_id":"file-main","path":"main.go","language":"Go","parse_status":"parsed","reason":null}],
		"symbols":[
			{"id":"symbol-one","file_id":"file-main","kind":"function","name":"apply","qualified_name":"main.apply","signature":"func()","location":{"file":"main.go","start_line":10,"start_column":1,"end_line":null,"end_column":null}},
			{"id":"symbol-two","file_id":"file-main","kind":"function","name":"apply","qualified_name":"main.apply","signature":"func()","location":{"file":"main.go","start_line":10,"start_column":1,"end_line":null,"end_column":null}}
		],
		"calls":[
			{"id":"call-one","caller_ref":"symbol-one","callee_ref":null,"callee_text":"run","location":{"file":"main.go","start_line":12,"start_column":1,"end_line":null,"end_column":null},"resolution":"unresolved","evidence_refs":[]},
			{"id":"call-two","caller_ref":"symbol-two","callee_ref":null,"callee_text":"run","location":{"file":"main.go","start_line":12,"start_column":1,"end_line":null,"end_column":null},"resolution":"unresolved","evidence_refs":[]}
		],
		"native_id_mappings":[]
	}`)
	executor := plugin.Executor{Manifest: manifest, PackageDigest: strings.Repeat("f", 64), OperationID: "execute", RunOutputs: func(_ context.Context, _ plugin.Invocation, _ [][]byte) (plugin.RawResult, error) {
		one := int64(1)
		return plugin.RawResult{Status: "SUCCEEDED", Coverage: plugin.StageCoverage{Unit: "files", Seen: &one, Analyzed: &one}, Outputs: []plugin.RawOutput{
			{Port: "code", Kind: "code.facts", SchemaID: "codexploit/code-facts/v2", Bytes: int64(len(code)), SHA256: fmt.Sprintf("%x", sha256.Sum256(code)), MediaType: "application/json", Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(code)), nil }},
		}}, nil
	}}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Scopes: index, Artifacts: objects, Executors: []plugin.Executor{executor}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	request.PluginID = "example.parse"
	request.PluginVersion = "0.1.0"
	request.PackageDigest = executor.PackageDigest
	request.ID = "colliding-native-facts"
	request.Budget = plugin.Budget{MaxInputBytes: 500 << 20, MaxOutputBytes: 16 << 20, MaxFiles: 16, TimeoutSeconds: 30}
	inv, err := host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil || done.Status != "SUCCEEDED" {
		t.Fatalf("colliding canonical facts were rejected: %+v %v", done, err)
	}
	documents, err := host.StandardResults(t.Context(), request.Scope, request.ID, 1<<20)
	if err != nil || len(documents) != 1 {
		t.Fatalf("standard results: %+v %v", documents, err)
	}
	var payload struct {
		Symbols []struct {
			ID string `json:"id"`
		} `json:"symbols"`
		Calls []struct {
			ID     string  `json:"id"`
			Caller *string `json:"caller_ref"`
		} `json:"calls"`
	}
	if err := json.Unmarshal(documents[0].Data, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Symbols) != 2 || payload.Symbols[0].ID == payload.Symbols[1].ID {
		t.Fatalf("symbols did not receive distinct canonical identities: %+v", payload.Symbols)
	}
	if len(payload.Calls) != 2 || payload.Calls[0].ID == payload.Calls[1].ID {
		t.Fatalf("calls did not receive distinct canonical identities: %+v", payload.Calls)
	}
	callers := map[string]string{}
	for _, call := range payload.Calls {
		if call.Caller != nil {
			callers[call.ID] = *call.Caller
		}
	}
	if callers[payload.Calls[0].ID] == callers[payload.Calls[1].ID] {
		t.Fatalf("colliding calls lost their caller associations: %+v", payload.Calls)
	}
}

func TestFileJobDriverPublishesIndependentBinaryOutputs(t *testing.T) {
	for _, protocol := range []string{"codexploit/file-job/v1", "codexploit/file-job/v2"} {
		t.Run(protocol, func(t *testing.T) { fileJobDriverPublishesIndependentBinaryOutputs(t, protocol) })
	}
}
func fileJobDriverPublishesIndependentBinaryOutputs(t *testing.T, protocol string) {
	old, request, objects, index := hostFixture(t, map[string]string{"main.go": "package main\nfunc main() {}\n"})
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	directory := filepath.Join(root, "example.capture@1.0.0")
	if err := os.MkdirAll(filepath.Join(directory, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	const source = `package main
import("encoding/json";"os";"path/filepath";"crypto/sha256";"fmt")
func main(){
 var req struct{Version string ` + "`json:\"api_version\"`" + `;Inputs []struct{ArtifactID string ` + "`json:\"artifact_id\"`" + `} ` + "`json:\"inputs\"`" + `;Invocation string ` + "`json:\"invocation_id\"`" + `; Output string ` + "`json:\"output_directory\"`" + `}
 raw,e:=os.ReadFile(os.Args[2]);if e!=nil{os.Exit(2)};if json.Unmarshal(raw,&req)!=nil{os.Exit(3)}
 if req.Invocation=="bounded-failure" {raw,_=json.Marshal(map[string]any{"api_version":req.Version,"invocation_id":req.Invocation,"status":"FAILED","error_code":"selection_budget_exceeded","outputs":[]any{},"coverage":map[string]any{"unit":"files","seen":7,"analyzed":2,"skipped":5,"failed":0,"truncated":false,"reasons":[]string{}},"limitations":[]string{"joern:frontend=JAVASRC;step=parse;reason=selection_budget_exceeded"}});if os.WriteFile(os.Args[4],raw,0600)!=nil{os.Exit(6)};return}
 if req.Version=="codexploit/file-job/v2" && (len(req.Inputs)!=1 || req.Inputs[0].ArtifactID==""){os.Exit(7)}
 data:=[]byte("independent binary result")
 if e=os.WriteFile(filepath.Join(filepath.Dir(os.Args[2]),req.Output,"native.bin"),data,0600);e!=nil{os.Exit(4)}
 result:=map[string]any{"api_version":req.Version,"invocation_id":req.Invocation,"status":"SUCCEEDED","outputs":[]any{map[string]any{"port":"native","kind":"tool.native","schema_id":"codexploit/native-bytes/v1","path":"native.bin","media_type":"application/octet-stream","bytes":len(data),"sha256":fmt.Sprintf("%x",sha256.Sum256(data))}},"coverage":map[string]any{"unit":"files","seen":1,"analyzed":1,"skipped":0,"failed":0,"truncated":false,"reasons":[]string{}},"limitations":[]string{"native bytes only; no code facts"}}
 raw,e=json.Marshal(result);if e!=nil{os.Exit(5)};if os.WriteFile(os.Args[4],raw,0600)!=nil{os.Exit(6)}
}`
	code := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(code, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	entry := "adapter"
	if runtime.GOOS == "windows" {
		entry += ".exe"
	}
	cmd := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(directory, "bin", entry), code)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build independent binary: %v %s", err, output)
	}
	manifest := []byte(`{"api_version":"codexploit/plugin/v2","id":"example.capture","version":"1.0.0","name":"Native capture","description":"Independent binary contract fixture","languages":["Go"],"runtime":{"kind":"process","protocol":"codexploit/file-job/v1","entrypoint":"bin/adapter"},"permissions":{"network":"none","source_write":false,"target_execution":false},"operations":[{"id":"capture","stage":"parse","capability":"parse","profile":"native","inputs":[{"name":"source","kind":"source.snapshot","schema_id":"codexploit/source-tar/v1","required":true,"cardinality":"one"}],"outputs":[{"name":"native","kind":"tool.native","schema_id":"codexploit/native-bytes/v1","required":true,"cardinality":"one"}],"config_schema":{"type":"object","additionalProperties":false}}]}`)
	manifest = []byte(strings.Replace(string(manifest), "codexploit/file-job/v1", protocol, 1))
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := plugin.BuildFilesLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "files.lock.json"), lock, 0600); err != nil {
		t.Fatal(err)
	}
	executors, err := processplugin.Executors(root)
	if err != nil {
		t.Fatalf("load generic binary: %v", err)
	}
	catalog, err := plugin.NewCatalog(t.Context(), index)
	if err != nil {
		t.Fatal(err)
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Scopes: index, Artifacts: objects, Executors: executors})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	pkg, err := plugin.LoadPackage(directory)
	if err != nil {
		t.Fatal(err)
	}
	request.PluginID = "example.capture"
	request.PluginVersion = "1.0.0"
	request.PackageDigest = pkg.PackageDigest
	request.ID = "native-file-job"
	inv, err := host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "SUCCEEDED" || len(done.Outputs) != 1 || done.Outputs[0].Kind != "tool.native" {
		t.Fatalf("native job: %+v", done)
	}
	request.ID = "bounded-failure"
	failed, err := host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	failed, err = host.Wait(t.Context(), request.Scope, failed.ID)
	if err != nil || failed.Status != "FAILED" || failed.ErrorCode != "selection_budget_exceeded" || len(failed.Outputs) != 0 {
		t.Fatalf("file-job failure classification must survive without output publication: %+v %v", failed, err)
	}
	if failed.StageCoverage == nil || failed.StageCoverage.Seen == nil || *failed.StageCoverage.Seen != 7 || failed.Coverage.ParsedFiles != 2 || len(failed.Limitations) < 1 {
		t.Fatalf("file-job failure lost measured coverage or diagnostics: %+v", failed)
	}
	request.ID = "native-file-job"
	workflows := &workflow.Catalog{Repository: index}
	spec := json.RawMessage(`{"api_version":"codexploit/v1","id":"native-capture","version":"1.0.0","name":"Native capture workflow","description":"A real independent binary without fabricated code facts","inputs":["source.snapshot"],"nodes":[{"id":"capture","plugin_id":"example.capture","plugin_version":"1.0.0","operation_id":"capture","needs":[],"config":{},"timeout_seconds":30}]}`)
	if _, err = workflows.Save(t.Context(), request.Scope.ProjectID, spec, ""); err != nil {
		t.Fatal(err)
	}
	compiler := &workflow.Compiler{Plugins: catalog, Workflows: workflows, Plans: index, Artifacts: objects, Scopes: index, Knowledge: index}
	plan, err := compiler.Compile(t.Context(), request.Scope.ProjectID, "native-capture", "1.0.0", workflow.CompileRequest{APIVersion: "codexploit/v1", SnapshotID: request.Scope.SnapshotID, Inputs: []string{request.Inputs[0].ID}, Language: "Go"})
	if err != nil {
		t.Fatal(err)
	}
	runner := workflow.NewRunner(compiler, index, workflow.PluginExecutor{Host: host, Catalog: catalog}, objects)
	runner.Effects = &workflowexec.Effects{Store: index, Host: host, Artifacts: objects}
	t.Cleanup(func() { _ = runner.Close() })
	run, err := runner.Start(t.Context(), workflow.StartRequest{ProjectID: request.Scope.ProjectID, SnapshotID: request.Scope.SnapshotID, PlanID: plan.ID, Task: workflow.TaskDefinition{Name: "Native capture", Objective: "Keep native evidence without fabricating graph facts"}})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !workflow.RunTerminal(run.Status) {
		if time.Now().After(deadline) {
			t.Fatal("native workflow did not terminate")
		}
		time.Sleep(10 * time.Millisecond)
		run, err = runner.Get(t.Context(), request.Scope.ProjectID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if run.Status != "SUCCEEDED" || run.Nodes[0].Status != "SUCCEEDED" || run.Nodes[1].Status != "SKIPPED" {
		detail, _ := host.GetStatus(t.Context(), request.Scope, run.Nodes[0].InvocationID)
		t.Fatalf("native workflow: node=%+v plan=%+v invocation=%+v", run.Nodes[0], plan.Nodes[0], detail)
	}
	if err = runner.Close(); err != nil {
		t.Fatal(err)
	}
	installations, err := index.ListPluginInstallations(t.Context())
	selected := []plugin.Installation{}
	for _, row := range installations {
		if row.Release.PluginID == request.PluginID {
			selected = append(selected, row)
		}
	}
	if err != nil || len(selected) != 1 {
		t.Fatalf("installation: %+v %v", installations, err)
	}
	policy := selected[0]
	expected := policy.Version
	policy.Version++
	policy.Enabled = false
	if _, err = index.SavePluginInstallation(t.Context(), policy, expected); err != nil {
		t.Fatal(err)
	}
	request.ID = "disabled-native-file-job"
	if _, err = host.Execute(t.Context(), request); !errors.Is(err, plugin.ErrUnsupported) {
		t.Fatalf("disabled installation executed: %v", err)
	}
	if err = host.Close(); err != nil {
		t.Fatal(err)
	}
	reloadedCatalog, err := plugin.NewCatalog(t.Context(), index)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := plugin.NewHost(plugin.Deps{Catalog: reloadedCatalog, Repository: index, Scopes: index, Artifacts: objects, Executors: executors})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reloaded.Close() })
	if _, err = reloaded.Execute(t.Context(), request); !errors.Is(err, plugin.ErrUnsupported) {
		t.Fatalf("restart re-enabled disabled package: %v", err)
	}
}

func TestStageBinaryPackageVerifiesEveryDeclaredFile(t *testing.T) {
	directory := t.TempDir()
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(directory, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	entry := "bin/adapter"
	if runtime.GOOS == "windows" {
		entry += ".exe"
	}
	tool := []byte("fixture binary package bytes")
	if err = os.WriteFile(filepath.Join(directory, filepath.FromSlash(entry)), tool, 0700); err != nil {
		t.Fatal(err)
	}
	lock, _ := json.Marshal(map[string]any{"api_version": "codexploit/plugin-files/v2", "files": []any{map[string]any{"path": entry, "bytes": len(tool), "sha256": fmt.Sprintf("%x", sha256.Sum256(tool)), "executable": true}}})
	if err = os.WriteFile(filepath.Join(directory, "files.lock.json"), lock, 0600); err != nil {
		t.Fatal(err)
	}
	pkg, err := plugin.LoadPackage(directory)
	if err != nil {
		t.Fatalf("load stage binary: %v", err)
	}
	if pkg.Manifest.APIVersion != plugin.DefinitionVersion || len(pkg.PackageDigest) != 64 {
		t.Fatal("stage release identity missing")
	}
	if err = os.WriteFile(filepath.Join(directory, "undeclared.rules"), []byte("modified rules"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = plugin.LoadPackage(directory); err == nil {
		t.Fatal("undeclared file accepted")
	}
	if err = os.Remove(filepath.Join(directory, "undeclared.rules")); err != nil {
		t.Fatal(err)
	}
	tool[0] = 'F'
	if err = os.WriteFile(filepath.Join(directory, filepath.FromSlash(entry)), tool, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = plugin.LoadPackage(directory); err == nil {
		t.Fatal("same-size binary replacement accepted")
	}
}

func TestStageDefinitionsRejectIncompatiblePortsAndDomainBypass(t *testing.T) {
	catalog, err := plugin.NewCatalog(t.Context(), storage.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"stage", "capability", "schema_id", "duplicate_port", "duplicate_key"} {
		t.Run(field, func(t *testing.T) {
			var value map[string]any
			_ = json.Unmarshal(raw, &value)
			op := value["operations"].([]any)[0].(map[string]any)
			switch field {
			case "stage":
				op["stage"] = "unknown"
			case "capability":
				op["capability"] = "verification"
			case "schema_id":
				op["outputs"].([]any)[0].(map[string]any)["schema_id"] = "unknown/facts/v1"
			case "duplicate_port":
				op["inputs"] = append(op["inputs"].([]any), op["inputs"].([]any)[0])
			}
			encoded, _ := json.Marshal(value)
			if field == "duplicate_key" {
				encoded = []byte(strings.Replace(string(encoded), `"version":"0.1.0"`, `"version":"9.0.0","version":"0.1.0"`, 1))
			}
			if _, err := catalog.Register(t.Context(), encoded, strings.Repeat("b", 64), "contract fixture"); !errors.Is(err, plugin.ErrInvalid) {
				t.Fatalf("invalid definition accepted: %v", err)
			}
		})
	}
}

func TestStageHostRecordsMissingRuntimeDependencyAsFailedProbe(t *testing.T) {
	old, request, objects, index := hostFixture(t, map[string]string{"main.go": "package main\n"})
	_ = old.Close()
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := plugin.NewCatalog(t.Context(), index)
	if err != nil {
		t.Fatal(err)
	}
	executor := plugin.Executor{Manifest: raw, PackageDigest: strings.Repeat("d", 64), OperationID: "execute", RunOutputs: func(context.Context, plugin.Invocation, [][]byte) (plugin.RawResult, error) {
		return plugin.RawResult{}, &plugin.ExecutionError{Code: "dependency_unavailable"}
	}}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Scopes: index, Artifacts: objects, Executors: []plugin.Executor{executor}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	request.PluginID = "example.parse"
	request.PluginVersion = "0.1.0"
	request.PackageDigest = executor.PackageDigest
	request.ID = "missing-runtime"
	inv, err := host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil || done.Status != "FAILED" || len(done.Outputs) != 0 {
		t.Fatalf("dependency failure: %+v %v", done, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		record, err := catalog.Get(t.Context(), request.PluginID, request.PluginVersion)
		if err != nil {
			t.Fatal(err)
		}
		if record.Installation != nil && record.Installation.Probe == "failed" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("a real dependency failure was not recorded as a failed functional probe")
}

func TestStageHostBindsNativeMappingsToPublishedArtifact(t *testing.T) {
	old, request, objects, index := hostFixture(t, map[string]string{"main.go": "package main\nfunc main() {}\n"})
	_ = old.Close()
	manifest, err := os.ReadFile("../../plugins/joern/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var currentManifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &currentManifest); err != nil || currentManifest.Version == "" {
		t.Fatalf("manifest version: %v", err)
	}
	// This regression covers an already published archive-based release.
	manifest = bytes.ReplaceAll(manifest, []byte(currentManifest.Version), []byte("2.1.1"))
	manifest = bytes.ReplaceAll(manifest, []byte("codexploit/source-directory/v1"), []byte("codexploit/source-tar/v1"))
	catalog, err := plugin.NewCatalog(t.Context(), index)
	if err != nil {
		t.Fatal(err)
	}
	nativeRef := "output:cpg"
	nativeCount := 1
	executor := plugin.Executor{Manifest: manifest, PackageDigest: strings.Repeat("b", 64), OperationID: "parse", RunOutputs: func(context.Context, plugin.Invocation, [][]byte) (plugin.RawResult, error) {
		code := fmt.Sprintf(`{"files":[{"file_id":"f","path":"main.go","language":"Go","parse_status":"partial","reason":"frontend"}],"symbols":[],"calls":[],"native_id_mappings":[{"native_artifact_ref":%q,"native_id":"123","canonical_ref":"f","mapping_rule":"test","mapping_status":"mapped"}]}`, nativeRef)
		outputs := []plugin.RawOutput{}
		for _, o := range []struct{ port, kind, schema, data string }{{"cpg", "tool.native", "joern/cpg/v1", "native CPG bytes"}, {"code", "code.facts", "codexploit/code-facts/v2", code}} {
			data := o.data
			outputs = append(outputs, plugin.RawOutput{Port: o.port, Kind: o.kind, SchemaID: o.schema, Bytes: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(data))), MediaType: "application/json", Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(data)), nil }})
		}
		if nativeCount == 2 {
			outputs = append([]plugin.RawOutput{outputs[0]}, outputs...)
		}
		return plugin.RawResult{Status: "PARTIAL", Coverage: plugin.StageCoverage{Unit: "files", Reasons: []string{"frontend"}}, Outputs: outputs}, nil
	}}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Scopes: index, Artifacts: objects, Executors: []plugin.Executor{executor}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	request.PluginID = "codexploit.joern"
	request.PluginVersion = "2.1.1"
	request.OperationID = "parse"
	request.PackageDigest = executor.PackageDigest
	request.ID = "native-mapping"
	inv, err := host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil || done.Status != "PARTIAL" {
		t.Fatalf("run: %+v %v", done, err)
	}
	docs, err := host.StandardResults(t.Context(), request.Scope, inv.ID, 1<<20)
	if err != nil || len(docs) != 1 {
		t.Fatalf("standard: %v", err)
	}
	var data struct {
		Mappings []struct {
			Artifact string `json:"native_artifact_ref"`
		} `json:"native_id_mappings"`
	}
	if err := json.Unmarshal(docs[0].Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Mappings) != 1 || data.Mappings[0].Artifact != done.Outputs[0].ID {
		t.Fatalf("native reference not bound to output: %+v", data)
	}
	nativeRef = "output:cpg:0"
	request.ID = "indexed-native-mapping"
	inv, err = host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err = host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil || done.Status != "PARTIAL" {
		t.Fatalf("indexed native mapping: %+v %v", done, err)
	}

	nativeCount = 2
	nativeRef = "output:cpg:1"
	request.ID = "multiple-native-mapping"
	inv, err = host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err = host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil || done.Status != "PARTIAL" {
		t.Fatalf("multiple native mapping: %+v %v", done, err)
	}
	docs, err = host.StandardResults(t.Context(), request.Scope, inv.ID, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(docs[0].Data, &data) != nil || data.Mappings[0].Artifact != done.Outputs[1].ID {
		t.Fatal("indexed mapping not bound to second CPG")
	}
	nativeRef = "output:cpg"
	request.ID = "ambiguous-native-mapping"
	inv, err = host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err = host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil || done.Status != "FAILED" || len(done.Outputs) != 0 {
		t.Fatal("ambiguous native mapping accepted")
	}

	nativeRef = "unbound-native-artifact"
	request.ID = "forged-native-mapping"
	inv, err = host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err = host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil || done.Status != "FAILED" || len(done.Outputs) != 0 {
		t.Fatalf("foreign native mapping accepted: %+v %v", done, err)
	}
}
