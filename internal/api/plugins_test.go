package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestPluginInvocationAndOutputsRemainReadableAfterRestart(t *testing.T) {
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	rt, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	project := createProject(t, env.ts, env.source).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	prefix := "/api/v1/projects/" + project.ID + "/snapshots/" + snapshot.Snapshot.SnapshotID
	registered := do(t, env.ts, http.MethodPost, prefix+"/artifacts", nil, nil)
	var directory struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	registered.decode(t, &directory)
	var input artifact.Ref
	for _, ref := range directory.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	request := plugin.Request{APIVersion: "codexploit/v1", ID: "inv-api-parser", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: input.Scope, Inputs: []artifact.Ref{input}, Config: json.RawMessage(`{}`)}
	started := do(t, env.ts, http.MethodPost, prefix+"/plugin-invocations", request, nil)
	if started.status != 202 {
		t.Fatalf("start: %d %s", started.status, started.body)
	}
	endpoint := prefix + "/plugin-invocations/" + request.ID
	var result struct {
		Invocation plugin.Invocation `json:"invocation"`
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		r := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint, nil, nil)
		if r.status != 200 {
			t.Fatalf("status: %d %s", r.status, r.body)
		}
		r.decode(t, &result)
		if plugin.Terminal(result.Invocation.Status) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parse did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if result.Invocation.Coverage.ParsedFiles != 2 || len(result.Invocation.Outputs) != 2 {
		t.Fatalf("real parse: %+v", result.Invocation)
	}
	env.ts.Close()
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	rt, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env = serveTestEnv(t, rt, false)
	read := do(t, env.ts, http.MethodGet, endpoint, nil, nil)
	read.decode(t, &result)
	if read.status != 200 || len(result.Invocation.Outputs) != 2 {
		t.Fatalf("restart: %d %s", read.status, read.body)
	}
	for _, ref := range result.Invocation.Outputs {
		r := do(t, env.ts, http.MethodGet, prefix+"/artifacts/"+ref.ID+"/content", nil, nil)
		if r.status != 200 || !strings.Contains(string(r.body), "main.go") {
			t.Fatalf("output: %d %s", r.status, r.body)
		}
	}
	wrong := strings.Replace(endpoint, project.ID, "project-elsewhere", 1)
	if r := do(t, env.ts, http.MethodGet, wrong, nil, nil); r.status != 404 {
		t.Fatalf("project escape: %d %s", r.status, r.body)
	}
}

func TestActivePluginInvocationBlocksSnapshotRetirement(t *testing.T) {
	env := newTestEnv(t, false)
	writeFile(t, env.source, "main.go", "package main\n"+strings.Repeat("var X int\n", 50000))
	project := createProject(t, env.ts, env.source).Project
	r := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snap snapshotResponse
	r.decode(t, &snap)
	prefix := "/api/v1/projects/" + project.ID + "/snapshots/" + snap.Snapshot.SnapshotID
	r = do(t, env.ts, http.MethodPost, prefix+"/artifacts", nil, nil)
	var page struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	r.decode(t, &page)
	var input artifact.Ref
	for _, ref := range page.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	req := plugin.Request{APIVersion: "codexploit/v1", ID: "inv-active", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: input.Scope, Inputs: []artifact.Ref{input}, Config: json.RawMessage(`{}`), Budget: plugin.Budget{MaxASTNodes: 500000, MaxOutputBytes: 64 << 20}}
	r = do(t, env.ts, http.MethodPost, prefix+"/plugin-invocations", req, nil)
	if r.status != 202 {
		t.Fatalf("start: %d %s", r.status, r.body)
	}
	r = do(t, env.ts, http.MethodDelete, "/api/snapshots/"+snap.Snapshot.SnapshotID, nil, nil)
	if r.status != 409 {
		t.Fatalf("active snapshot retired: %d %s", r.status, r.body)
	}
	endpoint := prefix + "/plugin-invocations/" + req.ID
	for range 5 {
		read := do(t, env.ts, http.MethodGet, endpoint, nil, nil)
		if read.status != 200 {
			t.Fatalf("status: %d %s", read.status, read.body)
		}
		r = do(t, env.ts, http.MethodPost, endpoint+"/cancel", map[string]any{}, map[string]string{"If-Match": read.header.Get("ETag")})
		if r.status == 412 {
			continue
		}
		if r.status != 200 {
			t.Fatalf("cancel: %d %s", r.status, r.body)
		}
		return
	}
	t.Fatal("cancel CAS never settled")
}

func TestRegisteredPluginVersionsSurviveRestartWithoutBecomingInstalled(t *testing.T) {
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	rt, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	raw, err := contracts.Files.ReadFile("examples/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"api_version": "codexploit/v1", "manifest": json.RawMessage(raw), "package_digest": strings.Repeat("1", 64), "source": "offline fixture"}
	for range 2 {
		r := do(t, env.ts, http.MethodPost, "/api/v1/plugins", request, nil)
		if r.status != 201 {
			t.Fatalf("register: %d %s", r.status, r.body)
		}
	}
	request["package_digest"] = strings.Repeat("2", 64)
	if r := do(t, env.ts, http.MethodPost, "/api/v1/plugins", request, nil); r.status != 409 {
		t.Fatalf("package replacement: %d %s", r.status, r.body)
	}
	if r := doAs(t, env.ts, readerSecret, http.MethodPost, "/api/v1/plugins", request, nil); r.status != 403 {
		t.Fatalf("reader registration: %d", r.status)
	}
	request["manifest"] = json.RawMessage(strings.Replace(string(raw), "codexploit/v1", "codexploit/v99", 1))
	if r := do(t, env.ts, http.MethodPost, "/api/v1/plugins", request, nil); r.status != 400 {
		t.Fatalf("invalid protocol: %d %s", r.status, r.body)
	}
	env.ts.Close()
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	rt, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env = serveTestEnv(t, rt, false)
	r := do(t, env.ts, http.MethodGet, "/api/v1/plugins", nil, nil)
	var page struct {
		Plugins []struct {
			Manifest      struct{ ID string }
			Executable    bool
			Reason        string
			PackageDigest string `json:"package_digest"`
		} `json:"plugins"`
	}
	r.decode(t, &page)
	if r.status != 200 || len(page.Plugins) != 5 {
		t.Fatalf("persisted catalog: %d %s", r.status, r.body)
	}
	for _, entry := range page.Plugins {
		if entry.Manifest.ID == "team.scanner.example" && (entry.Executable || entry.Reason == "" || entry.PackageDigest != strings.Repeat("1", 64)) {
			t.Fatalf("external manifest executable: %s", r.body)
		}
	}
}

func TestPluginCatalogListsTheInstalledGoParser(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	read := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/plugins", nil, nil)
	var page struct {
		Plugins []struct {
			Manifest      struct{ ID, Version string }
			PackageDigest string `json:"package_digest"`
			Executable    bool
			Reason        string
		} `json:"plugins"`
	}
	read.decode(t, &page)
	var installed bool
	for _, entry := range page.Plugins {
		if entry.Manifest.ID == plugin.BuiltinID && entry.Manifest.Version == plugin.BuiltinVersion && entry.Executable && len(entry.PackageDigest) == 64 {
			installed = true
		}
	}
	if read.status != 200 || len(page.Plugins) != 4 || !installed {
		t.Fatalf("installed catalog: %d %s", read.status, read.body)
	}
}

func TestPluginCapabilitiesListEveryStage(t *testing.T) {
	env := newTestEnv(t, false)
	read := do(t, env.ts, http.MethodGet, "/api/v1/plugins/capabilities", nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("capabilities: %d %s", read.status, read.body)
	}
	var page struct {
		APIVersion   string                 `json:"api_version"`
		Capabilities []pluginCapabilityView `json:"capabilities"`
	}
	read.decode(t, &page)
	if page.APIVersion != "codexploit/v1" || len(page.Capabilities) != 9 {
		t.Fatalf("page = %+v", page)
	}
	byKey := map[string]pluginCapabilityView{}
	for _, capability := range page.Capabilities {
		byKey[capability.Key] = capability
	}
	parse, ok := byKey["parse"]
	if !ok || !parse.Available {
		t.Fatalf("parse capability = %+v", parse)
	}
	found := false
	for _, entry := range parse.Plugins {
		if entry.ID == plugin.BuiltinID && entry.Executable {
			found = true
		}
	}
	if !found {
		t.Fatalf("builtin parser missing from %+v", parse.Plugins)
	}
	environment, ok := byKey["environment"]
	if !ok || environment.Available || environment.Reason == "" {
		t.Fatalf("environment capability = %+v", environment)
	}
	source, ok := byKey["source"]
	if !ok || len(source.Contracts) == 0 || source.Contracts[0].Kind != "source.snapshot" {
		t.Fatalf("source contracts = %+v", source.Contracts)
	}
	if scan := byKey["scan"]; scan.Available {
		for _, entry := range scan.Plugins {
			if entry.ID == "codexploit.static-patterns" {
				return
			}
		}
	}
	// A host without the bundled scanner still lists no scan adapter.
	if scan := byKey["scan"]; scan.Available {
		t.Fatalf("scan capability claimed availability without the scanner: %+v", scan)
	}
}

func TestRegisterPluginRejectsReservedSource(t *testing.T) {
	env := newTestEnv(t, false)
	request := map[string]any{
		"api_version":    "codexploit/v1",
		"manifest":       json.RawMessage(`{"api_version":"codexploit/v1","id":"fixture.source","version":"1.0.0","name":"Source","kind":"analyzer","languages":["Go"],"runtime":{"kind":"builtin"},"consumes":["source.snapshot"],"produces":["code.ast"],"permissions":{"network":"none","source_write":false},"config_schema":{"type":"object"}}`),
		"package_digest": strings.Repeat("a", 64),
		"source":         "compiled evil",
	}
	denied := do(t, env.ts, http.MethodPost, "/api/v1/plugins", request, nil)
	if denied.status != http.StatusBadRequest {
		t.Fatalf("reserved source = %d %s", denied.status, denied.body)
	}
}

func TestPluginCapabilityCatalogDistinguishesAdapterKindsAndProtocols(t *testing.T) {
	env := newTestEnv(t, false)
	read := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/plugins/capabilities", nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("capabilities: %d %s", read.status, read.body)
	}
	var page struct {
		APIVersion   string                  `json:"api_version"`
		Capabilities []pluginCapabilityView  `json:"capabilities"`
		Protocols    []plugin.DomainProtocol `json:"protocols"`
	}
	read.decode(t, &page)
	if len(page.Capabilities) != 9 || len(page.Protocols) < 7 {
		t.Fatalf("capability/protocol catalog = %d/%d", len(page.Capabilities), len(page.Protocols))
	}
	protocols := map[string]plugin.DomainProtocol{}
	for _, protocol := range page.Protocols {
		protocols[protocol.Schema] = protocol
	}
	for _, schema := range []string{"codexploit/agent-task/v1", "codexploit/environment-request/v1", "codexploit/verification-evidence/v1", "codexploit/path-enhancement/v1"} {
		if protocols[schema].Transport == "" {
			t.Fatalf("missing domain protocol %s", schema)
		}
	}
	byKey := map[string]pluginCapabilityView{}
	for _, capability := range page.Capabilities {
		byKey[capability.Key] = capability
	}
	parse := byKey["parse"]
	if !parse.Available || parse.ExecutionModel != "plugin_execute" {
		t.Fatalf("parse = %+v", parse)
	}
	foundPlugin := false
	for _, adapter := range parse.Adapters {
		if adapter.Kind == "plugin_runtime" && adapter.Measured && adapter.ProtocolVersion == "builtin/v1" {
			foundPlugin = true
		}
	}
	if !foundPlugin {
		t.Fatalf("parse plugin adapter = %+v", parse.Adapters)
	}
	source := byKey["source"]
	if !source.Available || source.ExecutionModel != "native_service" || len(source.Adapters) == 0 || source.Adapters[0].Kind != "native_service" || !source.Adapters[0].Measured {
		t.Fatalf("source adapters = %+v", source)
	}
	agent := byKey["agent"]
	if agent.ExecutionModel != "agent_runtime" || len(agent.Adapters) == 0 || agent.Adapters[0].Kind != "agent_runtime" {
		t.Fatalf("agent adapters = %+v", agent.Adapters)
	}
	environment := byKey["environment"]
	if environment.Available || environment.ExecutionModel != "environment_backend" {
		t.Fatalf("environment = %+v", environment)
	}
	for _, adapter := range environment.Adapters {
		if adapter.Kind != "environment_backend" || adapter.Measured {
			t.Fatalf("environment adapter = %+v", adapter)
		}
	}
	verification := byKey["verification"]
	if verification.Available || verification.ExecutionModel != "verification_executor" {
		t.Fatalf("verification = %+v", verification)
	}
}

func TestCapabilityCatalogShowsEnvironmentBackendSeparatelyFromPlugins(t *testing.T) {
	env := newTestEnv(t, false)
	srv := NewServer(env.rt.Store, env.rt.Manager, env.rt.Analyzer,
		WithAuth(testAuthenticator(t)),
		WithPluginCatalog(env.rt.PluginCatalog),
		WithContainerVerification(&ContainerVerification{Provider: &planProvider{}, Owner: "capability-test"}),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	read := doAs(t, ts, readerSecret, http.MethodGet, "/api/v1/plugins/capabilities", nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("capabilities: %d %s", read.status, read.body)
	}
	var page struct {
		Capabilities []pluginCapabilityView `json:"capabilities"`
	}
	read.decode(t, &page)
	for _, capability := range page.Capabilities {
		if capability.Key != "environment" {
			continue
		}
		if !capability.Available || capability.ExecutionModel != "environment_backend" || len(capability.Adapters) != 1 {
			t.Fatalf("environment capability = %+v", capability)
		}
		adapter := capability.Adapters[0]
		if adapter.Kind != "environment_backend" || !adapter.Installed || !adapter.Measured || len(adapter.Capabilities) == 0 {
			t.Fatalf("environment adapter = %+v", adapter)
		}
		if adapter.ProtocolVersion != "environment-provider/v1" {
			t.Fatalf("environment protocol = %+v", adapter)
		}
		return
	}
	t.Fatal("environment capability missing")
}
