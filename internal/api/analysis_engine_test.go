package api

import (
	"encoding/json"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestPatchedDefaultProfilePreservesPreviouslySavedEnginePlan(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	endpoint := "/api/v1/projects/" + project + "/workflows"
	previous := workflow.DefaultAnalysisSpec()
	previous.Version = "2.2.0"
	for i := range previous.Nodes {
		previous.Nodes[i].PluginVersion = "2.3.1"
	}
	saved := do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "spec": previous, "expected_head": ""}, nil)
	if saved.status != http.StatusCreated {
		t.Fatalf("save existing engine definition: %d %s", saved.status, saved.body)
	}
	var old struct {
		Workflow workflow.Record `json:"workflow"`
	}
	saved.decode(t, &old)
	updated := do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "spec": workflow.DefaultAnalysisSpec(), "expected_head": old.Workflow.Digest}, nil)
	if updated.status != http.StatusCreated {
		t.Fatalf("new default must have an independent immutable version: %d %s", updated.status, updated.body)
	}
	read := do(t, env.ts, http.MethodGet, endpoint+"/"+previous.ID+"/versions/2.2.0", nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("read previous definition: %d %s", read.status, read.body)
	}
	var retained struct {
		Workflow workflow.Record `json:"workflow"`
	}
	read.decode(t, &retained)
	if retained.Workflow.Digest != old.Workflow.Digest || retained.Workflow.Spec.Nodes[0].PluginVersion != "2.3.1" {
		t.Fatal("engine adoption rewrote the previous immutable definition")
	}
}

func TestDefaultAnalysisRefusesMissingJoernBeforeCreatingWork(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	endpoint := "/api/v1/projects/" + project
	ready := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint+"/analysis-engine", nil, nil)
	if ready.status != http.StatusOK || !strings.Contains(string(ready.body), `"ready": false`) {
		t.Fatalf("engine readiness: %d %s", ready.status, ready.body)
	}
	result := do(t, env.ts, http.MethodPost, endpoint+"/analysis-runs", map[string]any{"api_version": "codexploit/v1"}, nil)
	if result.status != http.StatusServiceUnavailable || !strings.Contains(string(result.body), "analysis_engine_unavailable") {
		t.Fatalf("missing engine: %d %s", result.status, result.body)
	}
	runs, err := env.rt.Store.ListAnalysisRuns(t.Context(), project, 20)
	if err != nil || len(runs) != 0 {
		t.Fatalf("created work without engine: %+v %v", runs, err)
	}
}

func TestStageReleaseAPIRegistersDigestBoundBuilds(t *testing.T) {
	env := newTestEnv(t, false)
	raw, err := os.ReadFile("../../plugins/joern/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	registered := do(t, env.ts, http.MethodPost, "/api/v2/plugins", map[string]any{"api_version": "codexploit/v2", "manifest": json.RawMessage(raw), "package_digest": strings.Repeat("a", 64), "source": "sealed release registration fixture"}, nil)
	if registered.status != 201 {
		t.Fatalf("register: %d %s", registered.status, registered.body)
	}
	record, err := env.rt.PluginCatalog.Get(t.Context(), "codexploit.joern", "2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "/api/v2/plugins/codexploit.joern/versions/2.3.4/releases"
	for _, digest := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		release := plugin.Release{PluginID: "codexploit.joern", PluginVersion: "2.3.4", OS: "linux", Arch: "arm64", BuildID: digest, PackageDigest: digest, ManifestDigest: record.ManifestDigest}
		got := do(t, env.ts, http.MethodPost, endpoint, release, nil)
		if got.status != 201 {
			t.Fatalf("build release: %d %s", got.status, got.body)
		}
		release.PackageDigest = strings.Repeat("c", 64)
		forged := do(t, env.ts, http.MethodPost, endpoint, release, nil)
		if forged.status != 400 {
			t.Fatalf("accepted mismatched build identity: %d %s", forged.status, forged.body)
		}
	}
	rows, err := env.rt.PluginCatalog.Repository.(plugin.InstallationRepository).ListPluginReleases(t.Context(), "codexploit.joern", "2.3.4")
	if err != nil || len(rows) != 2 {
		t.Fatalf("immutable builds missing: %+v %v", rows, err)
	}
}
