package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestVersionedStageCatalogUsesAuthenticatedManagementAPI(t *testing.T) {
	rt, err := app.Build(t.Context(), app.Config{Workspace: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	env := serveTestEnv(t, rt, false)
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"api_version": "codexploit/v2", "manifest": json.RawMessage(raw), "package_digest": strings.Repeat("d", 64), "source": "contract fixture"}
	denied := doAs(t, env.ts, readerSecret, http.MethodPost, "/api/v2/plugins", body, nil)
	if denied.status != 403 {
		t.Fatalf("reader registration: %d %s", denied.status, denied.body)
	}
	created := do(t, env.ts, http.MethodPost, "/api/v2/plugins", body, nil)
	if created.status != 201 {
		t.Fatalf("registration: %d %s", created.status, created.body)
	}
	listed := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v2/plugins", nil, nil)
	if listed.status != 200 || !strings.Contains(string(listed.body), "example.parse") {
		t.Fatalf("catalog: %d %s", listed.status, listed.body)
	}
	stages := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v2/plugin-stages", nil, nil)
	var page struct {
		Stages []json.RawMessage `json:"stages"`
	}
	stages.decode(t, &page)
	if stages.status != 200 || len(page.Stages) != 10 {
		t.Fatalf("stages: %d %s", stages.status, stages.body)
	}
}

func TestInstallationPolicyRequiresAdminAndCurrentVersion(t *testing.T) {
	rt, err := app.Build(t.Context(), app.Config{Workspace: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	env := serveTestEnv(t, rt, false)
	repo := rt.PluginCatalog.Repository.(plugin.InstallationRepository)
	release := plugin.Release{PluginID: "example.installed", PluginVersion: "1.0.0", OS: "linux", Arch: "amd64", PackageDigest: strings.Repeat("e", 64), ManifestDigest: strings.Repeat("f", 64)}
	if err = repo.PutPluginRelease(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	row := plugin.Installation{ID: "installation-api-fixture", Release: release, WorkerID: "local", Installed: true, Enabled: true, Integrity: "verified", Probe: "not_run", Version: 1}
	if _, err = repo.SavePluginInstallation(t.Context(), row, 0); err != nil {
		t.Fatal(err)
	}
	endpoint := "/api/v2/plugin-installations/" + row.ID
	for _, secret := range []string{readerSecret, writerSecret} {
		denied := doAs(t, env.ts, secret, http.MethodPatch, endpoint, map[string]any{"enabled": false}, map[string]string{"If-Match": installationTag(row)})
		if denied.status != 403 {
			t.Fatalf("non-admin policy: %d %s", denied.status, denied.body)
		}
	}
	missing := do(t, env.ts, http.MethodPatch, endpoint, map[string]any{"enabled": false}, nil)
	if missing.status != 428 {
		t.Fatalf("missing version: %d %s", missing.status, missing.body)
	}
	changed := do(t, env.ts, http.MethodPatch, endpoint, map[string]any{"enabled": false}, map[string]string{"If-Match": installationTag(row)})
	if changed.status != 200 {
		t.Fatalf("disable: %d %s", changed.status, changed.body)
	}
	stale := do(t, env.ts, http.MethodPatch, endpoint, map[string]any{"enabled": true}, map[string]string{"If-Match": installationTag(row)})
	if stale.status != 412 {
		t.Fatalf("stale policy: %d %s", stale.status, stale.body)
	}
	listed := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v2/plugin-installations", nil, nil)
	var page struct {
		Installations []plugin.Installation `json:"installations"`
	}
	listed.decode(t, &page)
	found := false
	for _, entry := range page.Installations {
		if entry.ID == row.ID && !entry.Enabled {
			found = true
		}
	}
	if listed.status != 200 || !found {
		t.Fatalf("read policy: %d %s", listed.status, listed.body)
	}
}

func TestInstalledV2ProtocolsSatisfyAuthenticatedResponseContract(t *testing.T) {
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest plugin.Manifest
	if json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("manifest")
	}
	for _, protocol := range []string{plugin.FileJobProtocol, plugin.ProcessProtocolV2} {
		manifest.Runtime.Protocol = protocol
		record := plugin.Record{Manifest: manifest, PackageDigest: strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64), Source: "verified package", Installed: true, Executable: true, ProtocolVersion: protocol}
		response := httptest.NewRecorder()
		writePluginV2JSON(response, 200, map[string]any{"api_version": "codexploit/v2", "plugins": []plugin.Record{record}, "next_cursor": ""})
		if response.Code != 200 {
			t.Fatalf("installed %s record violates API contract: %s", protocol, response.Body.String())
		}
	}
}

func TestKnowledgeDirectoryRetainsStageProducerProvenance(t *testing.T) {
	response := httptest.NewRecorder()
	producer := map[string]any{"plugin_id": "codexploit.joern", "plugin_version": "1.0.1", "invocation_id": "inv-joern", "config_digest": strings.Repeat("a", 64), "operation_id": "parse_go", "output_port": "code", "package_digest": strings.Repeat("b", 64), "normalizer_digest": strings.Repeat("c", 64)}
	scope := map[string]any{"project_id": "project", "snapshot_id": "snapshot"}
	revision := map[string]any{"scope": scope, "revision": "rev-1", "revision_no": 1, "batch_id": "batch-joern", "base_revision": "rev-0", "digest": strings.Repeat("d", 64), "layer": "code", "producer": producer, "coverage": map[string]any{"files_seen": 1, "files_analyzed": 1, "files_skipped": 0}, "created_at": "2026-10-23T00:00:00Z", "view": map[string]any{"view_id": "view-fixed", "revision": "rev-1", "scope": scope}}
	writeKnowledgeDirectory(response, map[string]any{"api_version": "codexploit/v1", "head_revision": "rev-1", "revisions": []any{revision}, "next_cursor": ""})
	if response.Code != 200 {
		t.Fatalf("modern publication directory: %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"normalizer_digest"`) {
		t.Fatal("normalizer provenance discarded")
	}
}
