package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

func TestRealSourceParseContinuesPastAnEmptyIncidentalFrontend(t *testing.T) {
	pkg := os.Getenv("JOERN_TEST_PACKAGE")
	if pkg == "" {
		t.Skip("requires the real offline Joern package")
	}
	root := t.TempDir()
	tree := filepath.Join(root, "source")
	files := map[string]string{"Example.java": "class Example { void sink(String value) {} void entry(String input) { sink(input); } }", "src/test/resources/fixture.js": "function example(v) { return v; }"}
	var total int64
	for name, body := range files {
		path := filepath.Join(tree, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0400); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0600) })
		total += int64(len(body))
	}
	manifest, _ := os.ReadFile(filepath.Join(pkg, "manifest.json"))
	var version struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &version); err != nil {
		t.Fatal(err)
	}
	req := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: "mixed-source-empty-frontend", PluginID: "codexploit.joern", PluginVersion: version.Version, OperationID: "parse", Stage: pluginsdk.Parse, OutputDirectory: "outputs", Config: json.RawMessage(`{"frontend":"AUTO","heap_mib":1024}`), Budget: pluginsdk.Budget{TimeoutSeconds: 300, MaxInputBytes: 1 << 20, MaxOutputBytes: 64 << 20, MaxOutputFiles: 8}, Inputs: []pluginsdk.LocalInput{{ArtifactID: "source", Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-directory/v1", Path: tree, Bytes: total, SHA256: strings.Repeat("a", 64)}}}
	raw, _ := json.Marshal(req)
	os.WriteFile(filepath.Join(root, "job.json"), raw, 0600)
	if out, err := exec.Command(filepath.Join(pkg, "bin/joern-adapter"), "--request", filepath.Join(root, "job.json"), "--response", filepath.Join(root, "result.json")).CombinedOutput(); err != nil {
		t.Fatalf("real runner: %v %s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "PARTIAL" || result.Coverage.Analyzed == nil || *result.Coverage.Analyzed < 1 || len(result.Outputs) < 2 {
		t.Fatalf("empty incidental frontend blocked Java: %s", raw)
	}
}
