package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

func TestEnhancementRanksWithoutChangingPinnedPaths(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "adapter")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if out, err := exec.Command("go", "build", "-trimpath", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	raw := []byte(`{"data":{"paths":[{"id":"b","basis":"hypothesis"},{"id":"a","basis":"data_flow"}],"graph_pins":{"code":"code-fixed","security":"security-fixed"},"omitted":{"count":0,"reasons":[]}}}`)
	if err := os.WriteFile(filepath.Join(root, "paths.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	req := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: "inv-enhance", PluginID: "codexploit.joern", PluginVersion: "2.1.1", OperationID: "enhance", Stage: pluginsdk.PathEnhance, OutputDirectory: "outputs", Config: json.RawMessage(`{}`), Budget: pluginsdk.Budget{TimeoutSeconds: 10, MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20, MaxOutputFiles: 2}, Inputs: []pluginsdk.LocalInput{{ArtifactID: "paths-fixed", Port: "paths", Kind: "discovery.paths", SchemaID: "codexploit/discovery-paths/v2", Path: "paths.json", Bytes: int64(len(raw)), SHA256: fmtDigest(raw)}}}
	request, _ := json.Marshal(req)
	if err := os.WriteFile(filepath.Join(root, "request.json"), request, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(binary, "--request", filepath.Join(root, "request.json"), "--response", filepath.Join(root, "result.json")).CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	resultRaw, err := os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	if json.Unmarshal(resultRaw, &result) != nil || result.Status != "PARTIAL" || len(result.Outputs) != 2 {
		t.Fatalf("result: %s", resultRaw)
	}
	for _, out := range result.Outputs {
		data, err := os.ReadFile(filepath.Join(root, "outputs", out.Path))
		if err != nil {
			t.Fatal(err)
		}
		if out.Port == "paths" {
			var got map[string]any
			var before struct{ Data map[string]any }
			_ = json.Unmarshal(data, &got)
			_ = json.Unmarshal(raw, &before)
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(before.Data)
			if string(a) != string(b) {
				t.Fatal("enhancement changed evidence or graph pins")
			}
		}
		if out.Port == "selection" {
			var got struct {
				Source   string `json:"source_path_artifact"`
				Selected []struct {
					ID    string  `json:"path_id"`
					Rank  int     `json:"rank"`
					Score float64 `json:"score"`
				}
			}
			if json.Unmarshal(data, &got) != nil || got.Source != "paths-fixed" || len(got.Selected) != 2 || got.Selected[0].ID != "a" || got.Selected[0].Rank != 1 || got.Selected[0].Score <= got.Selected[1].Score {
				t.Fatalf("selection: %s", data)
			}
		}
	}
}
