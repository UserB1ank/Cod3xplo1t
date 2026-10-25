package main_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

func TestRecipeAdapterWrapsAnIndependentCLIAndRejectsEscapingSource(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "vendor"), 0700); err != nil {
		t.Fatal(err)
	}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	adapter := filepath.Join(root, "bin", "adapter"+suffix)
	build := exec.Command("go", "build", "-trimpath", "-o", adapter, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build adapter: %v %s", err, output)
	}
	toolSource := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(toolSource, []byte(`package main
import("os";"path/filepath")
func main(){raw,err:=os.ReadFile(filepath.Join(os.Args[2],"main.go"));if err!=nil{os.Exit(2)};if os.WriteFile(os.Args[4],append([]byte("native-fixture:"),raw...),0600)!=nil{os.Exit(3)}}`), 0600); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(root, "vendor", "tool"+suffix)
	build = exec.Command("go", "build", "-trimpath", "-o", tool, toolSource)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI fixture: %v %s", err, output)
	}
	recipe := map[string]any{"api_version": "codexploit/binary-recipe/v1", "operation_id": "capture", "execution": map[string]any{"executable": "vendor/tool" + suffix, "argv": []string{"--input", "{input:source_tree}", "--output", "{output:native}"}, "shell": false}, "outputs": []any{map[string]any{"name": "native", "kind": "tool.native", "schema_id": "codexploit/native-bytes/v1"}}}
	raw, _ := json.Marshal(recipe)
	if err := os.WriteFile(filepath.Join(root, "recipe.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"main.go", "../escape.go"} {
		t.Run(path, func(t *testing.T) {
			job := t.TempDir()
			for _, dir := range []string{"inputs", "outputs", "work"} {
				if err := os.Mkdir(filepath.Join(job, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			content := []byte("package main\nfunc main(){}\n")
			var buffer bytes.Buffer
			writer := tar.NewWriter(&buffer)
			if err := writer.WriteHeader(&tar.Header{Name: path, Mode: 0600, Size: int64(len(content))}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(content); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			input := buffer.Bytes()
			if err := os.WriteFile(filepath.Join(job, "inputs", "source.tar"), input, 0400); err != nil {
				t.Fatal(err)
			}
			request := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v1", InvocationID: "recipe-fixture", PluginID: "example.recipe", PluginVersion: "1.0.0", OperationID: "capture", Stage: pluginsdk.Parse, Scope: pluginsdk.Scope{ProjectID: "project", SourceID: "source", SnapshotID: "snapshot"}, Inputs: []pluginsdk.LocalInput{{Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-tar/v1", Path: "inputs/source.tar", Bytes: int64(len(input)), SHA256: fmt.Sprintf("%x", sha256.Sum256(input))}}, OutputDirectory: "outputs", Config: json.RawMessage(`{}`), Budget: pluginsdk.Budget{TimeoutSeconds: 10, MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20, MaxOutputFiles: 10}}
			raw, _ := json.Marshal(request)
			requestPath, responsePath := filepath.Join(job, "job.json"), filepath.Join(job, "result.json")
			if err := os.WriteFile(requestPath, raw, 0400); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(adapter, "--request", requestPath, "--response", responsePath)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("adapter process: %v %s", err, output)
			}
			raw, err := os.ReadFile(responsePath)
			if err != nil {
				t.Fatal(err)
			}
			var result pluginsdk.JobResult
			if err = json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if path != "main.go" {
				if result.Status != "FAILED" || len(result.Outputs) != 0 {
					t.Fatalf("escaping source accepted: %+v", result)
				}
				return
			}
			if result.Status != "PARTIAL" || result.Coverage.Analyzed != nil || len(result.Outputs) != 1 {
				t.Fatalf("native coverage was overstated: %+v", result)
			}
			raw, err = os.ReadFile(filepath.Join(job, "outputs", result.Outputs[0].Path))
			if err != nil || string(raw) != "native-fixture:"+string(content) {
				t.Fatalf("wrapped binary output: %q %v", raw, err)
			}
		})
	}
}
