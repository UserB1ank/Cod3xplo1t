package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

func TestAutoSourceProjectSkipsResourceBytecodeAndReportsFailureContext(t *testing.T) {
	pkg := t.TempDir()
	if err := os.Mkdir(filepath.Join(pkg, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(pkg, "bin", "joern-adapter")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if out, err := exec.Command("go", "build", "-trimpath", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	frontends, err := os.ReadFile("../../plugins/joern/frontends.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "frontends.json"), frontends, 0600); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile("../../plugins/joern/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var version struct {
		Version string `json:"version"`
	}
	json.Unmarshal(manifest, &version)
	for _, tc := range []struct {
		name, requested, want string
		source                bool
	}{
		{"source-with-resource-jars", "AUTO", "JAVASRC", true},
		{"bytecode-only", "AUTO", "JAVA", false},
		{"explicit-bytecode", "JAVA", "JAVA", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tree := filepath.Join(root, "source")
			if err := os.Mkdir(tree, 0700); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{"first.jar": "resource fixture", "second.jar": "resource fixture"}
			if tc.source {
				files["Example.java"] = "class Example { void run() {} }"
			}
			var total int64
			for name, content := range files {
				t.Cleanup(func() { _ = os.Chmod(filepath.Join(tree, name), 0600) })
				if err := os.WriteFile(filepath.Join(tree, name), []byte(content), 0400); err != nil {
					t.Fatal(err)
				}
				total += int64(len(content))
			}
			req := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: "selection-diagnostic", PluginID: "codexploit.joern", PluginVersion: version.Version, OperationID: "parse", Stage: pluginsdk.Parse, OutputDirectory: "outputs", Config: json.RawMessage(`{"frontend":"` + tc.requested + `"}`), Budget: pluginsdk.Budget{TimeoutSeconds: 60, MaxInputBytes: 1 << 20, MaxOutputBytes: 16 << 20, MaxOutputFiles: 2}, Inputs: []pluginsdk.LocalInput{{ArtifactID: "source-binding", Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-directory/v1", Path: tree, Bytes: total, SHA256: strings.Repeat("a", 64)}}}
			raw, _ := json.Marshal(req)
			requestPath := filepath.Join(root, "job.json")
			responsePath := filepath.Join(root, "result.json")
			if err := os.WriteFile(requestPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(binary, "--request", requestPath, "--response", responsePath).CombinedOutput(); err != nil {
				t.Fatalf("run: %v %s", err, out)
			}
			raw, err = os.ReadFile(responsePath)
			if err != nil {
				t.Fatal(err)
			}
			var result pluginsdk.JobResult
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if result.ErrorCode != "dependency_unavailable" || len(result.Outputs) != 0 {
				t.Fatalf("unexpected failure: %s", raw)
			}
			if result.Coverage.Seen == nil || *result.Coverage.Seen != int64(len(files)) {
				t.Fatalf("observed source inventory lost: %s", raw)
			}
			if !strings.Contains(strings.Join(result.Limitations, "\n"), "frontend="+tc.want+";step=parse") {
				t.Fatalf("wrong selected frontend or missing diagnostic: %s", raw)
			}
		})
	}
}

func TestJavaMemoryFailureReportsBudgetWithoutLeakingVendorStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the vendored JVM layout in this process fixture uses POSIX executable names")
	}
	pkg := t.TempDir()
	for _, path := range []string{"bin", "vendor/jdk/bin"} {
		if err := os.MkdirAll(filepath.Join(pkg, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	adapter := filepath.Join(pkg, "bin", "adapter")
	if runtime.GOOS == "windows" {
		adapter += ".exe"
	}
	if out, err := exec.Command("go", "build", "-trimpath", "-o", adapter, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	source := filepath.Join(t.TempDir(), "main.go")
	// This subprocess deliberately fails. No successful CPG or code facts are mocked.
	program := `package main
import("os";"strings")
func main(){os.Stderr.WriteString(strings.Repeat("PRIVATE_VENDOR_DIAGNOSTIC_SHOULD_NOT_ESCAPE",10000)+"\njava.lang.OutOfMemoryError: Java heap space\n");os.Exit(1)}`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", filepath.Join(pkg, "vendor/jdk/bin/java"), source).CombinedOutput(); err != nil {
		t.Fatalf("native failure fixture: %v %s", err, out)
	}
	catalog, err := os.ReadFile("../../plugins/joern/frontends.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "frontends.json"), catalog, 0600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	tree := filepath.Join(root, "source")
	os.Mkdir(tree, 0700)
	file := filepath.Join(tree, "Example.java")
	if err := os.WriteFile(file, []byte("class Example {}"), 0400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(file, 0600) })
	manifest, _ := os.ReadFile("../../plugins/joern/manifest.json")
	var version struct {
		Version string `json:"version"`
	}
	json.Unmarshal(manifest, &version)
	req := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: "memory-failure", PluginID: "codexploit.joern", PluginVersion: version.Version, OperationID: "parse", Stage: pluginsdk.Parse, OutputDirectory: "outputs", Config: json.RawMessage(`{}`), Budget: pluginsdk.Budget{TimeoutSeconds: 60, MaxInputBytes: 1 << 20, MaxOutputBytes: 16 << 20, MaxOutputFiles: 2}, Inputs: []pluginsdk.LocalInput{{ArtifactID: "source", Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-directory/v1", Path: tree, Bytes: 16, SHA256: strings.Repeat("a", 64)}}}
	raw, _ := json.Marshal(req)
	os.WriteFile(filepath.Join(root, "job.json"), raw, 0600)
	if out, err := exec.Command(adapter, "--request", filepath.Join(root, "job.json"), "--response", filepath.Join(root, "result.json")).CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	raw, err = os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	json.Unmarshal(raw, &result)
	if result.ErrorCode != "memory_budget_exceeded" || len(result.Outputs) != 0 || result.Coverage.Seen == nil || *result.Coverage.Seen != 1 {
		t.Fatalf("memory failure: %s", raw)
	}
	if strings.Contains(string(raw), "PRIVATE_VENDOR_DIAGNOSTIC") || !strings.Contains(strings.Join(result.Limitations, "\n"), "frontend=JAVASRC;step=parse;reason=memory_budget_exceeded") {
		t.Fatalf("unsafe or missing diagnostic: %s", raw)
	}
}
