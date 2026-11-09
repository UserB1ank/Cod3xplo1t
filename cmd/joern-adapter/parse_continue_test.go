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

func TestAutoParseContinuesAfterAFrontendFailure(t *testing.T) {
	pkg := buildParseFixture(t)
	tree := filepath.Join(t.TempDir(), "source")
	writeParseFixture(t, tree, map[string]string{
		"Example.c":  "void entry(void) {}\n",
		"Example.cs": "class Example { void Entry() {} }\n",
	})

	result, decoded := runParseFixture(t, pkg, tree, map[string]any{"frontend": "AUTO"})
	if result.Status != "PARTIAL" || result.ErrorCode != "" || len(result.Outputs) != 2 {
		t.Fatalf("successful frontend was discarded after another failed: %+v", result)
	}
	if result.Coverage.Analyzed == nil || *result.Coverage.Analyzed != 1 ||
		result.Coverage.Failed == nil || *result.Coverage.Failed != 1 ||
		result.Coverage.Skipped == nil || *result.Coverage.Skipped != 0 {
		t.Fatalf("coverage does not retain the successful and failed frontends: %+v", result.Coverage)
	}
	if !strings.Contains(strings.Join(result.Limitations, "\n"), "joern:frontend=C;step=parse;reason=execution_failed") {
		t.Fatalf("failed frontend diagnostic missing: %v", result.Limitations)
	}

	files := map[string]string{}
	for _, file := range decoded.Files {
		files[file.Path] = file.ParseStatus
	}
	if files["Example.c"] != "unparsed" || files["Example.cs"] != "partial" {
		t.Fatalf("code facts lost a frontend result: %+v", files)
	}
}

func TestParseInputPathMapsRelativeNativeFilesToSnapshotPaths(t *testing.T) {
	pkg := buildParseFixture(t)
	tree := filepath.Join(t.TempDir(), "source")
	writeParseFixture(t, tree, map[string]string{
		"sub/Example.cs": "class Example { void Entry() {} }\n",
	})

	result, decoded := runParseFixture(t, pkg, tree, map[string]any{
		"frontend":   "CSHARPSRC",
		"input_path": "sub",
	})
	if result.Status != "PARTIAL" || result.ErrorCode != "" || len(result.Outputs) != 2 {
		t.Fatalf("input_path parse failed: %+v", result)
	}
	if result.Coverage.Analyzed == nil || *result.Coverage.Analyzed != 1 {
		t.Fatalf("relative native path was not rebound to the snapshot: %+v", result.Coverage)
	}
	if len(decoded.Files) != 1 || decoded.Files[0].Path != "sub/Example.cs" || decoded.Files[0].Language != "C#" {
		t.Fatalf("unexpected frozen paths: %+v", decoded.Files)
	}
}

type decodedParseFacts struct {
	Files []struct {
		Path        string `json:"path"`
		Language    string `json:"language"`
		ParseStatus string `json:"parse_status"`
	} `json:"files"`
}

func buildParseFixture(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake JVM fixture uses a POSIX executable name")
	}
	pkg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(pkg, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pkg, "vendor", "jdk", "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	adapter := filepath.Join(pkg, "bin", "joern-adapter")
	if out, err := exec.Command("go", "build", "-trimpath", "-o", adapter, ".").CombinedOutput(); err != nil {
		t.Fatalf("build adapter: %v %s", err, out)
	}
	catalog, err := os.ReadFile("../../plugins/joern/frontends.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "frontends.json"), catalog, 0600); err != nil {
		t.Fatal(err)
	}
	javaSource := filepath.Join(pkg, "fake_java.go")
	if err := os.WriteFile(javaSource, []byte(fakeJavaProgram), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(pkg, "vendor", "jdk", "bin", "java"), javaSource).CombinedOutput(); err != nil {
		t.Fatalf("build fake JVM: %v %s", err, out)
	}
	return pkg
}

func writeParseFixture(t *testing.T, tree string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(tree, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0400); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0600) })
	}
}

func runParseFixture(t *testing.T, pkg, tree string, config map[string]any) (pluginsdk.JobResult, decodedParseFacts) {
	t.Helper()
	var total int64
	if err := filepath.Walk(tree, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	configRaw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile("../../plugins/joern/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	request := pluginsdk.JobRequest{
		APIVersion: "codexploit/file-job/v2", InvocationID: "parse-frontend-continuation",
		PluginID: "codexploit.joern", PluginVersion: manifest.Version, OperationID: "parse", Stage: pluginsdk.Parse,
		OutputDirectory: "outputs", Config: configRaw,
		Budget: pluginsdk.Budget{TimeoutSeconds: 60, MaxInputBytes: 1 << 20, MaxOutputBytes: 16 << 20, MaxOutputFiles: 16},
		Inputs: []pluginsdk.LocalInput{{
			ArtifactID: "source-binding", Port: "source", Kind: "source.snapshot",
			SchemaID: "codexploit/source-directory/v1", Path: tree, Bytes: total, SHA256: strings.Repeat("a", 64),
		}},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	requestPath := filepath.Join(root, "request.json")
	responsePath := filepath.Join(root, "result.json")
	if err := os.WriteFile(requestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(filepath.Join(pkg, "bin", "joern-adapter"), "--request", requestPath, "--response", responsePath).CombinedOutput(); err != nil {
		t.Fatalf("run adapter: %v %s", err, out)
	}
	raw, err = os.ReadFile(responsePath)
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if logRaw, err := os.ReadFile(filepath.Join(root, "work", "fake-java.log")); err == nil {
		t.Logf("fake JVM log:\n%s", logRaw)
	}
	decoded := decodedParseFacts{}
	for _, output := range result.Outputs {
		if output.Port != "code" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, request.OutputDirectory, output.Path))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
	}
	return result, decoded
}

const fakeJavaProgram = `package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	joined := strings.Join(os.Args[1:], " ")
	work := ""
	if out := argument(os.Args[1:], "--output"); out != "" {
		work = filepath.Dir(out)
	} else if out := parameter(os.Args[1:], "outFile"); out != "" {
		work = filepath.Dir(out)
	}
	log := func(message string) {
		if work != "" {
			path := filepath.Join(work, "fake-java.log")
			file, _ := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if file != nil {
				_, _ = file.WriteString(message + "\n")
				_ = file.Close()
			}
		}
	}
	if strings.Contains(joined, "io.joern.c2cpg.Main") {
		log("C frontend failure")
		os.Stderr.WriteString("synthetic C frontend failure\n")
		os.Exit(1)
	}
	if strings.Contains(joined, "io.joern.csharpsrc2cpg.Main") {
		log("C# parse")
		out := argument(os.Args[1:], "--output")
		cpg := filepath.Join(filepath.Dir(out), "workspace", filepath.Base(out), "cpg.bin")
		sourcePath := ""
		for i := 0; i+1 < len(os.Args); i++ {
			if os.Args[i] == "io.joern.csharpsrc2cpg.Main" {
				sourcePath = os.Args[i+1]
				break
			}
		}
		if sourcePath == "" ||
			os.MkdirAll(filepath.Dir(cpg), 0700) != nil ||
			os.WriteFile(cpg, []byte("synthetic cpg"), 0600) != nil ||
			os.WriteFile(filepath.Join(work, "source-path"), []byte(sourcePath), 0600) != nil {
			log("C# output failure")
			os.Exit(2)
		}
		return
	}
	if strings.Contains(joined, "io.joern.joerncli.console.ReplBridge") {
		log("C# export")
		out := parameter(os.Args[1:], "outFile")
		work := filepath.Dir(out)
		sourceRaw, _ := os.ReadFile(filepath.Join(work, "source-path"))
		sourceRoot := strings.TrimSpace(string(sourceRaw))
		var source string
		_ = filepath.Walk(sourceRoot, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() && strings.EqualFold(filepath.Ext(path), ".cs") {
				source = path
			}
			return nil
		})
		if source == "" || out == "" {
			log("export input missing")
			os.Exit(3)
		}
		export := map[string]any{
			"files": []any{map[string]any{"id": "file-cs", "name": filepath.Base(source)}},
			"methods": []any{map[string]any{
				"id": "method-entry", "name": "Entry", "full_name": "Example.Entry",
				"signature": "void Entry()", "external": false,
				"filename": filepath.Base(source), "line": 1, "column": 1,
			}},
			"calls": []any{},
		}
		raw, _ := json.Marshal(export)
		if os.WriteFile(out, raw, 0600) != nil {
			log("export write failure")
			os.Exit(4)
		}
		return
	}
	log("unhandled main")
	os.Exit(5)
}

func argument(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func parameter(args []string, name string) string {
	prefix := name + "="
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--param" && strings.HasPrefix(args[i+1], prefix) {
			return strings.TrimPrefix(args[i+1], prefix)
		}
	}
	return ""
}
`
