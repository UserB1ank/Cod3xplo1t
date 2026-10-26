package main_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

func TestMissingJoernRuntimeReportsUnsupportedWithoutOutputs(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "joern-adapter")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	command := exec.Command("go", "build", "-trimpath", "-o", binary, ".")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	request := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: "inv-test", PluginID: "codexploit.joern", PluginVersion: "2.3.0", OperationID: "parse", Stage: pluginsdk.Parse, OutputDirectory: "outputs", Config: json.RawMessage(`{}`), Budget: pluginsdk.Budget{TimeoutSeconds: 120, MaxInputBytes: 1 << 20, MaxOutputBytes: 16 << 20, MaxOutputFiles: 2}}
	var source bytes.Buffer
	tw := tar.NewWriter(&source)
	body := []byte("package main\nfunc main() {}\n")
	if err := tw.WriteHeader(&tar.Header{Name: "main.go", Mode: 0600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.tar"), source.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	request.Inputs = []pluginsdk.LocalInput{{ArtifactID: "source-fixed", Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-tar/v1", Path: "source.tar", Bytes: int64(source.Len()), SHA256: fmtDigest(source.Bytes())}}
	raw, _ := json.Marshal(request)
	if err := os.WriteFile(filepath.Join(root, "request.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(binary, "--request", filepath.Join(root, "request.json"), "--response", filepath.Join(root, "result.json"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "UNSUPPORTED" || result.ErrorCode != "dependency_unavailable" || len(result.Outputs) != 0 {
		t.Fatalf("unexpected result: %s", raw)
	}
}

func fmtDigest(raw []byte) string {
	const alphabet = "0123456789abcdef"
	sum := sha256.Sum256(raw)
	out := make([]byte, 64)
	for i, b := range sum {
		out[2*i] = alphabet[b>>4]
		out[2*i+1] = alphabet[b&15]
	}
	return string(out)
}

// Opt in with a real offline package. This test never substitutes a mock CPG.
func TestRealJoernGoBinaryParsesFrozenSource(t *testing.T) {
	packageRoot := os.Getenv("JOERN_TEST_PACKAGE")
	if packageRoot == "" {
		t.Skip("set JOERN_TEST_PACKAGE to the verified offline Joern package")
	}
	root := t.TempDir()
	for _, path := range []string{"outputs", "work"} {
		if err := os.Mkdir(filepath.Join(root, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"main.go": "package main\nimport \"fmt\"\nfunc helper(v string) { fmt.Println(v) }\nfunc main() { helper(\"ok\") }\n", "README.md": "frozen auxiliary file\n"}
	var source bytes.Buffer
	tw := tar.NewWriter(&source)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.tar"), source.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	request := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: "inv-real-joern", PluginID: "codexploit.joern", PluginVersion: "2.3.0", OperationID: "parse", Stage: pluginsdk.Parse, OutputDirectory: "outputs", Config: json.RawMessage(`{}`), Budget: pluginsdk.Budget{TimeoutSeconds: 180, MaxInputBytes: 1 << 20, MaxOutputBytes: 16 << 20, MaxOutputFiles: 2}, Inputs: []pluginsdk.LocalInput{{ArtifactID: "source-fixed", Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-tar/v1", Path: "source.tar", Bytes: int64(source.Len()), SHA256: fmtDigest(source.Bytes())}}}
	raw, _ := json.Marshal(request)
	if err := os.WriteFile(filepath.Join(root, "request.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(packageRoot, "bin", "joern-adapter"), "--request", filepath.Join(root, "request.json"), "--response", filepath.Join(root, "result.json"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "PARTIAL" || result.ErrorCode != "" || len(result.Outputs) != 2 || result.Coverage.Seen == nil || *result.Coverage.Seen != 2 || result.Coverage.Analyzed == nil || *result.Coverage.Analyzed != 1 || result.Coverage.Skipped == nil || *result.Coverage.Skipped != 1 {
		t.Fatalf("result: %s", raw)
	}
	var facts struct {
		Files   []struct{ Path string }
		Symbols []struct {
			ID            string
			QualifiedName string `json:"qualified_name"`
		}
		Calls []struct {
			Caller     *string `json:"caller_ref"`
			Callee     *string `json:"callee_ref"`
			Resolution string
		}
		Mappings []struct {
			Artifact string `json:"native_artifact_ref"`
		} `json:"native_id_mappings"`
	}
	for _, output := range result.Outputs {
		data, err := os.ReadFile(filepath.Join(root, "outputs", output.Path))
		if err != nil {
			t.Fatal(err)
		}
		if output.Bytes != int64(len(data)) || output.SHA256 != fmtDigest(data) {
			t.Fatal("unbound output")
		}
		if output.Port == "code" {
			if err := json.Unmarshal(data, &facts); err != nil {
				t.Fatal(err)
			}
		}
	}
	names := map[string]bool{}
	for _, s := range facts.Symbols {
		names[s.QualifiedName] = true
	}
	resolved, external := false, false
	for _, c := range facts.Calls {
		if c.Resolution == "resolved" && c.Caller != nil && c.Callee != nil {
			resolved = true
		}
		if c.Resolution == "external" && c.Callee == nil {
			external = true
		}
	}
	if !names["main.main"] || !names["main.helper"] || !resolved || !external || len(facts.Mappings) == 0 {
		t.Fatalf("missing real CPG facts: %+v", facts)
	}
	for _, f := range facts.Files {
		if _, ok := files[f.Path]; !ok {
			t.Fatalf("unbound source path: %s", f.Path)
		}
	}
}

func TestRealJoernDoesNotPublishAnEmptyGraphForUnparseableGo(t *testing.T) {
	packageRoot := os.Getenv("JOERN_TEST_PACKAGE")
	if packageRoot == "" {
		t.Skip("requires real offline Joern package")
	}
	root := t.TempDir()
	body := []byte("this is not valid Go source\n")
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "broken.go", Mode: 0600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.tar"), archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	req := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: "broken-go", PluginID: "codexploit.joern", PluginVersion: "2.3.0", OperationID: "parse", Stage: pluginsdk.Parse, OutputDirectory: "outputs", Config: json.RawMessage(`{}`), Budget: pluginsdk.Budget{TimeoutSeconds: 120, MaxInputBytes: 1 << 20, MaxOutputBytes: 16 << 20, MaxOutputFiles: 2}, Inputs: []pluginsdk.LocalInput{{ArtifactID: "source-fixed", Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-tar/v1", Path: "source.tar", Bytes: int64(archive.Len()), SHA256: fmtDigest(archive.Bytes())}}}
	raw, _ := json.Marshal(req)
	if err := os.WriteFile(filepath.Join(root, "job.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(packageRoot, "bin/joern-adapter"), "--request", filepath.Join(root, "job.json"), "--response", filepath.Join(root, "result.json"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "FAILED" || len(result.Outputs) != 0 {
		t.Fatalf("unparseable source must not publish an empty successful graph: %s", raw)
	}
}

func TestRealJoernMixedLanguagesUsesEveryMatchingFrontend(t *testing.T) {
	packageRoot := os.Getenv("JOERN_TEST_PACKAGE")
	if packageRoot == "" {
		t.Skip("requires full offline Joern package")
	}
	root := t.TempDir()
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for name, body := range map[string]string{"sample.c": "void sink(char *v) {}\nvoid entry(char *input) { sink(input); }\n", "sample.js": "function sink(v) {}\nfunction entry(input) { sink(input); }\n", "sample.py": "def sink(v):\n    pass\ndef entry(input):\n    sink(input)\n"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.tar"), archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	req := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: "mixed", PluginID: "codexploit.joern", PluginVersion: "2.3.0", OperationID: "parse", Stage: pluginsdk.Parse, OutputDirectory: "outputs", Config: json.RawMessage(`{"frontend":"AUTO"}`), Budget: pluginsdk.Budget{TimeoutSeconds: 300, MaxInputBytes: 1 << 20, MaxOutputBytes: 64 << 20, MaxOutputFiles: 10}, Inputs: []pluginsdk.LocalInput{{ArtifactID: "frozen-source", Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-tar/v1", Path: "source.tar", Bytes: int64(archive.Len()), SHA256: fmtDigest(archive.Bytes())}}}
	raw, _ := json.Marshal(req)
	if err := os.WriteFile(filepath.Join(root, "job.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(filepath.Join(packageRoot, "bin/joern-adapter"), "--request", filepath.Join(root, "job.json"), "--response", filepath.Join(root, "result.json")).CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	raw, err = os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "PARTIAL" || len(result.Outputs) != 4 || result.Coverage.Analyzed == nil || *result.Coverage.Analyzed != 3 {
		t.Fatalf("all matching languages must run: %s", raw)
	}
}

func TestRealJoernTaintAndPinnedPaths(t *testing.T) {
	packageRoot := os.Getenv("JOERN_TEST_PACKAGE")
	if packageRoot == "" {
		t.Skip("requires full offline Joern package")
	}
	for _, fixture := range []struct{ name, body string }{
		{"sample.c", "void sink(char *v) {}\nvoid entry(char *input) { char *copy=input; sink(copy); sink(\"constant\"); }\n"},
		{"sample.js", "function sink(v) {}\nfunction entry(input) { let copy=input; sink(copy); sink(\"constant\"); }\n"},
		{"sample.py", "def sink(v):\n    pass\ndef entry(input):\n    copy = input\n    sink(copy)\n    sink(\"constant\")\n"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := t.TempDir()
			var archive bytes.Buffer
			tw := tar.NewWriter(&archive)
			if e := tw.WriteHeader(&tar.Header{Name: fixture.name, Size: int64(len(fixture.body)), Mode: 0600}); e != nil {
				t.Fatal(e)
			}
			_, _ = tw.Write([]byte(fixture.body))
			_ = tw.Close()
			bind := func(port, kind, schema, id string, raw []byte) pluginsdk.LocalInput {
				path := id + ".input"
				if e := os.WriteFile(filepath.Join(root, path), raw, 0600); e != nil {
					t.Fatal(e)
				}
				return pluginsdk.LocalInput{ArtifactID: id, Port: port, Kind: kind, SchemaID: schema, Path: path, Bytes: int64(len(raw)), SHA256: fmtDigest(raw)}
			}
			source := bind("source", "source.snapshot", "codexploit/source-tar/v1", "source-fixed", archive.Bytes())
			invoke := func(op string, stage pluginsdk.Stage, config string, inputs []pluginsdk.LocalInput) (pluginsdk.JobResult, map[string][]byte) {
				t.Helper()
				req := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: op, PluginID: "codexploit.joern", PluginVersion: "2.3.0", OperationID: op, Stage: stage, OutputDirectory: op + "-outputs", Config: json.RawMessage(config), Inputs: inputs, Budget: pluginsdk.Budget{TimeoutSeconds: 180, MaxInputBytes: 64 << 20, MaxOutputBytes: 64 << 20, MaxOutputFiles: 16}}
				raw, _ := json.Marshal(req)
				_ = os.WriteFile(filepath.Join(root, "job.json"), raw, 0600)
				out, e := exec.Command(filepath.Join(packageRoot, "bin/joern-adapter"), "--request", filepath.Join(root, "job.json"), "--response", filepath.Join(root, "result.json")).CombinedOutput()
				if e != nil {
					t.Fatalf("invoke: %v %s", e, out)
				}
				raw, _ = os.ReadFile(filepath.Join(root, "result.json"))
				var result pluginsdk.JobResult
				if json.Unmarshal(raw, &result) != nil {
					t.Fatal(string(raw))
				}
				values := map[string][]byte{}
				for _, o := range result.Outputs {
					v, e := os.ReadFile(filepath.Join(root, req.OutputDirectory, o.Path))
					if e != nil || fmtDigest(v) != o.SHA256 {
						t.Fatal("invalid output digest")
					}
					values[o.Port] = v
				}
				return result, values
			}
			parsed, values := invoke("parse", pluginsdk.Parse, `{}`, []pluginsdk.LocalInput{source})
			if parsed.Status != "PARTIAL" {
				t.Fatalf("parse: %+v", parsed)
			}
			code := bytes.ReplaceAll(values["code"], []byte("output:cpg:0"), []byte("cpg-fixed"))
			enveloped, _ := json.Marshal(map[string]any{"data": json.RawMessage(code)})
			codeInput := bind("code", "code.facts", "codexploit/code-facts/v2", "code-fixed", enveloped)
			cpgInput := bind("cpg", "tool.native", "joern/cpg/v1", "cpg-fixed", values["cpg"])
			config := `{"rules":[{"id":"test.flow","source":{"kind":"parameter","method":"entry","index":1},"sink":{"method":"sink","argument_index":1}}],"max_flows":20}`
			result, flowValues := invoke("taint", pluginsdk.Semantic, config, []pluginsdk.LocalInput{source, codeInput, cpgInput})
			if result.Status != "PARTIAL" || len(result.Outputs) != 2 {
				t.Fatalf("taint must execute real data flow: %+v", result)
			}
			var report struct {
				Flows       []struct{ Nodes []struct{ Code string } }
				SourceCount int `json:"source_count"`
				SinkCount   int `json:"sink_count"`
			}
			if json.Unmarshal(flowValues["flows"], &report) != nil || len(report.Flows) != 1 || report.SourceCount < 1 || report.SinkCount != 2 {
				t.Fatalf("tainted flow only, with matched sink count: %s", flowValues["flows"])
			}

			if fixture.name == "sample.c" {
				var payload map[string]any
				if e := json.Unmarshal(code, &payload); e != nil {
					t.Fatal(e)
				}
				mappings := payload["native_id_mappings"].([]any)
				original := append([]any{}, mappings...)
				for _, row := range original {
					data, _ := json.Marshal(row)
					var copy map[string]any
					json.Unmarshal(data, &copy)
					copy["native_artifact_ref"] = "cpg-broken"
					mappings = append(mappings, copy)
				}
				payload["native_id_mappings"] = mappings
				mixedCode, _ := json.Marshal(map[string]any{"data": payload})
				mixedInput := bind("code", "code.facts", "codexploit/code-facts/v2", "code-mixed", mixedCode)
				broken := bind("cpg", "tool.native", "joern/cpg/v1", "cpg-broken", []byte("invalid CPG; must never produce facts"))
				partial, partialValues := invoke("taint", pluginsdk.Semantic, config, []pluginsdk.LocalInput{source, mixedInput, cpgInput, broken})
				if partial.Status != "PARTIAL" || partial.Coverage.Analyzed == nil || *partial.Coverage.Analyzed != 1 || partial.Coverage.Failed == nil || *partial.Coverage.Failed != 1 {
					t.Fatalf("one bad language discarded real data flow: %+v", partial)
				}
				var incomplete struct {
					Flows           []json.RawMessage `json:"flows"`
					Failed          []string          `json:"failed_cpgs"`
					FailedFrontends []string          `json:"failed_frontends"`
					Truncated       bool              `json:"truncated"`
				}
				if e := json.Unmarshal(partialValues["flows"], &incomplete); e != nil || len(incomplete.Flows) != 1 || len(incomplete.Failed) != 1 || len(incomplete.FailedFrontends) != 1 || incomplete.FailedFrontends[0] != "C" || !incomplete.Truncated {
					t.Fatalf("missing retained flow or explicit gap: %s", partialValues["flows"])
				}
				allFailed, _ := invoke("taint", pluginsdk.Semantic, config, []pluginsdk.LocalInput{source, mixedInput, broken})
				if allFailed.Status != "FAILED" || len(allFailed.Outputs) != 0 {
					t.Fatalf("all failed CPGs must not become success: %+v", allFailed)
				}
			}
			for _, n := range report.Flows[0].Nodes {
				if bytes.Contains([]byte(n.Code), []byte("constant")) {
					t.Fatal("constant must not be tainted")
				}
			}
			if fixture.name == "sample.c" {
				limited := `{"rules":[{"id":"test.one","source":{"kind":"parameter","method":"entry","index":1},"sink":{"method":"sink","argument_index":1}},{"id":"test.two","source":{"kind":"parameter","method":"entry","index":1},"sink":{"method":"sink","argument_index":1}}],"max_flows":1}`
				bounded, outputs := invoke("taint", pluginsdk.Semantic, limited, []pluginsdk.LocalInput{source, codeInput, cpgInput})
				var retained struct {
					Flows     []json.RawMessage `json:"flows"`
					Truncated bool              `json:"truncated"`
				}
				if bounded.Status != "PARTIAL" || !bounded.Coverage.Truncated || json.Unmarshal(outputs["flows"], &retained) != nil || !retained.Truncated || len(retained.Flows) != 1 {
					t.Fatalf("flow limit must retain bounded evidence and declare truncation: %+v", bounded)
				}
			}
			sec, _ := json.Marshal(map[string]any{"data": json.RawMessage(flowValues["security"])})
			securityInput := bind("security", "security.facts", "codexploit/security-facts/v2", "security-fixed", sec)
			flowsInput := bind("flows", "tool.native", "codexploit/native-bytes/v1", "flows-fixed", flowValues["flows"])
			paths, pathValues := invoke("paths", pluginsdk.PathGenerate, `{}`, []pluginsdk.LocalInput{codeInput, securityInput, flowsInput})
			if paths.Status != "PARTIAL" || len(paths.Outputs) != 1 {
				t.Fatalf("paths: %+v", paths)
			}
			var p struct {
				Pins  map[string]string `json:"graph_pins"`
				Paths []struct {
					Basis        string
					Completeness string
					Steps        []any `json:"ordered_steps"`
				}
			}
			_ = json.Unmarshal(pathValues["paths"], &p)
			if p.Pins["code"] != "code-fixed" || p.Pins["security"] != "security-fixed" || len(p.Paths) != 1 || p.Paths[0].Basis != "data_flow" || p.Paths[0].Completeness != "partial" || len(p.Paths[0].Steps) != 1 {
				t.Fatalf("unbound paths: %s", pathValues["paths"])
			}
			// A raw report from another code artifact must never produce pinned paths.
			bad := bytes.ReplaceAll(flowValues["flows"], []byte("code-fixed"), []byte("other-code"))
			badInput := bind("flows", "tool.native", "codexploit/native-bytes/v1", "bad-flow", bad)
			rejected, _ := invoke("paths", pluginsdk.PathGenerate, `{}`, []pluginsdk.LocalInput{codeInput, securityInput, badInput})
			if rejected.Status != "FAILED" || len(rejected.Outputs) != 0 {
				t.Fatal("foreign raw flow accepted")
			}
		})
	}
}
