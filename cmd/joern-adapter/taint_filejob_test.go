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

func TestTaintFileJobSharesFallbackSinkAcrossDifferentFlows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this recorded JVM process fixture uses the sealed POSIX java executable layout")
	}
	pkg := t.TempDir()
	for _, dir := range []string{"bin", "vendor/jdk/bin"} {
		if err := os.MkdirAll(filepath.Join(pkg, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	adapter := filepath.Join(pkg, "bin", "joern-adapter")
	if out, err := exec.Command("go", "build", "-trimpath", "-o", adapter, ".").CombinedOutput(); err != nil {
		t.Fatalf("build adapter: %v %s", err, out)
	}
	// Replay a native-tool response at the process boundary. This is not a
	// substitute for the opt-in tests with a real Joern CPG and JVM.
	program := `package main
import("os";"path/filepath";"strings")
func main(){
 data,err:=os.ReadFile(filepath.Join(filepath.Dir(os.Args[0]),"replay.json"));if err!=nil{panic(err)}
 for _,arg:=range os.Args[1:]{if strings.HasPrefix(arg,"outFile="){if err:=os.WriteFile(strings.TrimPrefix(arg,"outFile="),data,0600);err!=nil{panic(err)};return}}
 panic("missing output binding")
}`
	programFile := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(programFile, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", filepath.Join(pkg, "vendor/jdk/bin/java"), programFile).CombinedOutput(); err != nil {
		t.Fatalf("build native-response replay: %v %s", err, out)
	}
	replay := []byte(`{"sink_inventory":[],"partitions":[],"flows":[
	 {"rule_id":"test.flow","nodes":[{"id":"input-a","label":"METHOD_PARAMETER_IN"},{"id":"shared-sink","label":"CALL"}]},
	 {"rule_id":"test.flow","nodes":[{"id":"input-b","label":"METHOD_PARAMETER_IN"},{"id":"shared-sink","label":"CALL"}]},
	 {"rule_id":"test.flow","nodes":[{"id":"input-a","label":"METHOD_PARAMETER_IN"},{"id":"shared-sink","label":"CALL"}]}
	]}`)
	if err := os.WriteFile(filepath.Join(pkg, "vendor/jdk/bin/replay.json"), replay, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"java-sinks.json", "rules.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "plugins", "joern", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(pkg, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	rawManifest, err := os.ReadFile("../../plugins/joern/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Version string }
	if err = json.Unmarshal(rawManifest, &manifest); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bind := func(port, kind, schema, id string, raw []byte) pluginsdk.LocalInput {
		t.Helper()
		name := id + ".input"
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return pluginsdk.LocalInput{ArtifactID: id, Port: port, Kind: kind, SchemaID: schema, Path: name, Bytes: int64(len(raw)), SHA256: fmtDigest(raw)}
	}
	code := bind("code", "code.facts", "codexploit/code-facts/v2", "code-fixed", []byte(`{"data":{"files":[],"native_id_mappings":[{"native_artifact_ref":"cpg-fixed","native_id":"native-method","canonical_ref":null}]}}`))
	cpg := bind("cpg", "tool.native", "joern/cpg/v1", "cpg-fixed", []byte("recorded native input"))
	req := pluginsdk.JobRequest{APIVersion: "codexploit/file-job/v2", InvocationID: "shared-sink", PluginID: "codexploit.joern", PluginVersion: manifest.Version, OperationID: "taint", Stage: pluginsdk.Semantic, Inputs: []pluginsdk.LocalInput{code, cpg}, OutputDirectory: "outputs", Config: json.RawMessage(`{"max_flows":10}`), Budget: pluginsdk.Budget{TimeoutSeconds: 30, MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20, MaxOutputFiles: 4}}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	request, response := filepath.Join(root, "job.json"), filepath.Join(root, "result.json")
	if err = os.WriteFile(request, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(adapter, "--request", request, "--response", response).CombinedOutput(); err != nil {
		t.Fatalf("file job: %v %s", err, out)
	}
	raw, err = os.ReadFile(response)
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "PARTIAL" {
		t.Fatalf("taint response: %s", raw)
	}
	for _, output := range result.Outputs {
		if output.Port != "security" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, "outputs", output.Path))
		if err != nil {
			t.Fatal(err)
		}
		if fmtDigest(raw) != output.SHA256 || int64(len(raw)) != output.Bytes {
			t.Fatal("security output is not bound to the file-job response")
		}
		var facts struct {
			Entries   []struct{ ID string }
			Sinks     []struct{ ID string }
			Relations []struct{ ID, From, To string }
		}
		if err := json.Unmarshal(raw, &facts); err != nil {
			t.Fatal(err)
		}
		if len(facts.Entries) != 2 || len(facts.Sinks) != 1 || len(facts.Relations) != 2 {
			t.Fatalf("shared sink must be unique without losing independent flows: %s", raw)
		}
		if facts.Relations[0].From == facts.Relations[1].From || facts.Relations[0].To != facts.Sinks[0].ID || facts.Relations[1].To != facts.Sinks[0].ID {
			t.Fatal("independent entries must retain their relationships to the shared sink")
		}
		if !strings.Contains(string(raw), `"has_flow":true`) {
			t.Fatal("shared sink lost its observed-flow association")
		}
		return
	}
	t.Fatal("security output missing")
}
