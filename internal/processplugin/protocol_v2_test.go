package processplugin_test

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin"
)

func TestNativeProtocolStagesOutputAndRejectsCorruptDigest(t *testing.T) {
	const source = `package main
import("bufio";"encoding/json";"os";"crypto/sha256";"fmt";"encoding/base64")
func send(id json.RawMessage,result any){_ =json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc":"2.0","id":id,"result":result})}
func call(id,method string,params any){_ =json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc":"2.0","id":id,"method":method,"params":params})}
func main(){
 scanner:=bufio.NewScanner(os.Stdin);var invocation string;var pending json.RawMessage;var stage string;bad:=false;data:=[]byte("native stream output")
 for scanner.Scan(){var m struct{ID json.RawMessage ` + "`json:\"id\"`" + `;Method string ` + "`json:\"method\"`" + `;Params map[string]any ` + "`json:\"params\"`" + `;Result map[string]any ` + "`json:\"result\"`" + `};if json.Unmarshal(scanner.Bytes(),&m)!=nil{os.Exit(2)}
 switch m.Method{
 case "plugin.initialize":p:=m.Params;send(m.ID,map[string]any{"protocol":p["protocol"],"plugin_id":p["plugin_id"],"plugin_version":p["plugin_version"],"package_digest":p["package_digest"],"manifest_digest":p["manifest_digest"],"operations":[]any{p["operation_id"]},"inputs":p["inputs"],"outputs":p["outputs"]})
 case "plugin.execute":invocation=m.Params["invocation_id"].(string);if config,ok:=m.Params["config"].(map[string]any);ok{bad,_=config["bad_digest"].(bool)};send(m.ID,map[string]any{"accepted":true,"invocation_id":invocation})
 case "plugin.status":pending=m.ID;digest:=fmt.Sprintf("%x",sha256.Sum256(data));if bad{digest=fmt.Sprintf("%064d",0)};call("begin","host.artifacts.begin",map[string]any{"invocation_id":invocation,"output_port":"native","kind":"tool.native","schema_id":"codexploit/native-bytes/v1","expected_bytes":len(data),"expected_sha256":digest})
 default:var id string;_ =json.Unmarshal(m.ID,&id);switch id{
 case "begin":stage,_=m.Result["staging_id"].(string);call("write","host.artifacts.write",map[string]any{"staging_id":stage,"index":0,"data":base64.StdEncoding.EncodeToString(data)})
 case "write":call("finish","host.artifacts.finish",map[string]any{"staging_id":stage})
 case "finish":send(pending,map[string]any{"invocation_id":invocation,"status":"SUCCEEDED","coverage":map[string]any{"unit":"files","seen":1,"analyzed":1,"skipped":0,"failed":0,"truncated":false,"reasons":[]string{}},"limitations":[]string{}})
 }
 }
 }
}`
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	code := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(code, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	entry := "adapter"
	if runtime.GOOS == "windows" {
		entry += ".exe"
	}
	command := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(directory, "bin", entry), code)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("independent protocol binary: %v %s", err, output)
	}
	manifest := []byte(`{"api_version":"codexploit/plugin/v2","id":"example.stream","version":"1.0.0","name":"Native stream","description":"Protocol boundary fixture","languages":["Go"],"runtime":{"kind":"process","protocol":"codexploit/process-plugin/v2","entrypoint":"bin/adapter"},"permissions":{"network":"none","source_write":false,"target_execution":false},"operations":[{"id":"capture","stage":"parse","capability":"parse","profile":"native","inputs":[{"name":"source","kind":"source.snapshot","schema_id":"codexploit/source-tar/v1","required":true,"cardinality":"one"}],"outputs":[{"name":"native","kind":"tool.native","schema_id":"codexploit/native-bytes/v1","required":true,"cardinality":"one"}],"config_schema":{"type":"object","properties":{"bad_digest":{"type":"boolean"}},"additionalProperties":false}}]}`)
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := plugin.BuildFilesLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "files.lock.json"), lock, 0600); err != nil {
		t.Fatal(err)
	}
	pkg, err := plugin.LoadPackage(directory)
	if err != nil {
		t.Fatal(err)
	}
	executors, err := processplugin.PackageExecutors(pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []bool{false, true} {
		t.Run(fmtBool(bad), func(t *testing.T) {
			config, _ := json.Marshal(map[string]bool{"bad_digest": bad})
			inv := plugin.Invocation{ID: "stream-fixture", Request: plugin.Request{ID: "stream-fixture", PluginID: pkg.Manifest.ID, PluginVersion: pkg.Manifest.Version, OperationID: "capture", PackageDigest: pkg.PackageDigest, Config: config, Budget: plugin.Budget{MaxOutputBytes: 1 << 20, MaxFiles: 10, TimeoutSeconds: 10}}}
			result, err := executors[0].RunOutputs(t.Context(), inv, nil)
			if result.Close != nil {
				defer result.Close()
			}
			if bad {
				if err == nil {
					t.Fatal("bad digest accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Outputs) != 1 {
				t.Fatalf("output count: %d", len(result.Outputs))
			}
			reader, err := result.Outputs[0].Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(reader)
			_ = reader.Close()
			if err != nil || string(data) != "native stream output" {
				t.Fatalf("native bytes: %q %v", data, err)
			}
		})
	}
}

func fmtBool(b bool) string {
	if b {
		return "corrupt"
	}
	return "valid"
}
