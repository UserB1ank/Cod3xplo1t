package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

const adapterVersion = "2.1.1"

type failure struct {
	Code        string
	Unsupported bool
}

func (f *failure) Error() string    { return f.Code }
func failed(code string) error      { return &failure{Code: code} }
func unavailable(code string) error { return &failure{Code: code, Unsupported: true} }

type job struct {
	Request                     pluginsdk.JobRequest
	Result                      pluginsdk.JobResult
	Root, Package, Work, Output string
	Context                     context.Context
	Total                       int64
}

func decodeConfig(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return failed("invalid_config")
	}
	return nil
}
func run(requestPath, responsePath string) error {
	req, err := pluginsdk.ReadJob(requestPath)
	if err != nil {
		return err
	}
	j := job{Request: req, Result: pluginsdk.JobResult{APIVersion: req.APIVersion, InvocationID: req.InvocationID, Status: "FAILED", Outputs: []pluginsdk.LocalOutput{}, Coverage: pluginsdk.Coverage{Unit: "files", Reasons: []string{}}, Limitations: []string{}}, Root: filepath.Dir(requestPath)}
	execute := func() error {
		if req.APIVersion != "codexploit/file-job/v2" || req.PluginID != "codexploit.joern" || req.PluginVersion != adapterVersion || req.Budget.TimeoutSeconds < 1 || req.Budget.TimeoutSeconds > 3600 {
			return unavailable("unsupported")
		}
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		j.Package = filepath.Dir(filepath.Dir(binary))
		j.Work = filepath.Join(j.Root, "work")
		j.Output = filepath.Join(j.Root, req.OutputDirectory)
		for _, path := range []string{j.Work, j.Output} {
			if err := os.MkdirAll(path, 0700); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Budget.TimeoutSeconds)*time.Second)
		defer cancel()
		j.Context = ctx
		switch req.OperationID {
		case "parse":
			if req.Stage != pluginsdk.Parse {
				return failed("invalid_input")
			}
			return j.parse()
		case "taint":
			if req.Stage != pluginsdk.Semantic {
				return failed("invalid_input")
			}
			return j.taint()
		case "paths":
			if req.Stage != pluginsdk.PathGenerate {
				return failed("invalid_input")
			}
			return j.paths()
		case "enhance":
			if req.Stage != pluginsdk.PathEnhance {
				return failed("invalid_input")
			}
			return j.enhance()
		default:
			return unavailable("unsupported")
		}
	}
	err = execute()
	if err != nil {
		j.Result.Outputs = []pluginsdk.LocalOutput{}
		j.Result.ErrorCode = "execution_failed"
		if f, ok := err.(*failure); ok {
			j.Result.ErrorCode = f.Code
			if f.Unsupported {
				j.Result.Status = "UNSUPPORTED"
			}
		}
		if j.Context != nil && j.Context.Err() == context.DeadlineExceeded {
			j.Result.ErrorCode = "deadline"
			j.Result.Status = "FAILED"
		}
	}
	return pluginsdk.WriteResult(responsePath, j.Result)
}
func (j *job) inputs(port string) []pluginsdk.LocalInput {
	out := []pluginsdk.LocalInput{}
	for _, i := range j.Request.Inputs {
		if i.Port == port {
			out = append(out, i)
		}
	}
	return out
}
func (j *job) read(port string) ([]byte, error) {
	raw, err := pluginsdk.ReadInput(j.Root, j.Request, port)
	if err != nil {
		return nil, failed("invalid_input")
	}
	return raw, nil
}
func (j *job) readBound(input pluginsdk.LocalInput) ([]byte, error) {
	// The selected LocalInput must be one of this host-authored job's bindings.
	req := j.Request
	req.Inputs = []pluginsdk.LocalInput{input}
	return pluginsdk.ReadInput(j.Root, req, input.Port)
}
func (j *job) source() (string, map[string]bool, error) {
	raw, err := j.read("source")
	if err != nil {
		return "", nil, err
	}
	tree := filepath.Join(j.Work, "source")
	files, err := sourceTree(raw, tree)
	if err != nil {
		return "", nil, failed("invalid_input")
	}
	return tree, files, nil
}
func (j *job) java(module, main string, heap int, args ...string) error {
	javaHome := filepath.Join(j.Package, "vendor/jdk")
	java := filepath.Join(javaHome, "bin/java")
	info, err := os.Lstat(java)
	if err != nil || !info.Mode().IsRegular() {
		return unavailable("dependency_unavailable")
	}
	if heap == 0 {
		heap = 1024
	}
	if heap < 256 || heap > 4096 {
		return failed("invalid_config")
	}
	cp := filepath.Join(j.Package, "vendor/joern-cli/lib/*")
	if module != "" {
		cp = filepath.Join(j.Package, "vendor/joern-cli/frontends", module, "lib/*")
	}
	memory := fmt.Sprintf("-Xmx%dm", heap)
	options := memory + " -XX:ActiveProcessorCount=2 " + strconv.Quote("-Djava.io.tmpdir="+j.Work) + " " + strconv.Quote("-Duser.home="+j.Work)
	command := exec.CommandContext(j.Context, java, append([]string{memory, "-XX:ActiveProcessorCount=2", "-cp", cp, main}, args...)...)
	command.Dir = j.Work
	command.Env = []string{"HOME=" + j.Work, "TMPDIR=" + j.Work, "TMP=" + j.Work, "TEMP=" + j.Work, "JAVA_HOME=" + javaHome, "PATH=" + strings.Join([]string{filepath.Join(javaHome, "bin"), filepath.Join(j.Package, "vendor/php/bin"), filepath.Join(j.Package, "vendor/rust/bin"), "/usr/bin", "/bin"}, string(os.PathListSeparator)), "JAVA_TOOL_OPTIONS=" + options, "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOTELEMETRY=off", "LANG=C.UTF-8", "CARGO_NET_OFFLINE=true", "CARGO_HOME=" + j.Work, "RUSTUP_HOME=" + j.Work}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return failed("execution_failed")
	}
	return nil
}
func (j *job) script(name string, heap int, params ...string) error {
	args := []string{"--script", filepath.Join(j.Package, "scripts", name)}
	for _, p := range params {
		args = append(args, "--param", p)
	}
	return j.java("", "io.joern.joerncli.console.ReplBridge", heap, args...)
}
func (j *job) addOutput(port, kind, schema, name, media string) error {
	if len(j.Result.Outputs) >= j.Request.Budget.MaxOutputFiles {
		return failed("output_budget_exceeded")
	}
	f, err := os.Open(filepath.Join(j.Output, name))
	if err != nil {
		return failed("normalization_failed")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > j.Request.Budget.MaxOutputBytes-j.Total {
		return failed("output_budget_exceeded")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, j.Request.Budget.MaxOutputBytes-j.Total+1))
	if err != nil || n != info.Size() {
		return failed("normalization_failed")
	}
	j.Total += n
	j.Result.Outputs = append(j.Result.Outputs, pluginsdk.LocalOutput{Port: port, Kind: kind, SchemaID: schema, Path: name, MediaType: media, Bytes: n, SHA256: fmt.Sprintf("%x", h.Sum(nil))})
	return nil
}
func (j *job) jsonOutput(port, kind, schema, name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return failed("normalization_failed")
	}
	if int64(len(raw)) > j.Request.Budget.MaxOutputBytes-j.Total {
		return failed("output_budget_exceeded")
	}
	if err := os.WriteFile(filepath.Join(j.Output, name), raw, 0600); err != nil {
		return err
	}
	return j.addOutput(port, kind, schema, name, "application/json")
}
func copyFile(source, target string, max int64) error {
	f, err := os.Open(source)
	if err != nil {
		return failed("normalization_failed")
	}
	defer f.Close()
	g, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(g, io.LimitReader(f, max+1))
	closeErr := g.Close()
	if err != nil || closeErr != nil || n > max {
		return failed("output_budget_exceeded")
	}
	return nil
}
