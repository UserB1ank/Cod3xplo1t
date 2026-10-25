// plugin-adapter wraps an offline CLI distribution using a sealed recipe.
// The tool's implementation is opaque; only bound input and output ports matter.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
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

type recipe struct {
	APIVersion  string `json:"api_version"`
	OperationID string `json:"operation_id"`
	Outputs     []struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		Schema    string `json:"schema_id"`
		MediaType string `json:"media_type"`
	} `json:"outputs"`
	Execution struct {
		Executable string   `json:"executable"`
		Args       []string `json:"argv"`
		Shell      bool     `json:"shell"`
	} `json:"execution"`
	RuntimePaths []string `json:"runtime_paths"`
}

func safePath(path string) bool {
	return path != "" && path != "." && path != ".." && !filepath.IsAbs(path) && !strings.HasPrefix(path, "../") && !strings.ContainsAny(path, "\\:\x00\r\n") && filepath.ToSlash(filepath.Clean(path)) == path
}

func unpack(raw []byte, destination string) (int64, error) {
	if err := os.Mkdir(destination, 0700); err != nil {
		return 0, err
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	seen := map[string]bool{}
	var count, total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, pluginsdk.ErrJob
		}
		name := strings.TrimSuffix(header.Name, "/")
		if !safePath(name) || seen[strings.ToLower(name)] {
			return 0, pluginsdk.ErrJob
		}
		seen[strings.ToLower(name)] = true
		if len(seen) > 20000 || header.Size < 0 || header.Size > 64<<20 || header.Size > int64(len(raw))-total {
			return 0, pluginsdk.ErrJob
		}
		path := filepath.Join(destination, filepath.FromSlash(name))
		if header.Typeflag == tar.TypeDir {
			if err = os.MkdirAll(path, 0700); err != nil {
				return 0, err
			}
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return 0, pluginsdk.ErrJob
		}
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return 0, err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
		if err != nil {
			return 0, err
		}
		written, copyErr := io.CopyN(file, reader, header.Size)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != header.Size {
			return 0, pluginsdk.ErrJob
		}
		count++
		total += written
	}
	return count, nil
}

func run(requestPath, responsePath, packageRoot string) error {
	request, err := pluginsdk.ReadJob(requestPath)
	if err != nil {
		return err
	}
	jobRoot := filepath.Dir(requestPath)
	result := pluginsdk.JobResult{APIVersion: "codexploit/file-job/v1", InvocationID: request.InvocationID, Status: "FAILED", Outputs: []pluginsdk.LocalOutput{}, Coverage: pluginsdk.Coverage{Unit: "files", Reasons: []string{}}, Limitations: []string{}}
	fail := func(code string, unsupported bool) error {
		result.ErrorCode = code
		if unsupported {
			result.Status = "UNSUPPORTED"
		}
		return pluginsdk.WriteResult(responsePath, result)
	}
	info, err := os.Lstat(filepath.Join(packageRoot, "recipe.json"))
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return fail("dependency_unavailable", true)
	}
	raw, err := os.ReadFile(filepath.Join(packageRoot, "recipe.json"))
	if err != nil {
		return fail("dependency_unavailable", true)
	}
	var configuration recipe
	if json.Unmarshal(raw, &configuration) != nil || configuration.APIVersion != "codexploit/binary-recipe/v1" || configuration.OperationID != request.OperationID || configuration.Execution.Shell || !safePath(configuration.Execution.Executable) {
		return fail("invalid_config", false)
	}
	var config map[string]any
	if json.Unmarshal(request.Config, &config) != nil {
		return fail("invalid_config", false)
	}
	values := map[string]string{"{job:work}": filepath.Join(jobRoot, "work")}
	var seenFiles int64
	for _, input := range request.Inputs {
		values["{input:"+input.Port+"}"] = filepath.Join(jobRoot, filepath.FromSlash(input.Path))
		if input.Kind == "source.snapshot" && input.SchemaID == "codexploit/source-tar/v1" {
			raw, err := pluginsdk.ReadInput(jobRoot, request, input.Port)
			if err != nil {
				return fail("invalid_input", false)
			}
			tree := filepath.Join(jobRoot, "work", "source-"+strconv.Itoa(len(values)))
			count, err := unpack(raw, tree)
			if err != nil {
				return fail("invalid_input", false)
			}
			seenFiles += count
			values["{input:"+input.Port+"_tree}"] = tree
		}
	}
	for key, value := range config {
		text, ok := value.(string)
		if !ok {
			continue
		}
		values["{config:"+key+"}"] = text
	}
	for _, out := range configuration.Outputs {
		if !safePath(out.Name) || strings.Contains(out.Name, "/") {
			return fail("invalid_config", false)
		}
		values["{output:"+out.Name+"}"] = filepath.Join(jobRoot, request.OutputDirectory, out.Name+".output")
	}
	args := make([]string, 0, len(configuration.Execution.Args))
	for _, arg := range configuration.Execution.Args {
		if strings.HasPrefix(arg, "{") {
			replacement, ok := values[arg]
			if !ok {
				return fail("invalid_config", false)
			}
			arg = replacement
		}
		args = append(args, arg)
	}
	executable := filepath.Join(packageRoot, filepath.FromSlash(configuration.Execution.Executable))
	info, err = os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return fail("dependency_unavailable", true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(request.Budget.TimeoutSeconds)*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = filepath.Join(jobRoot, "work")
	command.Env = os.Environ()
	paths := []string{filepath.Join(packageRoot, "bin")}
	for _, path := range configuration.RuntimePaths {
		if !safePath(path) {
			return fail("invalid_config", false)
		}
		paths = append(paths, filepath.Join(packageRoot, filepath.FromSlash(path)))
	}
	paths = append(paths, os.Getenv("PATH"))
	command.Env = append(command.Env, "PATH="+strings.Join(paths, string(os.PathListSeparator)))
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err = command.Run(); err != nil {
		if ctx.Err() != nil {
			return fail("deadline", false)
		}
		return fail("tool_failed", false)
	}
	var total int64
	for _, out := range configuration.Outputs {
		path := values["{output:"+out.Name+"}"]
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > request.Budget.MaxOutputBytes-total {
			return fail("output_contract_mismatch", false)
		}
		file, err := os.Open(path)
		if err != nil {
			return fail("output_contract_mismatch", false)
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(hasher, io.LimitReader(file, info.Size()+1))
		_ = file.Close()
		if copyErr != nil || written != info.Size() {
			return fail("output_contract_mismatch", false)
		}
		total += written
		mediaType := out.MediaType
		if mediaType == "" {
			mediaType = "application/json"
			if out.Kind == "tool.native" {
				mediaType = "application/octet-stream"
			}
		}
		result.Outputs = append(result.Outputs, pluginsdk.LocalOutput{Port: out.Name, Kind: out.Kind, SchemaID: out.Schema, Path: out.Name + ".output", MediaType: mediaType, Bytes: written, SHA256: fmt.Sprintf("%x", hasher.Sum(nil))})
	}
	result.Status = "PARTIAL"
	result.Coverage.Seen = &seenFiles
	result.Coverage.Reasons = []string{"The wrapped CLI did not provide standardized coverage counters"}
	result.Limitations = []string{"Native tool output is preserved; complete analysis coverage is not asserted"}
	return pluginsdk.WriteResult(responsePath, result)
}

func main() {
	request := flag.String("request", "", "bound job file")
	response := flag.String("response", "", "bound result file")
	flag.Parse()
	executable, err := os.Executable()
	if err != nil || *request == "" || *response == "" {
		os.Exit(2)
	}
	if err = run(*request, *response, filepath.Dir(filepath.Dir(executable))); err != nil {
		os.Exit(1)
	}
}
