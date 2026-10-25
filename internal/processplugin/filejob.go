package processplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v2"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

type jobInput struct {
	ArtifactID string `json:"artifact_id,omitempty"`
	Port       string `json:"port"`
	Kind       string `json:"kind"`
	SchemaID   string `json:"schema_id"`
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}
type jobOutput struct {
	jobInput
	MediaType string `json:"media_type"`
}
type jobResult struct {
	APIVersion   string               `json:"api_version"`
	InvocationID string               `json:"invocation_id"`
	Status       string               `json:"status"`
	ErrorCode    string               `json:"error_code,omitempty"`
	Outputs      []jobOutput          `json:"outputs"`
	Coverage     plugin.StageCoverage `json:"coverage"`
	Limitations  []string             `json:"limitations"`
}

var jobSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile("file-job.schema.json")
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err = json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
})

func fileJobExecutor(pkg plugin.Package, op plugin.Operation) plugin.Executor {
	return plugin.Executor{Manifest: pkg.RawManifest, PackageDigest: pkg.PackageDigest, ManifestDigest: pkg.ManifestDigest, Source: "local package " + pkg.Manifest.ID + "@" + pkg.Manifest.Version, OperationID: op.ID, RunOutputs: func(ctx context.Context, inv plugin.Invocation, inputs [][]byte) (plugin.RawResult, error) {
		return runFileJob(ctx, pkg, op, inv, inputs)
	}}
}

// Each invocation uses a newly verified private copy of the complete release.
// A changed file is rejected before launch and again before publishing outputs.
func copyRelease(ctx context.Context, pkg plugin.Package, destination string) (plugin.Package, error) {
	current, err := plugin.LoadPackage(pkg.Directory)
	if err != nil || current.PackageDigest != pkg.PackageDigest {
		return plugin.Package{}, plugin.ErrConflict
	}
	root, err := os.OpenRoot(pkg.Directory)
	if err != nil {
		return plugin.Package{}, plugin.ErrInvalid
	}
	defer root.Close()
	var total int64
	err = filepath.WalkDir(pkg.Directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(pkg.Directory, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(destination, 0700)
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(destination, rel), 0700)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return plugin.ErrInvalid
		}
		if info.Size() > plugin.MaxStagePackageBytes-total {
			return plugin.ErrBudget
		}
		total += info.Size()
		input, err := root.Open(rel)
		if err != nil {
			return plugin.ErrInvalid
		}
		output, err := os.OpenFile(filepath.Join(destination, rel), os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			_ = input.Close()
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, info.Size()+1))
		_ = input.Close()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if written != info.Size() {
			return plugin.ErrConflict
		}
		return nil
	})
	if err != nil {
		return plugin.Package{}, err
	}
	copy, err := plugin.LoadPackage(destination)
	if err != nil || copy.PackageDigest != pkg.PackageDigest {
		return plugin.Package{}, plugin.ErrConflict
	}
	return copy, nil
}

type discardLog struct{}

func (discardLog) Write(p []byte) (int, error) { return len(p), nil }

func runFileJob(ctx context.Context, pkg plugin.Package, op plugin.Operation, inv plugin.Invocation, inputs [][]byte) (result plugin.RawResult, err error) {
	if pkg.Manifest.Permissions.Network != "none" || (pkg.Manifest.Permissions.TargetExecution != nil && *pkg.Manifest.Permissions.TargetExecution) {
		return result, plugin.ErrUnsupported
	}
	work, err := os.MkdirTemp("", "codexploit-plugin-job-")
	if err != nil {
		return result, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(work)
		}
	}()
	copy, err := copyRelease(ctx, pkg, filepath.Join(work, "package"))
	if err != nil {
		if errors.Is(err, plugin.ErrConflict) {
			return result, &plugin.ExecutionError{Code: "integrity_mismatch"}
		}
		return result, err
	}
	for _, dir := range []string{"inputs", "outputs", "work"} {
		if err = os.Mkdir(filepath.Join(work, dir), 0700); err != nil {
			return result, err
		}
	}
	bound := []jobInput{}
	if len(inputs) != len(inv.Request.Inputs) || len(inputs) != len(inv.Request.InputPorts) {
		return result, plugin.ErrInvalid
	}
	for i, raw := range inputs {
		path := fmt.Sprintf("inputs/%d.input", i)
		if err = os.WriteFile(filepath.Join(work, filepath.FromSlash(path)), raw, 0400); err != nil {
			return result, err
		}
		ref := inv.Request.Inputs[i]
		identity := ""
		if pkg.Manifest.Runtime.Protocol == plugin.FileJobProtocolV2 {
			identity = ref.ID
		}
		bound = append(bound, jobInput{ArtifactID: identity, Port: inv.Request.InputPorts[i], Kind: ref.Kind, SchemaID: ref.SchemaID, Path: path, Bytes: ref.Bytes, SHA256: ref.SHA256})
	}
	request := map[string]any{"api_version": pkg.Manifest.Runtime.Protocol, "invocation_id": inv.ID, "plugin_id": inv.Request.PluginID, "plugin_version": inv.Request.PluginVersion, "operation_id": op.ID, "stage": op.Stage, "scope": inv.Request.Scope, "inputs": bound, "output_directory": "outputs", "config": inv.Request.Config, "budget": map[string]any{"timeout_seconds": inv.Request.Budget.TimeoutSeconds, "max_input_bytes": inv.Request.Budget.MaxInputBytes, "max_output_bytes": inv.Request.Budget.MaxOutputBytes, "max_output_files": inv.Request.Budget.MaxFiles}}
	raw, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	requestPath, resultPath := filepath.Join(work, "job.json"), filepath.Join(work, "result.json")
	if err = os.WriteFile(requestPath, raw, 0400); err != nil {
		return result, err
	}
	cmd := exec.CommandContext(ctx, copy.Executable, "--request", requestPath, "--response", resultPath)
	cmd.Dir = filepath.Join(work, "work")
	cmd.Env = []string{"PATH=" + pluginPath(copy.Executable), "HOME=" + cmd.Dir, "TMPDIR=" + cmd.Dir, "TEMP=" + cmd.Dir, "TMP=" + cmd.Dir}
	for _, key := range []string{"SYSTEMROOT", "WINDIR"} {
		if value := os.Getenv(key); value != "" {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Stdout = discardLog{}
	cmd.Stderr = discardLog{}
	configureJobProcess(cmd)
	cmd.Cancel = func() error { return killJobProcess(cmd) }
	cmd.WaitDelay = time.Second
	defer func() { _ = killJobProcess(cmd) }()
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, &plugin.ExecutionError{Code: "tool_failed"}
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	verified, err := plugin.LoadPackage(copy.Directory)
	if err != nil || verified.PackageDigest != pkg.PackageDigest {
		return result, plugin.ErrConflict
	}
	jobRoot, err := os.OpenRoot(work)
	if err != nil {
		return result, err
	}
	defer jobRoot.Close()
	info, err := jobRoot.Lstat("result.json")
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return result, plugin.ErrProtocolViolation
	}
	f, err := jobRoot.Open("result.json")
	if err != nil {
		return result, plugin.ErrProtocolViolation
	}
	raw, err = io.ReadAll(io.LimitReader(f, 1<<20+1))
	_ = f.Close()
	if err != nil || len(raw) > 1<<20 {
		return result, plugin.ErrBudget
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return result, plugin.ErrProtocolViolation
	}
	var value any
	if json.Unmarshal(canonical, &value) != nil {
		return result, plugin.ErrProtocolViolation
	}
	schema, err := jobSchema()
	if err != nil {
		return result, err
	}
	if schema.Validate(value) != nil {
		return result, plugin.ErrProtocolViolation
	}
	var report jobResult
	if json.Unmarshal(canonical, &report) != nil || report.InvocationID != inv.ID || report.APIVersion != pkg.Manifest.Runtime.Protocol {
		return result, plugin.ErrProtocolViolation
	}
	if report.Status != "SUCCEEDED" && report.Status != "PARTIAL" {
		if report.Status == "UNSUPPORTED" {
			return result, plugin.ErrUnsupported
		}
		code := "tool_failed"
		// Only bounded protocol classifications cross the process boundary;
		// arbitrary stderr and vendor error text never reach the model or UI.
		switch report.ErrorCode {
		case "invalid_input", "invalid_config", "dependency_unavailable", "execution_failed", "selection_budget_exceeded", "flow_budget_exceeded", "trace_budget_exceeded", "report_budget_exceeded", "output_budget_exceeded", "normalization_failed", "memory_budget_exceeded", "deadline":
			code = report.ErrorCode
		}
		return result, &plugin.ExecutionError{Code: code}
	}
	c := report.Coverage
	for _, n := range []*int64{c.Seen, c.Analyzed, c.Skipped, c.Failed} {
		if n != nil && (*n < 0 || *n > 1<<40) {
			return result, plugin.ErrProtocolViolation
		}
	}
	if c.Seen != nil && c.Analyzed != nil && c.Skipped != nil && c.Failed != nil && *c.Seen != *c.Analyzed+*c.Skipped+*c.Failed {
		return result, plugin.ErrProtocolViolation
	}
	if (c.Truncated || (c.Failed != nil && *c.Failed > 0) || (c.Skipped != nil && *c.Skipped > 0)) && report.Status == "SUCCEEDED" {
		return result, plugin.ErrProtocolViolation
	}
	outputRoot, err := os.OpenRoot(filepath.Join(work, "outputs"))
	if err != nil {
		return result, err
	}
	result = plugin.RawResult{Status: report.Status, Coverage: c, Limitations: report.Limitations, Close: func() { _ = outputRoot.Close(); _ = os.RemoveAll(work) }}
	seen := map[string]bool{}
	for _, out := range report.Outputs {
		if !validJobPath(out.Path) || seen[strings.ToLower(out.Path)] {
			result.Close()
			return plugin.RawResult{}, plugin.ErrProtocolViolation
		}
		seen[strings.ToLower(out.Path)] = true
		info, err := outputRoot.Lstat(filepath.FromSlash(out.Path))
		if err != nil || !info.Mode().IsRegular() || info.Size() != out.Bytes {
			result.Close()
			return plugin.RawResult{}, plugin.ErrProtocolViolation
		}
		path := filepath.FromSlash(out.Path)
		result.Outputs = append(result.Outputs, plugin.RawOutput{Port: out.Port, Kind: out.Kind, SchemaID: out.SchemaID, Bytes: out.Bytes, SHA256: out.SHA256, MediaType: out.MediaType, Open: func() (io.ReadCloser, error) { return outputRoot.Open(path) }})
	}
	// The host re-reads every byte through ArtifactStore.Prepare before publishing.
	keep = true
	return result, nil
}

func validJobPath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && !strings.ContainsAny(path, "\\:\x00\n\r") && filepath.ToSlash(filepath.Clean(path)) == path && path != "." && !strings.HasPrefix(path, "../") && path != ".."
}

// Fixed system utility paths permit pinned JVM shell launchers without inheriting host PATH.
func pluginPath(executable string) string {
	return filepath.Dir(executable) + string(os.PathListSeparator) + "/usr/bin" + string(os.PathListSeparator) + "/bin"
}
