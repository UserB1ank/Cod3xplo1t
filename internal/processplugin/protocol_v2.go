package processplugin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/plugin/rpc"
)

type stageObject struct {
	Port     string
	Media    string
	Kind     string
	Schema   string
	Size     int64
	Digest   string
	Index    int
	Written  int64
	File     *os.File
	Path     string
	Finished bool
}

type streamState struct {
	mu        sync.Mutex
	directory string
	op        plugin.Operation
	inv       plugin.Invocation
	inputs    [][]byte
	objects   map[string]*stageObject
	order     []string
	reserved  int64
	eventSeq  int
	events    []plugin.StageEvent
	fatal     error
}

func (s *streamState) handle(ctx context.Context, method string, raw json.RawMessage) (any, *rpc.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func() (any, *rpc.Error) {
		s.fatal = plugin.ErrProtocolViolation
		return nil, &rpc.Error{Code: rpc.InvalidParams, Message: "stage contract or artifact channel rejected"}
	}
	if ctx.Err() != nil || s.fatal != nil {
		return fail()
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return fail()
	}
	var request struct {
		InvocationID string `json:"invocation_id"`
		Port         string `json:"output_port"`
		InputPort    string `json:"input_port"`
		ArtifactID   string `json:"artifact_id"`
		Kind         string `json:"kind"`
		Schema       string `json:"schema_id"`
		Size         int64  `json:"expected_bytes"`
		Digest       string `json:"expected_sha256"`
		StagingID    string `json:"staging_id"`
		Index        int    `json:"index"`
		Data         string `json:"data"`
		Offset       int64  `json:"offset"`
		Length       int64  `json:"length"`
		Seq          int    `json:"seq"`
		Type         string `json:"type"`
		Message      string `json:"message"`
		Media        string `json:"media_type"`
	}
	if json.Unmarshal(canonical, &request) != nil {
		return fail()
	}
	switch method {
	case "plugin.event":
		if request.InvocationID != s.inv.ID || request.Seq != s.eventSeq+1 || request.Seq > 200 || request.Type == "" || len(request.Type) > 64 || len(request.Message) > 1000 {
			return fail()
		}
		s.eventSeq++
		s.events = append(s.events, plugin.StageEvent{Seq: request.Seq, Type: request.Type, Message: request.Message})
		return map[string]bool{"accepted": true}, nil
	case "host.artifacts.read":
		if request.InvocationID != s.inv.ID || request.Offset < 0 || request.Length < 1 || request.Length > 256<<10 {
			return fail()
		}
		for i, ref := range s.inv.Request.Inputs {
			if ref.ID == request.ArtifactID && s.inv.Request.InputPorts[i] == request.InputPort {
				data := s.inputs[i]
				if request.Offset > int64(len(data)) {
					return fail()
				}
				end := min(request.Offset+request.Length, int64(len(data)))
				return map[string]any{"data": base64.StdEncoding.EncodeToString(data[request.Offset:end]), "eof": end == int64(len(data)), "total": len(data)}, nil
			}
		}
		return fail()
	case "host.artifacts.begin":
		if request.InvocationID != s.inv.ID || request.Size < 0 || len(request.Digest) != 64 || request.Size > s.inv.Request.Budget.MaxOutputBytes-s.reserved || len(s.order) >= s.inv.Request.Budget.MaxFiles {
			return fail()
		}
		valid := false
		for _, port := range s.op.Outputs {
			if port.Name == request.Port && port.Kind == request.Kind && port.SchemaID == request.Schema {
				valid = true
			}
		}
		if !valid || len(request.Media) > 100 {
			return fail()
		}
		id := "stage-" + rand.Text()
		path := filepath.Join(s.directory, id)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fail()
		}
		s.objects[id] = &stageObject{Media: request.Media, Port: request.Port, Kind: request.Kind, Schema: request.Schema, Size: request.Size, Digest: request.Digest, File: file, Path: path}
		s.order = append(s.order, id)
		s.reserved += request.Size
		return map[string]string{"staging_id": id}, nil
	case "host.artifacts.write", "host.artifacts.finish", "host.artifacts.abort":
		object, ok := s.objects[request.StagingID]
		if !ok {
			if method == "host.artifacts.abort" {
				for _, id := range s.order {
					if id == request.StagingID {
						return map[string]bool{"aborted": true}, nil
					}
				}
			}
			return fail()
		}
		if method == "host.artifacts.abort" {
			if object.File != nil {
				_ = object.File.Close()
			}
			_ = os.Remove(object.Path)
			delete(s.objects, request.StagingID)
			s.reserved -= object.Size
			return map[string]bool{"aborted": true}, nil
		}
		if object.Finished {
			return fail()
		}
		if method == "host.artifacts.write" {
			if request.Index != object.Index || len(request.Data) > base64.StdEncoding.EncodedLen(256<<10) {
				return fail()
			}
			data, err := base64.StdEncoding.DecodeString(request.Data)
			if err != nil || len(data) > 256<<10 || int64(len(data)) > object.Size-object.Written {
				return fail()
			}
			if _, err = object.File.Write(data); err != nil {
				return fail()
			}
			object.Written += int64(len(data))
			object.Index++
			return map[string]int{"accepted_index": request.Index}, nil
		}
		if object.Written != object.Size {
			return fail()
		}
		if err = object.File.Close(); err != nil {
			return fail()
		}
		object.File = nil
		file, err := os.Open(object.Path)
		if err != nil {
			return fail()
		}
		hasher := sha256.New()
		_, copyErr := io.Copy(hasher, file)
		_ = file.Close()
		if copyErr != nil || fmt.Sprintf("%x", hasher.Sum(nil)) != object.Digest {
			return fail()
		}
		object.Finished = true
		return map[string]bool{"staged": true}, nil
	default:
		return fail()
	}
}

func streamExecutor(pkg plugin.Package, op plugin.Operation) plugin.Executor {
	return plugin.Executor{Manifest: pkg.RawManifest, ManifestDigest: pkg.ManifestDigest, PackageDigest: pkg.PackageDigest, Source: "local package " + pkg.Manifest.ID + "@" + pkg.Manifest.Version, OperationID: op.ID, RunOutputs: func(ctx context.Context, inv plugin.Invocation, inputs [][]byte) (plugin.RawResult, error) {
		return runStream(ctx, pkg, op, inv, inputs)
	}}
}

func runStream(ctx context.Context, pkg plugin.Package, op plugin.Operation, inv plugin.Invocation, inputs [][]byte) (result plugin.RawResult, err error) {
	if pkg.Manifest.Permissions.Network != "none" || (pkg.Manifest.Permissions.TargetExecution != nil && *pkg.Manifest.Permissions.TargetExecution) {
		return result, plugin.ErrUnsupported
	}
	directory, err := os.MkdirTemp("", "codexploit-plugin-stream-")
	if err != nil {
		return result, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(directory)
		}
	}()
	copy, err := copyRelease(ctx, pkg, filepath.Join(directory, "package"))
	if err != nil {
		return result, err
	}
	state := &streamState{directory: directory, op: op, inv: inv, inputs: inputs, objects: map[string]*stageObject{}}
	defer func() {
		state.mu.Lock()
		defer state.mu.Unlock()
		for _, object := range state.objects {
			if object.File != nil {
				_ = object.File.Close()
			}
		}
	}()
	cmd := exec.CommandContext(ctx, copy.Executable)
	cmd.Dir = directory
	cmd.Env = []string{"PATH=" + pluginPath(copy.Executable), "HOME=" + directory, "TMPDIR=" + directory, "TEMP=" + directory, "TMP=" + directory}
	for _, key := range []string{"SYSTEMROOT", "WINDIR"} {
		if value := os.Getenv(key); value != "" {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	configureJobProcess(cmd)
	cmd.Cancel = func() error { return killJobProcess(cmd) }
	cmd.WaitDelay = time.Second
	cmd.Stderr = discardLog{}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return result, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return result, err
	}
	if err = cmd.Start(); err != nil {
		return result, &plugin.ExecutionError{Code: "spawn_failed"}
	}
	defer func() { _ = killJobProcess(cmd); _ = stdin.Close(); _ = cmd.Wait() }()
	conn := rpc.New(stdout, stdin, state.handle, rpc.Options{MaxMessageBytes: 1 << 20})
	defer conn.Close()
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	served := make(chan struct{})
	go func() { _ = conn.Serve(serveCtx); close(served) }()
	defer func() { _ = stdout.Close(); <-served }()
	handshake, done := context.WithTimeout(ctx, 5*time.Second)
	var response struct {
		Protocol       string        `json:"protocol"`
		PluginID       string        `json:"plugin_id"`
		PluginVersion  string        `json:"plugin_version"`
		PackageDigest  string        `json:"package_digest"`
		ManifestDigest string        `json:"manifest_digest"`
		Operations     []string      `json:"operations"`
		Inputs         []plugin.Port `json:"inputs"`
		Outputs        []plugin.Port `json:"outputs"`
	}
	err = conn.Call(handshake, "plugin.initialize", map[string]any{"protocol": plugin.ProcessProtocolV2, "plugin_id": pkg.Manifest.ID, "plugin_version": pkg.Manifest.Version, "package_digest": pkg.PackageDigest, "manifest_digest": pkg.ManifestDigest, "operation_id": op.ID, "inputs": op.Inputs, "outputs": op.Outputs, "max_message_bytes": 1 << 20, "max_chunk_bytes": 256 << 10, "max_output_bytes": inv.Request.Budget.MaxOutputBytes}, &response)
	done()
	if err != nil {
		return result, plugin.ErrProtocolViolation
	}
	if response.Protocol != plugin.ProcessProtocolV2 || response.PluginID != pkg.Manifest.ID || response.PluginVersion != pkg.Manifest.Version || response.PackageDigest != pkg.PackageDigest || response.ManifestDigest != pkg.ManifestDigest || len(response.Operations) != 1 || response.Operations[0] != op.ID || !reflect.DeepEqual(response.Inputs, op.Inputs) || !reflect.DeepEqual(response.Outputs, op.Outputs) {
		return result, plugin.ErrProtocolViolation
	}
	var accepted struct {
		Accepted     bool   `json:"accepted"`
		InvocationID string `json:"invocation_id"`
	}
	if err = conn.Call(ctx, "plugin.execute", inv.Request, &accepted); err != nil || !accepted.Accepted || accepted.InvocationID != inv.ID {
		return result, plugin.ErrProtocolViolation
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		var status jobResult
		if err = conn.Call(ctx, "plugin.status", map[string]string{"invocation_id": inv.ID}, &status); err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			return result, plugin.ErrProtocolViolation
		}
		state.mu.Lock()
		fatal := state.fatal
		state.mu.Unlock()
		if fatal != nil {
			return result, fatal
		}
		if status.InvocationID != inv.ID {
			return result, plugin.ErrProtocolViolation
		}
		if plugin.Terminal(status.Status) {
			if status.Status != "SUCCEEDED" && status.Status != "PARTIAL" {
				if status.Status == "UNSUPPORTED" {
					return result, plugin.ErrUnsupported
				}
				return result, &plugin.ExecutionError{Code: "tool_failed"}
			}
			state.mu.Lock()
			result = plugin.RawResult{Events: append([]plugin.StageEvent(nil), state.events...), Status: status.Status, Coverage: status.Coverage, Limitations: status.Limitations, Close: func() { _ = os.RemoveAll(directory) }}
			for _, id := range state.order {
				object, ok := state.objects[id]
				if !ok {
					continue
				}
				if !object.Finished {
					state.mu.Unlock()
					return plugin.RawResult{}, plugin.ErrProtocolViolation
				}
				path := object.Path
				media := object.Media
				if media == "" {
					media = "application/json"
					if object.Kind == "tool.native" {
						media = "application/octet-stream"
					}
				}
				result.Outputs = append(result.Outputs, plugin.RawOutput{Port: object.Port, Kind: object.Kind, SchemaID: object.Schema, Bytes: object.Size, SHA256: object.Digest, MediaType: media, Open: func() (io.ReadCloser, error) { return os.Open(path) }})
			}
			state.mu.Unlock()
			verified, err := plugin.LoadPackage(copy.Directory)
			if err != nil || verified.PackageDigest != pkg.PackageDigest {
				return plugin.RawResult{}, plugin.ErrConflict
			}
			keep = true
			return result, nil
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-ticker.C:
		}
	}
}
