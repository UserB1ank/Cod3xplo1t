// Package processplugin executes a versioned plugin package as a separate
// process over the bounded NDJSON JSON-RPC transport.
package processplugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/plugin/rpc"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin/wire"
)

const (
	handshakeTimeout = 5 * time.Second
	statusInterval   = 10 * time.Millisecond
	cancelGrace      = 300 * time.Millisecond
	exitGrace        = 2 * time.Second
	maxStderrBytes   = 8 << 10
)

var (
	// ErrInvalidRead is returned when a plugin asks the host for bytes outside
	// the inputs bound to its invocation.
	ErrInvalidRead = errors.New("processplugin: invalid host artifact read")
)

// Adapter is one installed process package. It never interprets manifest
// entrypoints through a shell.
type Adapter struct {
	Executable       string
	Directory        string
	Args             []string
	Env              []string
	Manifest         plugin.Manifest
	ManifestDigest   string
	PackageDigest    string
	ExecutableSHA256 string
	ExecutableBytes  int64
	// OnEvent observes validated, ordered events. It must not block.
	OnEvent func(wire.Event)
}

type invokeState struct {
	mu       sync.Mutex
	events   int
	chunks   int
	report   bytes.Buffer
	final    bool
	fatal    error
	failed   chan struct{}
	failOnce sync.Once
}

func newInvokeState() *invokeState {
	return &invokeState{failed: make(chan struct{})}
}

func (s *invokeState) fail(err error) {
	s.failOnce.Do(func() {
		s.mu.Lock()
		s.fatal = err
		s.mu.Unlock()
		close(s.failed)
	})
}

// Run starts one invocation, completes the handshake, serves bounded host
// reads and returns the raw native report. It never returns late output after
// the context is cancelled.
func (a Adapter) Run(ctx context.Context, inv plugin.Invocation, inputs [][]byte) ([]byte, error) {
	if a.Manifest.Runtime.Kind != "process" || a.Manifest.Permissions.SourceWrite || a.Manifest.Permissions.Network != "none" {
		return nil, plugin.ErrUnsupported
	}
	if a.Executable == "" || !a.executableIntact() {
		return nil, plugin.ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	command := exec.Command(a.Executable, a.Args...)
	command.Dir = a.Directory
	command.Env = a.environment()
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, plugin.ErrUnsupported
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, plugin.ErrUnsupported
	}
	stderr := &boundedBuffer{limit: maxStderrBytes}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, &plugin.ExecutionError{Code: "spawn_failed"}
	}
	defer func() {
		_ = stdin.Close()
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	}()

	state := newInvokeState()
	conn := rpc.New(stdout, stdin, a.handler(inv, inputs, state), rpc.Options{MaxMessageBytes: wire.MaxMessageBytes})
	defer conn.Close()
	serve := make(chan error, 1)
	go func() { serve <- conn.Serve(ctx) }()

	handshake, cancel := context.WithTimeout(ctx, handshakeTimeout)
	var initialized wire.InitializeResult
	err = conn.Call(handshake, wire.PluginInitialize, a.initializeParams(), &initialized)
	cancel()
	if err != nil {
		var rejected *rpc.Error
		if errors.As(err, &rejected) {
			return nil, fmt.Errorf("%w: handshake rejected", plugin.ErrUnsupported)
		}
		return nil, a.mapTransportError(ctx, err)
	}
	if err := a.validateHandshake(initialized); err != nil {
		return nil, err
	}

	var accepted wire.ExecuteResult
	if err := conn.Call(ctx, wire.PluginExecute, wire.ExecuteParams{
		InvocationID:  inv.ID,
		PluginID:      inv.Request.PluginID,
		PluginVersion: inv.Request.PluginVersion,
		PackageDigest: inv.Request.PackageDigest,
		Scope:         inv.Request.Scope,
		Inputs:        inv.Request.Inputs,
		Config:        inv.Request.Config,
		Budget:        inv.Request.Budget,
	}, &accepted); err != nil {
		return nil, a.mapTransportError(ctx, err)
	}
	if !accepted.Accepted || accepted.InvocationID != inv.ID {
		return nil, fmt.Errorf("%w: execute was not accepted", plugin.ErrProtocolViolation)
	}

	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()
	for {
		var status wire.StatusResult
		callCtx, callCancel := context.WithTimeout(ctx, handshakeTimeout)
		err := conn.Call(callCtx, wire.PluginStatus, wire.StatusParams{InvocationID: inv.ID}, &status)
		callCancel()
		if err == nil && plugin.Terminal(status.Status) {
			return a.finish(ctx, command, stdin, state, status)
		}
		if err != nil {
			if ctx.Err() != nil {
				a.cancel(command, stdin, conn, inv.ID)
				return nil, ctx.Err()
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				return nil, a.mapTransportError(ctx, err)
			}
		}
		select {
		case <-ctx.Done():
			a.cancel(command, stdin, conn, inv.ID)
			return nil, ctx.Err()
		case <-state.failed:
			state.mu.Lock()
			failure := state.fatal
			state.mu.Unlock()
			return nil, failure
		case serveErr := <-serve:
			if !errors.Is(serveErr, rpc.ErrClosed) && !errors.Is(serveErr, io.EOF) {
				return nil, a.mapTransportError(ctx, serveErr)
			}
			// The process may have sent its terminal status and exited before the
			// next poll. Give the persisted status one last read.
			var final wire.StatusResult
			lastCtx, lastCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			lastErr := conn.Call(lastCtx, wire.PluginStatus, wire.StatusParams{InvocationID: inv.ID}, &final)
			lastCancel()
			if lastErr == nil && plugin.Terminal(final.Status) {
				return a.finish(ctx, command, stdin, state, final)
			}
			return nil, fmt.Errorf("%w: process exited before a terminal status", plugin.ErrProtocolViolation)
		case <-ticker.C:
		}
	}
}

func (a Adapter) executableIntact() bool {
	info, err := os.Lstat(a.Executable)
	if err != nil || !info.Mode().IsRegular() || info.Size() != a.ExecutableBytes {
		return false
	}
	file, err := os.Open(a.Executable)
	if err != nil {
		return false
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.CopyN(hasher, file, a.ExecutableBytes); err != nil {
		return false
	}
	return hex.EncodeToString(hasher.Sum(nil)) == a.ExecutableSHA256
}

func (a Adapter) initializeParams() wire.InitializeParams {
	return wire.InitializeParams{
		Protocol:        wire.Protocol,
		ManifestDigest:  a.ManifestDigest,
		PackageDigest:   a.PackageDigest,
		Host:            wire.HostCapabilities{ArtifactRead: true},
		MaxMessageBytes: wire.MaxMessageBytes,
		MaxReportBytes:  wire.MaxReportBytes,
	}
}

func (a Adapter) validateHandshake(result wire.InitializeResult) error {
	if result.Protocol != wire.Protocol {
		return fmt.Errorf("%w: incompatible handshake protocol", plugin.ErrUnsupported)
	}
	if result.PluginID != a.Manifest.ID || result.PluginVersion != a.Manifest.Version || result.ManifestDigest != a.ManifestDigest {
		return fmt.Errorf("%w: handshake identity does not match the installed package", plugin.ErrProtocolViolation)
	}
	if !result.Capabilities.Alerts || result.Capabilities.Network != "none" || result.Capabilities.DataFlow || result.Capabilities.CallReachability {
		return fmt.Errorf("%w: the process adapter cannot enforce the advertised capability", plugin.ErrUnsupported)
	}
	if result.MaxReportBytes < 1 || result.MaxReportBytes > wire.MaxReportBytes {
		return fmt.Errorf("%w: invalid report ceiling", plugin.ErrProtocolViolation)
	}
	return nil
}

func (a Adapter) finish(ctx context.Context, command *exec.Cmd, stdin io.WriteCloser, state *invokeState, status wire.StatusResult) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		a.cancel(command, stdin, nil, status.InvocationID)
		return nil, err
	}
	switch status.Status {
	case "SUCCEEDED", "PARTIAL":
		state.mu.Lock()
		raw := append([]byte(nil), state.report.Bytes()...)
		final := state.final
		state.mu.Unlock()
		if !final || int64(len(raw)) != status.ReportBytes || len(raw) == 0 || status.ReportSHA256 != digest(raw) {
			return nil, fmt.Errorf("%w: report bytes do not match the terminal status", plugin.ErrProtocolViolation)
		}
		a.release(command, stdin)
		return raw, nil
	case "UNSUPPORTED":
		a.release(command, stdin)
		return nil, plugin.ErrUnsupported
	case "CANCELLED":
		a.release(command, stdin)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, context.Canceled
	case "TIMED_OUT":
		a.release(command, stdin)
		return nil, context.DeadlineExceeded
	case "FAILED":
		a.release(command, stdin)
		code := status.ErrorCode
		if code == "" {
			code = "execution_failed"
		}
		if !validCode(code) {
			code = "execution_failed"
		}
		return nil, &plugin.ExecutionError{Code: code}
	default:
		return nil, fmt.Errorf("%w: terminal status %q", plugin.ErrProtocolViolation, status.Status)
	}
}

func (a Adapter) cancel(command *exec.Cmd, stdin io.WriteCloser, conn *rpc.Conn, id string) {
	if conn != nil {
		cancelCtx, cancel := context.WithTimeout(context.Background(), cancelGrace)
		_ = conn.Call(cancelCtx, wire.PluginCancel, wire.CancelParams{InvocationID: id}, nil)
		cancel()
	}
	_ = stdin.Close()
	if command != nil && command.Process != nil {
		timer := time.AfterFunc(cancelGrace, func() { _ = command.Process.Kill() })
		_ = command.Wait()
		timer.Stop()
	}
}

func (a Adapter) release(command *exec.Cmd, stdin io.WriteCloser) {
	_ = stdin.Close()
	if command == nil || command.Process == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(exitGrace):
		_ = command.Process.Kill()
		<-done
	}
}

func (a Adapter) handler(inv plugin.Invocation, inputs [][]byte, state *invokeState) rpc.Handler {
	return func(_ context.Context, method string, params json.RawMessage) (any, *rpc.Error) {
		switch method {
		case wire.PluginEvent:
			var event wire.Event
			if err := decodeParams(params, &event); err != nil || event.InvocationID != inv.ID || event.Type == "" || len(event.Type) > 64 || len(event.Message) > 1024 {
				return nil, invalidParams("invalid event")
			}
			state.mu.Lock()
			expected := state.events + 1
			if event.Seq != expected {
				state.mu.Unlock()
				err := fmt.Errorf("%w: event seq %d, want %d", plugin.ErrProtocolViolation, event.Seq, expected)
				state.fail(err)
				return nil, invalidParams("event sequence gap or duplicate")
			}
			state.events = event.Seq
			state.mu.Unlock()
			if a.OnEvent != nil {
				a.OnEvent(event)
			}
			return map[string]any{"accepted": true}, nil
		case wire.PluginOutput:
			var chunk wire.OutputChunk
			if err := decodeParams(params, &chunk); err != nil || chunk.InvocationID != inv.ID {
				return nil, invalidParams("invalid output chunk")
			}
			if err := state.appendChunk(chunk, inv.Request.Budget.MaxOutputBytes); err != nil {
				state.fail(err)
				return nil, invalidParams("output chunk violates the report contract")
			}
			return map[string]any{"accepted": true}, nil
		case wire.HostReadArtifact:
			var request wire.ReadArtifactParams
			if err := decodeParams(params, &request); err != nil {
				return nil, invalidParams("invalid artifact read")
			}
			result, err := readInvocationInput(inv, inputs, request)
			if err != nil {
				return nil, invalidParams(err.Error())
			}
			return result, nil
		default:
			return nil, &rpc.Error{Code: rpc.MethodNotFound, Message: "method not found"}
		}
	}
}

func (s *invokeState) appendChunk(chunk wire.OutputChunk, budget int64) error {
	raw, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil || len(raw) == 0 || len(raw) > wire.MaxReadChunkBytes {
		return fmt.Errorf("%w: invalid output chunk", plugin.ErrProtocolViolation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.final {
		return fmt.Errorf("%w: output after final chunk", plugin.ErrProtocolViolation)
	}
	if chunk.Index != s.chunks {
		return fmt.Errorf("%w: output chunk %d, want %d", plugin.ErrProtocolViolation, chunk.Index, s.chunks)
	}
	if int64(s.report.Len()+len(raw)) > budget || int64(s.report.Len()+len(raw)) > wire.MaxReportBytes {
		return plugin.ErrBudget
	}
	s.report.Write(raw)
	s.chunks++
	s.final = chunk.Final
	return nil
}

func readInvocationInput(inv plugin.Invocation, inputs [][]byte, request wire.ReadArtifactParams) (wire.ReadArtifactResult, error) {
	if request.InvocationID != inv.ID {
		return wire.ReadArtifactResult{}, ErrInvalidRead
	}
	if request.Offset < 0 || request.Length < 1 || request.Length > wire.MaxReadChunkBytes {
		return wire.ReadArtifactResult{}, ErrInvalidRead
	}
	for i, ref := range inv.Request.Inputs {
		if ref.ID != request.ArtifactID || i >= len(inputs) {
			continue
		}
		data := inputs[i]
		if request.Offset > int64(len(data)) || request.Offset+request.Length > int64(len(data)) {
			return wire.ReadArtifactResult{}, ErrInvalidRead
		}
		end := request.Offset + request.Length
		return wire.ReadArtifactResult{
			Data:  base64.StdEncoding.EncodeToString(data[request.Offset:end]),
			EOF:   end == int64(len(data)),
			Total: int64(len(data)),
		}, nil
	}
	return wire.ReadArtifactResult{}, ErrInvalidRead
}

func (a Adapter) mapTransportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, rpc.ErrMessageTooLarge):
		return plugin.ErrBudget
	case errors.Is(err, plugin.ErrBudget), errors.Is(err, plugin.ErrProtocolViolation), errors.Is(err, plugin.ErrUnsupported):
		return err
	case errors.Is(err, rpc.ErrProtocol), errors.Is(err, rpc.ErrClosed):
		return fmt.Errorf("%w: %v", plugin.ErrProtocolViolation, err)
	default:
		return &plugin.ExecutionError{Code: "protocol_transport"}
	}
}

func decodeParams(raw json.RawMessage, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func invalidParams(message string) *rpc.Error {
	return &rpc.Error{Code: rpc.InvalidParams, Message: message}
}

func (a Adapter) environment() []string {
	var env []string
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SystemRoot", "WINDIR"} {
		if value, ok := os.LookupEnv(key); ok && value != "" {
			env = append(env, key+"="+value)
		}
	}
	for _, entry := range a.Env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.HasPrefix(key, "CODEXPLOIT_") || strings.HasPrefix(key, "PROCESS_FIXTURE_SECRET") {
			continue
		}
		env = append(env, entry)
	}
	return env
}

func validCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, r := range code {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

type boundedBuffer struct {
	limit int
	data  bytes.Buffer
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.data.Len() < b.limit {
		remaining := b.limit - b.data.Len()
		if len(p) > remaining {
			b.data.Write(p[:remaining])
		} else {
			b.data.Write(p)
		}
	}
	return len(p), nil
}
