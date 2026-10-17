package processplugin_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/plugin/rpc"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin/wire"
	"github.com/open-mcp-ai/Codexploit/internal/scanner"
)

// TestMain doubles as the subprocess entry point. It exits before the test
// harness can write its own output, so stdout stays a pure NDJSON channel.
func TestMain(m *testing.M) {
	if mode := os.Getenv("PROCESS_FIXTURE_MODE"); mode != "" {
		os.Exit(runFixture(mode))
	}
	os.Exit(m.Run())
}

const (
	fixtureID      = "codexploit.static-patterns"
	fixtureVersion = "1.0.0"
)

type fixtureState struct {
	mu          sync.Mutex
	mode        string
	status      string
	errorCode   string
	coverage    plugin.Coverage
	limitations []string
	report      []byte
	reportSHA   string
	execute     wire.ExecuteParams
	cancelled   chan struct{}
	cancelOnce  sync.Once
}

func runFixture(mode string) int {
	state := &fixtureState{mode: mode, status: "IDLE", cancelled: make(chan struct{})}
	var conn *rpc.Conn
	handler := func(_ context.Context, method string, params json.RawMessage) (any, *rpc.Error) {
		switch method {
		case wire.PluginInitialize:
			var request wire.InitializeParams
			if decodeFixture(params, &request) != nil {
				return nil, &rpc.Error{Code: rpc.InvalidParams, Message: "bad initialize"}
			}
			result := wire.InitializeResult{
				Protocol:       wire.Protocol,
				PluginID:       fixtureID,
				PluginVersion:  fixtureVersion,
				ManifestDigest: request.ManifestDigest,
				Capabilities:   wire.PluginCapabilities{Alerts: true, Network: "none"},
				MaxReportBytes: request.MaxReportBytes,
			}
			switch mode {
			case "wrongprotocol":
				result.Protocol = "codexploit/process-plugin/v0"
			case "dataflow":
				result.Capabilities.DataFlow = true
			}
			return result, nil
		case wire.PluginExecute:
			var request wire.ExecuteParams
			if decodeFixture(params, &request) != nil {
				return nil, &rpc.Error{Code: rpc.InvalidParams, Message: "bad execute"}
			}
			state.mu.Lock()
			state.execute = request
			state.status = "RUNNING"
			state.mu.Unlock()
			go runFixtureWork(conn, state)
			return wire.ExecuteResult{Accepted: true, InvocationID: request.InvocationID}, nil
		case wire.PluginStatus:
			var request wire.StatusParams
			if decodeFixture(params, &request) != nil {
				return nil, &rpc.Error{Code: rpc.InvalidParams, Message: "bad status"}
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			return wire.StatusResult{
				InvocationID: state.execute.InvocationID,
				Status:       state.status,
				ErrorCode:    state.errorCode,
				Coverage:     state.coverage,
				Limitations:  append([]string(nil), state.limitations...),
				ReportBytes:  int64(len(state.report)),
				ReportSHA256: state.reportSHA,
			}, nil
		case wire.PluginCancel:
			state.mu.Lock()
			state.status = "CANCELLED"
			state.mu.Unlock()
			state.cancelOnce.Do(func() { close(state.cancelled) })
			return wire.CancelResult{Cancelled: true}, nil
		default:
			return nil, &rpc.Error{Code: rpc.MethodNotFound, Message: "method not found"}
		}
	}
	conn = rpc.New(os.Stdin, os.Stdout, handler, rpc.Options{MaxMessageBytes: wire.MaxMessageBytes})
	if err := conn.Serve(context.Background()); err != nil {
		return 1
	}
	return 0
}

func runFixtureWork(conn *rpc.Conn, state *fixtureState) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state.mu.Lock()
	request := state.execute
	mode := state.mode
	state.mu.Unlock()
	if mode == "gap" {
		_ = conn.Notify(wire.PluginEvent, wire.Event{InvocationID: request.InvocationID, Seq: 1, Type: "started"})
		time.Sleep(50 * time.Millisecond)
		_ = conn.Notify(wire.PluginEvent, wire.Event{InvocationID: request.InvocationID, Seq: 3, Type: "skipped"})
		time.Sleep(time.Second)
		return
	}
	if mode == "oversize" {
		_, _ = os.Stdout.Write(append([]byte(strings.Repeat("x", 2<<20)), '\n'))
		time.Sleep(time.Second)
		return
	}
	if mode == "slow" {
		_ = conn.Notify(wire.PluginEvent, wire.Event{InvocationID: request.InvocationID, Seq: 1, Type: "started"})
		select {
		case <-state.cancelled:
		case <-time.After(3 * time.Second):
		}
		_ = conn.Notify(wire.PluginOutput, wire.OutputChunk{InvocationID: request.InvocationID, Index: 0, Data: base64.StdEncoding.EncodeToString([]byte("late")), Final: true})
		state.mu.Lock()
		state.status = "SUCCEEDED"
		state.report = []byte("late")
		state.reportSHA = fixtureDigest([]byte("late"))
		state.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		return
	}
	if mode == "badread" {
		var result wire.ReadArtifactResult
		err := conn.Call(ctx, wire.HostReadArtifact, wire.ReadArtifactParams{
			InvocationID: request.InvocationID,
			ArtifactID:   "artifact-not-bound",
			Offset:       0,
			Length:       1,
		}, &result)
		state.mu.Lock()
		state.status = "FAILED"
		if err != nil {
			state.errorCode = "invalid_read"
		} else {
			state.errorCode = "read_unexpectedly_succeeded"
		}
		state.mu.Unlock()
		return
	}
	if mode == "env" && os.Getenv("CODEXPLOIT_TEST_SECRET") != "" {
		state.mu.Lock()
		state.status = "FAILED"
		state.errorCode = "secret_leaked"
		state.mu.Unlock()
		return
	}

	_ = conn.Notify(wire.PluginEvent, wire.Event{InvocationID: request.InvocationID, Seq: 1, Type: "started"})
	var input []byte
	if len(request.Inputs) != 1 {
		state.fail("wrong input count")
		return
	}
	for offset := int64(0); ; {
		length := int64(4)
		if remaining := int64(10) - offset; remaining < length {
			length = remaining
		}
		var result wire.ReadArtifactResult
		if err := conn.Call(ctx, wire.HostReadArtifact, wire.ReadArtifactParams{
			InvocationID: request.InvocationID,
			ArtifactID:   request.Inputs[0].ID,
			Offset:       offset,
			Length:       length,
		}, &result); err != nil {
			state.fail("host read failed")
			return
		}
		raw, err := base64.StdEncoding.DecodeString(result.Data)
		if err != nil || result.Total != int64(10) {
			state.fail("invalid read response")
			return
		}
		input = append(input, raw...)
		offset += int64(len(raw))
		if result.EOF {
			break
		}
	}
	if expected := os.Getenv("PROCESS_FIXTURE_INPUT"); expected != "" && string(input) != expected {
		state.fail("read input mismatch")
		return
	}
	_ = conn.Notify(wire.PluginEvent, wire.Event{InvocationID: request.InvocationID, Seq: 2, Type: "scanned"})

	report := wire.ScannerReport{
		Format: wire.ScannerReportFormat,
		Scope:  request.Scope,
		Tool:   wire.ToolInfo{ID: fixtureID, Version: fixtureVersion, Ruleset: "fixture-rules-1"},
		Capabilities: wire.PluginCapabilities{
			Alerts: true, Network: "none",
		},
		Coverage: plugin.Coverage{InputFiles: 1, ParsedFiles: 1, InputBytes: 10},
		Limitations: []string{
			"Fixture reports alert locations only; it does not claim taint flow or exploitability",
		},
		Alerts: []wire.ScannerAlert{{
			ID:           "alert-1",
			RuleID:       "CP001",
			RuleVersion:  "1",
			Title:        "Command execution with a non-literal argument",
			SeverityHint: "high",
			File:         "main.go",
			Line:         7,
			EndLine:      7,
			Column:       2,
			Message:      "synthetic fixture alert",
			Evidence:     []string{"main.go:7"},
			Limitations:  []string{"Alert location only"},
		}},
	}
	if mode == "env" {
		report.Limitations = append(report.Limitations, "env_clean")
	}
	raw, err := json.Marshal(report)
	if err != nil {
		state.fail("marshal report")
		return
	}
	half := len(raw) / 2
	for index, chunk := range [][]byte{raw[:half], raw[half:]} {
		var accepted map[string]any
		if err := conn.Call(ctx, wire.PluginOutput, wire.OutputChunk{
			InvocationID: request.InvocationID,
			Index:        index,
			Data:         base64.StdEncoding.EncodeToString(chunk),
			Final:        index == 1,
		}, &accepted); err != nil {
			state.fail("output rejected")
			return
		}
	}
	state.mu.Lock()
	state.status = "SUCCEEDED"
	state.coverage = plugin.Coverage{InputFiles: 1, ParsedFiles: 1, InputBytes: 10}
	state.limitations = append([]string{}, report.Limitations...)
	state.report = raw
	state.reportSHA = fixtureDigest(raw)
	state.mu.Unlock()
	time.Sleep(500 * time.Millisecond)
}

func (s *fixtureState) fail(reason string) {
	s.mu.Lock()
	s.status = "FAILED"
	s.errorCode = "fixture_failed"
	s.mu.Unlock()
	_ = reason
}

func decodeFixture(raw json.RawMessage, value any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func fixtureDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func newFixtureAdapter(t *testing.T, mode string) processplugin.Adapter {
	t.Helper()
	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	return processplugin.Adapter{
		Executable:       executable,
		Directory:        t.TempDir(),
		Env:              []string{"PROCESS_FIXTURE_MODE=" + mode, "PROCESS_FIXTURE_INPUT=0123456789"},
		Manifest:         fixtureManifest(),
		ManifestDigest:   strings.Repeat("a", 64),
		PackageDigest:    strings.Repeat("b", 64),
		ExecutableSHA256: fixtureDigest(raw),
		ExecutableBytes:  int64(len(raw)),
	}
}

func fixtureManifest() plugin.Manifest {
	return plugin.Manifest{
		APIVersion:  "codexploit/v1",
		ID:          fixtureID,
		Version:     fixtureVersion,
		Name:        "Fixture scanner",
		Description: "Fixture process.",
		Kind:        "analyzer",
		Languages:   []string{"Go"},
		Runtime: struct {
			Kind       string `json:"kind"`
			Entrypoint string `json:"entrypoint,omitempty"`
		}{Kind: "process", Entrypoint: "fixture"},
		Consumes: []string{"source.snapshot"},
		Produces: []string{"scanner.alerts"},
		Permissions: struct {
			Network     string `json:"network"`
			SourceWrite bool   `json:"source_write"`
		}{Network: "none", SourceWrite: false},
	}
}

func fixtureInvocation() plugin.Invocation {
	scope := artifact.Scope{ProjectID: "project-scanner", SourceID: "source-scanner", SnapshotID: "snap-22222222222222222222222222222222"}
	return plugin.Invocation{
		ID: "inv-process-fixture",
		Request: plugin.Request{
			APIVersion:    "codexploit/v1",
			ID:            "inv-process-fixture",
			PluginID:      fixtureID,
			PluginVersion: fixtureVersion,
			PackageDigest: strings.Repeat("b", 64),
			Scope:         scope,
			Inputs: []artifact.Ref{{
				ID:        "artifact-source",
				Kind:      "source.snapshot",
				Scope:     scope,
				SHA256:    strings.Repeat("0", 64),
				Bytes:     10,
				MediaType: "application/x-tar",
				SchemaID:  "codexploit/source-tar/v1",
				Producer: artifact.Producer{
					PluginID:      "builtin.snapshot",
					PluginVersion: "1.0.0",
					InvocationID:  "inv-snapshot",
					ConfigDigest:  strings.Repeat("d", 64),
				},
			}},
			Config: json.RawMessage(`{}`),
			Budget: plugin.Budget{MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20, MaxFiles: 10, MaxFileBytes: 1024, MaxASTNodes: 1000, TimeoutSeconds: 10},
		},
		ConfigDigest: strings.Repeat("c", 64),
	}
}

func TestAdapterRunsHandshakeReadsEventsAndReport(t *testing.T) {
	adapter := newFixtureAdapter(t, "ok")
	var events []wire.Event
	adapter.OnEvent = func(event wire.Event) { events = append(events, event) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := adapter.Run(ctx, fixtureInvocation(), [][]byte{[]byte("0123456789")})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var report wire.ScannerReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("report: %v", err)
	}
	if report.Format != wire.ScannerReportFormat || len(report.Alerts) != 1 || report.Alerts[0].RuleID != "CP001" || report.Scope != fixtureInvocation().Request.Scope {
		t.Fatalf("report = %+v", report)
	}
	if len(events) != 2 || events[0].Seq != 1 || events[1].Seq != 2 || events[0].Type != "started" {
		t.Fatalf("events = %+v", events)
	}
}

func TestAdapterRejectsProtocolAndCapabilityProblems(t *testing.T) {
	for _, test := range []struct {
		mode string
		want error
	}{
		{mode: "gap", want: plugin.ErrProtocolViolation},
		{mode: "oversize", want: plugin.ErrBudget},
		{mode: "wrongprotocol", want: plugin.ErrUnsupported},
		{mode: "dataflow", want: plugin.ErrUnsupported},
	} {
		t.Run(test.mode, func(t *testing.T) {
			adapter := newFixtureAdapter(t, test.mode)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := adapter.Run(ctx, fixtureInvocation(), [][]byte{[]byte("0123456789")}); !errors.Is(err, test.want) {
				t.Fatalf("Run = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAdapterServesOnlyBoundInputs(t *testing.T) {
	adapter := newFixtureAdapter(t, "badread")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := adapter.Run(ctx, fixtureInvocation(), [][]byte{[]byte("0123456789")})
	var execution *plugin.ExecutionError
	if !errors.Is(err, plugin.ErrExecutionFailed) || !errors.As(err, &execution) || execution.Code != "invalid_read" {
		t.Fatalf("Run = %v", err)
	}
}

func TestAdapterDoesNotLeakTheHostEnvironment(t *testing.T) {
	t.Setenv("CODEXPLOIT_TEST_SECRET", "host-only-secret")
	adapter := newFixtureAdapter(t, "env")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := adapter.Run(ctx, fixtureInvocation(), [][]byte{[]byte("0123456789")})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var report wire.ScannerReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, limitation := range report.Limitations {
		if limitation == "env_clean" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fixture did not observe a clean environment: %+v", report.Limitations)
	}
}

func TestAdapterCancellationReturnsNoLateReport(t *testing.T) {
	adapter := newFixtureAdapter(t, "slow")
	started := make(chan struct{}, 1)
	adapter.OnEvent = func(event wire.Event) {
		if event.Seq == 1 {
			select {
			case started <- struct{}{}:
			default:
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := adapter.Run(ctx, fixtureInvocation(), [][]byte{[]byte("0123456789")})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("adapter did not stop after cancellation")
	}
}

func TestAdapterRejectsUnenforceableRestrictedNetworkBeforeSpawning(t *testing.T) {
	adapter := newFixtureAdapter(t, "ok")
	adapter.Executable = filepath.Join(t.TempDir(), "does-not-exist")
	adapter.Manifest.Permissions.Network = "restricted"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := adapter.Run(ctx, fixtureInvocation(), [][]byte{[]byte("0123456789")}); !errors.Is(err, plugin.ErrUnsupported) {
		t.Fatalf("Run = %v, want ErrUnsupported", err)
	}
}

func TestAdapterRejectsATamperedPackageExecutable(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "codexploit.static-patterns@1.0.0")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), scanner.Manifest(), 0o600); err != nil {
		t.Fatal(err)
	}
	name := "scanner"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(directory, name)
	raw, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	executors, err := processplugin.Executors(root)
	if err != nil || len(executors) != 1 {
		t.Fatalf("Executors = %+v %v", executors, err)
	}
	if err := os.WriteFile(binary, append(raw, 'x'), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := executors[0].Run(ctx, fixtureInvocation(), [][]byte{[]byte("0123456789")}); !errors.Is(err, plugin.ErrUnsupported) {
		t.Fatalf("tampered executable = %v, want ErrUnsupported", err)
	}
}
