package scanner

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
	"sync"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/plugin/rpc"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin/wire"
)

// Serve runs one process plugin until the host closes the transport. It is
// exported so an in-process test can exercise the same protocol as cmd/scanner.
func Serve(ctx context.Context, reader io.Reader, writer io.Writer) error {
	server := &Server{status: "IDLE"}
	conn := rpc.New(reader, writer, server.handle, rpc.Options{MaxMessageBytes: wire.MaxMessageBytes})
	server.conn = conn
	defer conn.Close()
	err := conn.Serve(ctx)
	if errors.Is(err, rpc.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// Main is the command entry point. Protocol errors go to stderr as a bounded
// message; stdout remains a pure NDJSON channel.
func Main() int {
	if err := Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "scanner: protocol transport closed")
		return 1
	}
	return 0
}

// Server is the protocol state machine of one scanner invocation.
type Server struct {
	conn *rpc.Conn

	mu             sync.Mutex
	initialized    bool
	maxReportBytes int64
	active         string
	cancel         context.CancelFunc
	status         string
	errorCode      string
	coverage       plugin.Coverage
	limitations    []string
	reportBytes    int64
	reportSHA256   string
	request        wire.ExecuteParams
}

func (s *Server) handle(_ context.Context, method string, params json.RawMessage) (any, *rpc.Error) {
	switch method {
	case wire.PluginInitialize:
		return s.initialize(params)
	case wire.PluginExecute:
		return s.execute(params)
	case wire.PluginStatus:
		return s.statusResult(params)
	case wire.PluginCancel:
		return s.cancelResult(params)
	default:
		return nil, &rpc.Error{Code: rpc.MethodNotFound, Message: "method not found"}
	}
}

func (s *Server) initialize(raw json.RawMessage) (any, *rpc.Error) {
	var request wire.InitializeParams
	if err := strictDecode(raw, &request); err != nil {
		return nil, invalid("invalid initialize parameters")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.initialized {
		return nil, invalid("handshake already completed")
	}
	if request.Protocol != wire.Protocol {
		return nil, &rpc.Error{Code: rpc.InvalidParams, Message: "incompatible protocol version"}
	}
	if !request.Host.ArtifactRead {
		return nil, &rpc.Error{Code: rpc.InvalidParams, Message: "host artifact reads are required"}
	}
	if request.MaxMessageBytes < 1024 || request.MaxReportBytes < 1 {
		return nil, invalid("host limits are too small")
	}
	if request.ManifestDigest != ManifestDigest() {
		return nil, &rpc.Error{Code: rpc.InvalidParams, Message: "manifest digest does not match this tool"}
	}
	maxReport := request.MaxReportBytes
	if maxReport > wire.MaxReportBytes {
		maxReport = wire.MaxReportBytes
	}
	s.initialized = true
	s.maxReportBytes = maxReport
	return wire.InitializeResult{
		Protocol:       wire.Protocol,
		PluginID:       ID,
		PluginVersion:  Version,
		ManifestDigest: request.ManifestDigest,
		Capabilities: wire.PluginCapabilities{
			Alerts:  true,
			Network: "none",
		},
		MaxReportBytes: maxReport,
	}, nil
}

func (s *Server) execute(raw json.RawMessage) (any, *rpc.Error) {
	var request wire.ExecuteParams
	if err := strictDecode(raw, &request); err != nil {
		return nil, invalid("invalid execute parameters")
	}
	if err := validateExecute(request); err != nil {
		return nil, invalid(err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		return nil, invalid("execute before initialize")
	}
	if s.active != "" {
		return nil, invalid("an invocation is already active")
	}
	runCtx, cancel := context.WithCancel(context.Background())
	s.active = request.InvocationID
	s.cancel = cancel
	s.request = request
	s.status = "RUNNING"
	s.errorCode = ""
	s.coverage = plugin.Coverage{}
	s.limitations = []string{}
	s.reportBytes = 0
	s.reportSHA256 = ""
	go s.run(runCtx, request)
	return wire.ExecuteResult{Accepted: true, InvocationID: request.InvocationID}, nil
}

func (s *Server) statusResult(raw json.RawMessage) (any, *rpc.Error) {
	var request wire.StatusParams
	if err := strictDecode(raw, &request); err != nil {
		return nil, invalid("invalid status parameters")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.InvocationID == "" || (s.request.InvocationID != "" && request.InvocationID != s.request.InvocationID) {
		return nil, invalid("unknown invocation")
	}
	return wire.StatusResult{
		InvocationID: s.request.InvocationID,
		Status:       s.status,
		ErrorCode:    s.errorCode,
		Coverage:     s.coverage,
		Limitations:  append([]string(nil), s.limitations...),
		ReportBytes:  s.reportBytes,
		ReportSHA256: s.reportSHA256,
	}, nil
}

func (s *Server) cancelResult(raw json.RawMessage) (any, *rpc.Error) {
	var request wire.CancelParams
	if err := strictDecode(raw, &request); err != nil {
		return nil, invalid("invalid cancel parameters")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == "" || request.InvocationID != s.active {
		return wire.CancelResult{Cancelled: false}, nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	return wire.CancelResult{Cancelled: true}, nil
}

func (s *Server) run(ctx context.Context, request wire.ExecuteParams) {
	seq := 0
	notify := func(kind string) {
		seq++
		_ = s.conn.Notify(wire.PluginEvent, wire.Event{
			InvocationID: request.InvocationID,
			Seq:          seq,
			Type:         kind,
		})
	}
	notify("started")
	archive, err := s.readSource(ctx, request)
	if err == nil {
		notify("source_read")
		var report wire.ScannerReport
		report, err = Scan(ctx, archive, request.Scope, request.Config, request.Budget)
		if err == nil {
			err = s.complete(ctx, request, report, seq+1)
			if err == nil {
				return
			}
		}
	}
	s.fail(ctx, err)
}

func (s *Server) readSource(ctx context.Context, request wire.ExecuteParams) ([]byte, error) {
	ref := request.Inputs[0]
	var source bytes.Buffer
	var offset int64
	for offset < ref.Bytes {
		length := int64(wire.MaxReadChunkBytes)
		if remaining := ref.Bytes - offset; remaining < length {
			length = remaining
		}
		var chunk wire.ReadArtifactResult
		if err := s.conn.Call(ctx, wire.HostReadArtifact, wire.ReadArtifactParams{
			InvocationID: request.InvocationID,
			ArtifactID:   ref.ID,
			Offset:       offset,
			Length:       length,
		}, &chunk); err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil || len(raw) == 0 || int64(len(raw)) > wire.MaxReadChunkBytes || chunk.Total != ref.Bytes {
			return nil, ErrInvalidArchive
		}
		if offset+int64(len(raw)) > ref.Bytes || offset+int64(len(raw)) > request.Budget.MaxInputBytes {
			return nil, ErrInvalidArchive
		}
		source.Write(raw)
		offset += int64(len(raw))
		if chunk.EOF {
			break
		}
	}
	if int64(source.Len()) != ref.Bytes || source.Len() == 0 {
		return nil, ErrInvalidArchive
	}
	sum := sha256.Sum256(source.Bytes())
	if hex.EncodeToString(sum[:]) != ref.SHA256 {
		return nil, ErrInvalidArchive
	}
	if int64(source.Len()) > request.Budget.MaxInputBytes {
		return nil, plugin.ErrBudget
	}
	return source.Bytes(), nil
}

func (s *Server) complete(ctx context.Context, request wire.ExecuteParams, report wire.ScannerReport, seq int) error {
	if report.Coverage.ParsedFiles == 0 {
		s.finish("UNSUPPORTED", "no_supported_files", report.Coverage, report.Limitations, nil)
		return nil
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if int64(len(raw)) > s.maxReportBytes || int64(len(raw)) > request.Budget.MaxOutputBytes {
		return plugin.ErrBudget
	}
	_ = s.conn.Notify(wire.PluginEvent, wire.Event{InvocationID: request.InvocationID, Seq: seq, Type: "scanned"})
	chunkSize := wire.MaxReadChunkBytes
	for offset, index := 0, 0; offset < len(raw); offset, index = offset+chunkSize, index+1 {
		end := offset + chunkSize
		if end > len(raw) {
			end = len(raw)
		}
		var accepted map[string]any
		if err := s.conn.Call(ctx, wire.PluginOutput, wire.OutputChunk{
			InvocationID: request.InvocationID,
			Index:        index,
			Data:         base64.StdEncoding.EncodeToString(raw[offset:end]),
			Final:        end == len(raw),
		}, &accepted); err != nil {
			return err
		}
	}
	status := "SUCCEEDED"
	if report.Coverage.Truncated {
		status = "PARTIAL"
	}
	sum := sha256.Sum256(raw)
	s.finish(status, "", report.Coverage, report.Limitations, &wire.StatusResult{
		InvocationID: request.InvocationID,
		Status:       status,
		ReportBytes:  int64(len(raw)),
		ReportSHA256: hex.EncodeToString(sum[:]),
	})
	return nil
}

func (s *Server) finish(status, code string, coverage plugin.Coverage, limitations []string, report *wire.StatusResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
	s.errorCode = code
	s.coverage = coverage
	s.limitations = append([]string{}, limitations...)
	s.active = ""
	s.cancel = nil
	if report != nil {
		s.reportBytes = report.ReportBytes
		s.reportSHA256 = report.ReportSHA256
	}
}

func (s *Server) fail(ctx context.Context, err error) {
	switch {
	case errors.Is(err, context.Canceled):
		s.finish("CANCELLED", "cancelled", s.currentCoverage(), s.currentLimitations(), nil)
	case errors.Is(err, context.DeadlineExceeded):
		s.finish("TIMED_OUT", "deadline", s.currentCoverage(), s.currentLimitations(), nil)
	case errors.Is(err, plugin.ErrBudget):
		s.finish("FAILED", "budget_exceeded", s.currentCoverage(), s.currentLimitations(), nil)
	case errors.Is(err, ErrInvalidArchive), errors.Is(err, ErrInvalidConfig):
		s.finish("FAILED", "invalid_input", s.currentCoverage(), s.currentLimitations(), nil)
	default:
		s.finish("FAILED", "scan_failed", s.currentCoverage(), s.currentLimitations(), nil)
	}
}

func (s *Server) currentCoverage() plugin.Coverage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.coverage
}

func (s *Server) currentLimitations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.limitations...)
}

func validateExecute(request wire.ExecuteParams) error {
	if !validInvocationID(request.InvocationID) {
		return errors.New("invocation id is invalid")
	}
	if request.PluginID != ID || request.PluginVersion != Version {
		return errors.New("plugin identity does not match this tool")
	}
	if request.PackageDigest == "" {
		return errors.New("package digest is required")
	}
	if request.Scope.ProjectID == "" || request.Scope.SourceID == "" || request.Scope.SnapshotID == "" {
		return errors.New("scope is incomplete")
	}
	if len(request.Inputs) != 1 {
		return errors.New("the scanner consumes exactly one source snapshot")
	}
	input := request.Inputs[0]
	if input.Kind != "source.snapshot" || input.SchemaID != "codexploit/source-tar/v1" || input.Scope != request.Scope || input.ID == "" || input.Bytes < 1 || len(input.SHA256) != 64 {
		return errors.New("the input is not a frozen source tar for this scope")
	}
	if request.Budget.MaxInputBytes < 1 || request.Budget.MaxOutputBytes < 1 || request.Budget.MaxFiles < 1 || request.Budget.MaxFileBytes < 1 || request.Budget.TimeoutSeconds < 1 {
		return errors.New("budget is incomplete")
	}
	if input.Bytes > request.Budget.MaxInputBytes {
		return errors.New("input exceeds the input budget")
	}
	if len(request.Config) > 64<<10 {
		return errors.New("config is too large")
	}
	return nil
}

func validInvocationID(id string) bool {
	if id == "" || len(id) > 120 {
		return false
	}
	for i, r := range id {
		alnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if i == 0 && !alnum {
			return false
		}
		if !alnum && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func strictDecode(raw json.RawMessage, value any) error {
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

func invalid(message string) *rpc.Error {
	return &rpc.Error{Code: rpc.InvalidParams, Message: message}
}
