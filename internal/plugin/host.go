package plugin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

var ErrBudget = errors.New("plugin: execution budget exceeded")

type Budget struct {
	MaxInputBytes  int64 `json:"max_input_bytes"`
	MaxOutputBytes int64 `json:"max_output_bytes"`
	MaxFiles       int   `json:"max_files"`
	MaxFileBytes   int64 `json:"max_file_bytes"`
	MaxASTNodes    int   `json:"max_ast_nodes"`
	TimeoutSeconds int   `json:"timeout_seconds"`
}

func (b Budget) defaults() (Budget, error) {
	if b.MaxInputBytes == 0 {
		b.MaxInputBytes = 64 << 20
	}
	if b.MaxOutputBytes == 0 {
		b.MaxOutputBytes = 16 << 20
	}
	if b.MaxFiles == 0 {
		b.MaxFiles = 2000
	}
	if b.MaxFileBytes == 0 {
		b.MaxFileBytes = 1 << 20
	}
	if b.MaxASTNodes == 0 {
		b.MaxASTNodes = 100000
	}
	if b.TimeoutSeconds == 0 {
		b.TimeoutSeconds = 60
	}
	if b.MaxInputBytes < 1 || b.MaxInputBytes > 256<<20 || b.MaxOutputBytes < 1 || b.MaxOutputBytes > 64<<20 || b.MaxFiles < 1 || b.MaxFiles > 20000 || b.MaxFileBytes < 1 || b.MaxFileBytes > 4<<20 || b.MaxASTNodes < 1 || b.MaxASTNodes > 500000 || b.TimeoutSeconds < 1 || b.TimeoutSeconds > 120 {
		return Budget{}, ErrInvalid
	}
	return b, nil
}

type Request struct {
	APIVersion    string          `json:"api_version"`
	ID            string          `json:"invocation_id,omitempty"`
	PluginID      string          `json:"plugin_id"`
	PluginVersion string          `json:"plugin_version"`
	PackageDigest string          `json:"package_digest"`
	Scope         artifact.Scope  `json:"scope"`
	Inputs        []artifact.Ref  `json:"inputs"`
	Config        json.RawMessage `json:"config"`
	Budget        Budget          `json:"budget"`
}
type Coverage struct {
	Truncated       bool  `json:"truncated,omitempty"`
	DescriptorFiles int   `json:"descriptor_files"`
	InputFiles      int   `json:"input_files"`
	ParsedFiles     int   `json:"parsed_files"`
	PartialFiles    int   `json:"partial_files"`
	UnparsedFiles   int   `json:"unparsed_files"`
	UnhandledFiles  int   `json:"unhandled_files"`
	InputBytes      int64 `json:"input_bytes"`
}
type Invocation struct {
	Analysis      *AnalysisResult `json:"analysis,omitempty"`
	ID            string          `json:"invocation_id"`
	Request       Request         `json:"request"`
	RequestDigest string          `json:"request_digest"`
	ConfigDigest  string          `json:"config_digest"`
	Status        string          `json:"status"`
	Version       int64           `json:"version"`
	Outputs       []artifact.Ref  `json:"outputs"`
	Coverage      Coverage        `json:"coverage"`
	Limitations   []string        `json:"limitations"`
	ErrorCode     string          `json:"error_code,omitempty"`
	CreatedAt     string          `json:"created_at"`
	UpdatedAt     string          `json:"updated_at"`
}

func Terminal(status string) bool {
	return status == "SUCCEEDED" || status == "PARTIAL" || status == "FAILED" || status == "CANCELLED" || status == "TIMED_OUT" || status == "UNSUPPORTED"
}
func ValidTransition(from, to string) bool {
	return !Terminal(from) && ((from == "CREATED" && to == "RUNNING") || Terminal(to))
}

type Repository interface {
	RecoverInvocations(context.Context) error
	CreateInvocation(context.Context, Invocation) (Invocation, bool, error)
	SaveInvocation(context.Context, Invocation, int64) error
	GetInvocation(context.Context, artifact.Scope, string) (Invocation, error)
	ListInvocations(context.Context, artifact.Scope, string, int) ([]Invocation, error)
}
type ArtifactStore interface {
	artifact.Store
	Prepare(context.Context, artifact.Ref, io.Reader, int64) (artifact.Ref, error)
}
type Scopes interface {
	ArtifactScope(context.Context, string, string) (artifact.Scope, error)
}
type Deps struct {
	Catalog    *Catalog
	Repository Repository
	Artifacts  ArtifactStore
	Scopes     Scopes
	Executors  []Executor
}
type Host struct {
	executors map[string]Executor
	deps      Deps
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	active    map[string]context.CancelFunc
	wg        sync.WaitGroup
	closed    bool
}

func NewHost(deps Deps) (*Host, error) {
	if deps.Catalog == nil || deps.Repository == nil || deps.Artifacts == nil || deps.Scopes == nil {
		return nil, ErrInvalid
	}
	executors := map[string]Executor{}
	for _, executor := range deps.Executors {
		if executor.Run == nil || len(executor.InputSchemas) == 0 {
			return nil, ErrInvalid
		}
		if err := deps.Catalog.install(context.Background(), executor.Manifest, executor.PackageDigest); err != nil {
			return nil, err
		}
		var manifest Manifest
		_ = json.Unmarshal(executor.Manifest, &manifest)
		executors[manifest.ID+"@"+manifest.Version] = executor
	}
	recoverCtx, done := context.WithTimeout(context.Background(), 15*time.Second)
	defer done()
	if err := deps.Repository.RecoverInvocations(recoverCtx); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Host{deps: deps, executors: executors, ctx: ctx, cancel: cancel, active: map[string]context.CancelFunc{}}, nil
}

func (h *Host) Execute(ctx context.Context, request Request) (Invocation, error) {
	if request.APIVersion != "codexploit/v1" {
		return Invocation{}, ErrInvalid
	}
	entry, err := h.deps.Catalog.Get(ctx, request.PluginID, request.PluginVersion)
	if err != nil {
		return Invocation{}, err
	}
	if !entry.Executable {
		return Invocation{}, ErrUnsupported
	}
	if entry.PackageDigest != request.PackageDigest {
		return Invocation{}, ErrConflict
	}
	scope, err := h.deps.Scopes.ArtifactScope(ctx, request.Scope.ProjectID, request.Scope.SnapshotID)
	if err != nil {
		return Invocation{}, ErrNotFound
	}
	if scope != request.Scope {
		return Invocation{}, ErrNotFound
	}
	request.Budget, err = request.Budget.defaults()
	if err != nil {
		return Invocation{}, err
	}
	if len(request.Config) == 0 {
		request.Config = json.RawMessage(`{}`)
	}
	var config any
	if json.Unmarshal(request.Config, &config) != nil {
		return Invocation{}, ErrInvalid
	}
	schema, err := resolveConfig(entry.Manifest.ConfigSchema)
	if err != nil || schema.Validate(config) != nil {
		return Invocation{}, ErrInvalid
	}
	request.Config, _ = json.Marshal(config)
	if err := h.validateInputs(ctx, request); err != nil {
		return Invocation{}, err
	}
	if request.ID == "" {
		request.ID = "inv-" + rand.Text()
	}
	if len(request.ID) > 120 {
		return Invocation{}, ErrInvalid
	}
	first := request.ID[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return Invocation{}, ErrInvalid
	}
	for _, r := range request.ID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return Invocation{}, ErrInvalid
		}
	}
	raw, _ := json.Marshal(request)
	var detached Request
	if err := json.Unmarshal(raw, &detached); err != nil {
		return Invocation{}, ErrInvalid
	}
	request = detached
	now := time.Now().UTC().Format(time.RFC3339Nano)
	inv := Invocation{ID: request.ID, Request: request, RequestDigest: digest(raw), ConfigDigest: digest(request.Config), Status: "CREATED", Version: 1, Outputs: []artifact.Ref{}, Limitations: []string{"Go syntax only; no type checking, dependency execution or vulnerability verdicts"}, CreatedAt: now, UpdatedAt: now}
	if request.PluginID != BuiltinID {
		inv.Limitations = []string{"Static analysis observations are candidates; no taint flow or exploitability is established"}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return Invocation{}, ErrUnsupported
	}
	prior, lookupErr := h.deps.Repository.GetInvocation(ctx, request.Scope, request.ID)
	if lookupErr == nil {
		if prior.RequestDigest != inv.RequestDigest {
			return Invocation{}, ErrConflict
		}
		return prior, nil
	}
	if !errors.Is(lookupErr, ErrNotFound) {
		return Invocation{}, lookupErr
	}
	if len(h.active) >= 2 {
		return Invocation{}, ErrBudget
	}
	stored, created, err := h.deps.Repository.CreateInvocation(ctx, inv)
	if err != nil || !created {
		return stored, err
	}
	runCtx, cancel := context.WithTimeout(h.ctx, time.Duration(request.Budget.TimeoutSeconds)*time.Second)
	h.active[inv.ID] = cancel
	h.wg.Add(1)
	workerRaw, _ := json.Marshal(inv)
	var workerInvocation Invocation
	_ = json.Unmarshal(workerRaw, &workerInvocation)
	go h.run(runCtx, cancel, workerInvocation)
	return stored, nil
}

func (h *Host) run(ctx context.Context, cancel context.CancelFunc, inv Invocation) {
	defer h.wg.Done()
	defer cancel()
	defer func() { h.mu.Lock(); delete(h.active, inv.ID); h.mu.Unlock() }()
	inv.Status = "RUNNING"
	inv.Version++
	inv.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if h.deps.Repository.SaveInvocation(ctx, inv, 1) != nil {
		return
	}
	var outputs []artifact.Ref
	var coverage Coverage
	var limitations []string
	var err error
	if inv.Request.PluginID == BuiltinID {
		outputs, coverage, limitations, err = h.parse(ctx, inv)
	} else {
		outputs, coverage, limitations, err = h.analyze(ctx, inv)
	}
	inv.Coverage = coverage
	inv.Limitations = append(inv.Limitations, limitations...)
	inv.Status = "SUCCEEDED"
	if coverage.Truncated || coverage.PartialFiles+coverage.UnparsedFiles+coverage.UnhandledFiles > 0 {
		inv.Status = "PARTIAL"
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		inv.Status = "FAILED"
		inv.ErrorCode = "parse_failed"
		switch {
		case errors.Is(err, context.Canceled):
			inv.Status = "CANCELLED"
			inv.ErrorCode = "cancelled"
		case errors.Is(err, context.DeadlineExceeded):
			inv.Status = "TIMED_OUT"
			inv.ErrorCode = "deadline"
		case errors.Is(err, ErrBudget), errors.Is(err, artifact.ErrBudget):
			inv.ErrorCode = "budget_exceeded"
		case errors.Is(err, artifact.ErrIntegrity), errors.Is(err, ErrInvalid):
			inv.ErrorCode = "invalid_input"
		}
		inv.Outputs = []artifact.Ref{}
		if errors.Is(err, ErrNormalization) || errors.Is(err, ErrReportVersion) {
			inv.Outputs = outputs
			inv.ErrorCode = "normalization_failed"
			if errors.Is(err, ErrReportVersion) {
				inv.Status = "UNSUPPORTED"
				inv.ErrorCode = "unsupported_report_version"
			}
		}
	} else if coverage.ParsedFiles+coverage.PartialFiles+coverage.UnparsedFiles == 0 {
		inv.Status = "UNSUPPORTED"
		inv.ErrorCode = "no_supported_files"
		inv.Outputs = []artifact.Ref{}
	} else {
		inv.Outputs = outputs
	}
	inv.Version++
	inv.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	commitCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	if inv.Request.PluginID != BuiltinID {
		inv.Analysis = analysisResult(inv)
	}
	defer done()
	_ = h.deps.Repository.SaveInvocation(commitCtx, inv, 2)
}

// PublishableOutput permits failed normalization to retain only its raw report.
// Budget failures, cancellation and interrupted invocations publish no outputs.
func PublishableOutput(inv Invocation, ref artifact.Ref) bool {
	if inv.Status == "SUCCEEDED" || inv.Status == "PARTIAL" {
		return true
	}
	return ((inv.Status == "FAILED" && inv.ErrorCode == "normalization_failed") || (inv.Status == "UNSUPPORTED" && inv.ErrorCode == "unsupported_report_version")) && ref.Kind == "report.document" && ref.SchemaID == "codexploit/builtin-native/v1"
}

func (h *Host) GetStatus(ctx context.Context, scope artifact.Scope, id string) (Invocation, error) {
	return h.deps.Repository.GetInvocation(ctx, scope, id)
}
func (h *Host) List(ctx context.Context, scope artifact.Scope, cursor string, limit int) ([]Invocation, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	return h.deps.Repository.ListInvocations(ctx, scope, cursor, limit)
}
func (h *Host) Wait(ctx context.Context, scope artifact.Scope, id string) (Invocation, error) {
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		inv, err := h.GetStatus(ctx, scope, id)
		if err != nil || Terminal(inv.Status) {
			return inv, err
		}
		select {
		case <-ctx.Done():
			return Invocation{}, ctx.Err()
		case <-timer.C:
		}
	}
}
func (h *Host) Cancel(ctx context.Context, scope artifact.Scope, id string, expected int64) (Invocation, error) {
	inv, err := h.GetStatus(ctx, scope, id)
	if err != nil {
		return Invocation{}, err
	}
	if Terminal(inv.Status) {
		return inv, nil
	}
	if inv.Version != expected {
		return Invocation{}, ErrConflict
	}
	inv.Status = "CANCELLED"
	inv.ErrorCode = "operator_cancelled"
	inv.Version++
	inv.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := h.deps.Repository.SaveInvocation(ctx, inv, expected); err != nil {
		return Invocation{}, err
	}
	h.mu.Lock()
	if cancel := h.active[id]; cancel != nil {
		cancel()
	}
	h.mu.Unlock()
	return inv, nil
}
func (h *Host) Close() error {
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.wg.Wait()
	return nil
}

func (h *Host) prepare(ctx context.Context, inv Invocation, kind string, document any) (artifact.Ref, error) {
	raw, err := json.Marshal(document)
	if err != nil {
		return artifact.Ref{}, err
	}
	if int64(len(raw)) > inv.Request.Budget.MaxOutputBytes {
		return artifact.Ref{}, ErrBudget
	}
	ref := artifact.Ref{ID: "artifact-" + inv.ID + "-" + kind, Kind: "code." + kind, Scope: inv.Request.Scope, SHA256: digest(raw), Bytes: int64(len(raw)), MediaType: "application/json", SchemaID: "codexploit/go-" + kind + "/v1", Producer: artifact.Producer{PluginID: inv.Request.PluginID, PluginVersion: inv.Request.PluginVersion, InvocationID: inv.ID, ConfigDigest: inv.ConfigDigest}}
	return h.deps.Artifacts.Prepare(ctx, ref, bytes.NewReader(raw), inv.Request.Budget.MaxOutputBytes)
}
