package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scanner"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func TestBuildRejectsEmptyWorkspace(t *testing.T) {
	t.Parallel()
	if _, err := Build(context.Background(), Config{}); err == nil {
		t.Fatal("Build accepted an empty workspace")
	}
}

func TestBuildDefaultsToInMemoryStore(t *testing.T) {
	t.Parallel()
	workspace := filepath.Join(t.TempDir(), "work")
	rt, err := Build(context.Background(), Config{Workspace: workspace})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer rt.Close()
	if _, ok := rt.Store.(*storage.Memory); !ok {
		t.Fatalf("store type = %T, want *storage.Memory", rt.Store)
	}
	if rt.Analyzer == nil || rt.Manager == nil {
		t.Fatal("runtime is not fully wired")
	}
	if _, err := os.Stat(filepath.Join(workspace, "snapshots")); err != nil {
		t.Fatalf("snapshots directory missing: %v", err)
	}
	if !rt.Manager.AllowNetwork {
		if rt.Manager.Freeze != true {
			t.Error("snapshot freezing should be on by default")
		}
	}
}

func TestBuildWithSQLiteMigratesAndPersists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	workspace := filepath.Join(t.TempDir(), "work")
	dbPath := filepath.Join(t.TempDir(), "nested", "codexploit.db")

	rt, err := Build(ctx, Config{Workspace: workspace, DBPath: dbPath})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := rt.Store.(*storage.SQL); !ok {
		t.Fatalf("store type = %T, want *storage.SQL", rt.Store)
	}
	project := storage.Project{ID: "proj-1", Name: "fixture", Source: "/srv/fixture", IdentityKind: "dir", Identity: "/srv/fixture"}
	if err := rt.Store.PutProject(ctx, project); err != nil {
		t.Fatalf("PutProject: %v", err)
	}
	snap := &repository.Snapshot{
		SchemaVersion: repository.SchemaVersion,
		SnapshotID:    "snap-0123456789abcdef0123456789abcdef",
		Identity:      repository.Identity{Kind: "dir", Name: "/srv/fixture"},
		VCS:           "none",
		Commit:        "content:deadbeef",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if err := rt.Store.PutSnapshot(ctx, project.ID, snap); err != nil {
		t.Fatalf("PutSnapshot: %v", err)
	}
	manifest := &analysis.Manifest{
		SchemaVersion: analysis.SchemaVersion,
		SnapshotID:    snap.SnapshotID,
		AnalysisID:    "analysis-1",
		Engine:        analysis.DefaultEngine,
	}
	if err := rt.Store.PutManifest(ctx, snap.SnapshotID, manifest); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening the same database must see the same records: migrations are
	// already applied and nothing is recreated from scratch.
	reopened, err := Build(ctx, Config{Workspace: workspace, DBPath: dbPath})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	gotProject, err := reopened.Store.GetProject(ctx, project.ID)
	if err != nil {
		t.Fatalf("GetProject after reopen: %v", err)
	}
	if gotProject.Name != project.Name {
		t.Errorf("project = %+v, want %+v", gotProject, project)
	}
	gotManifest, err := reopened.Store.GetManifest(ctx, snap.SnapshotID)
	if err != nil {
		t.Fatalf("GetManifest after reopen: %v", err)
	}
	if gotManifest.AnalysisID != "analysis-1" {
		t.Errorf("manifest analysis id = %q", gotManifest.AnalysisID)
	}
}

func TestBuildFailsWhenDatabasePathIsADirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rt, err := Build(context.Background(), Config{Workspace: filepath.Join(t.TempDir(), "work"), DBPath: dir})
	if err == nil {
		rt.Close()
		t.Fatal("Build accepted a directory as database path")
	}
	if !errors.Is(err, os.ErrExist) && !errors.Is(err, context.DeadlineExceeded) {
		// The driver reports this as a plain error; accept any failure, but make
		// sure we did not silently fall back to memory.
		t.Logf("open error: %v", err)
	}
}

// TestBuildRejectsMisconfiguredAgent pins the contract that a deployment which
// cannot run an agent fails at construction. A server that started anyway would
// accept a run request and fail every attempt, which is worse than refusing to
// start: the operator would debug an empty queue instead of a typo.
func TestBuildRejectsMisconfiguredAgent(t *testing.T) {
	t.Parallel()
	answer := `{"schema_version":1,"security_goal":"g","hypothesis":{"statement":"s","status":"candidate","confidence":"low"},
		"supporting_evidence":[{"kind":"source","ref":"ev-1"}],"finding_candidate":false}`
	cases := []struct {
		name string
		cfg  AgentConfig
	}{
		{"unknown runtime", AgentConfig{Enabled: true, Runtime: "gpt"}},
		{"disabled but enabled", AgentConfig{Enabled: true, Runtime: AgentRuntimeDisabled}},
		{"scripted without an answer", AgentConfig{Enabled: true, Runtime: AgentRuntimeScripted}},
		{"scripted with invalid json", AgentConfig{
			Enabled: true, Runtime: AgentRuntimeScripted, ScriptedAnswerJSON: "{not json",
		}},
		{"scripted with an unknown field", AgentConfig{
			Enabled: true, Runtime: AgentRuntimeScripted,
			ScriptedAnswerJSON: `{"security_goal":"g","nope":true}`,
		}},
		{"cli without a command", AgentConfig{Enabled: true, Runtime: AgentRuntimeCLI}},
		{"unknown tool", AgentConfig{
			Enabled: true, Runtime: AgentRuntimeScripted, ScriptedAnswerJSON: answer,
			AllowedTools: []string{"graph.query"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := Build(context.Background(), Config{
				Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory", Agent: tc.cfg,
			})
			if err == nil {
				rt.Close()
				t.Fatalf("Build accepted %+v", tc.cfg)
			}
		})
	}
}

// TestBuildWiresAgentOnlyWhenEnabled pins the 501 contract: a disabled agent
// leaves both fields nil, which is what makes the run routes answer
// agent_unavailable instead of pretending a run is missing.
func TestBuildWiresAgentOnlyWhenEnabled(t *testing.T) {
	t.Parallel()
	workspace := filepath.Join(t.TempDir(), "work")
	disabled, err := Build(context.Background(), Config{Workspace: workspace, DBPath: "memory"})
	if err != nil {
		t.Fatalf("Build (disabled): %v", err)
	}
	defer disabled.Close()
	if disabled.Agent != nil || disabled.AgentRegistry != nil {
		t.Errorf("a disabled agent was wired: %+v", disabled.Agent)
	}

	answer := `{"schema_version":1,"security_goal":"g","hypothesis":{"statement":"s","status":"candidate","confidence":"low"},
		"supporting_evidence":[{"kind":"source","ref":"ev-1"}],"finding_candidate":false}`
	enabled, err := Build(context.Background(), Config{
		Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory",
		Agent: AgentConfig{Enabled: true, Runtime: AgentRuntimeScripted, ScriptedAnswerJSON: answer},
	})
	if err != nil {
		t.Fatalf("Build (enabled): %v", err)
	}
	defer enabled.Close()
	if enabled.Agent == nil || enabled.AgentRegistry == nil {
		t.Fatal("the enabled agent was not wired")
	}
	if enabled.Agent.Tasks == nil || enabled.Agent.Paths == nil || enabled.Agent.Store == nil {
		t.Errorf("the runner is incomplete: %+v", enabled.Agent)
	}
	// The advertised allowlist is the registry's own: every name the agent is
	// told about is one the orchestrator can execute.
	names := enabled.AgentRegistry.Names()
	if len(names) == 0 {
		t.Fatal("the tool registry is empty")
	}
	for _, name := range enabled.Agent.Policy.AllowedTools {
		if _, ok := enabled.AgentRegistry.Lookup(name); !ok {
			t.Errorf("policy allows %q, which the registry cannot execute", name)
		}
	}
}

// TestBuildRejectsMisconfiguredVerification pins the same contract for P6: a
// deployment that cannot verify anything fails at construction, because a server
// that started anyway would accept a verification request and fail every attempt.
func TestBuildRejectsMisconfiguredVerification(t *testing.T) {
	t.Parallel()
	scratch := t.TempDir()
	cases := []struct {
		name string
		cfg  VerificationConfig
	}{
		{"unknown executor", VerificationConfig{Enabled: true, Executor: "gpt"}},
		{"disabled but enabled", VerificationConfig{Enabled: true, Executor: VerifyExecutorDisabled}},
		{"empty executor", VerificationConfig{Enabled: true}},
		{"cli without a command", VerificationConfig{Enabled: true, Executor: VerifyExecutorCLI, WorkingDir: scratch}},
		{"cli without a working directory", VerificationConfig{Enabled: true, Executor: VerifyExecutorCLI, Command: []string{"true"}}},
		{"cli with a missing working directory", VerificationConfig{
			Enabled: true, Executor: VerifyExecutorCLI, Command: []string{"true"},
			WorkingDir: filepath.Join(scratch, "absent"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := Build(context.Background(), Config{
				Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory", Verification: tc.cfg,
			})
			if err == nil {
				rt.Close()
				t.Fatalf("Build accepted %+v", tc.cfg)
			}
		})
	}
}

// TestBuildWiresVerificationOnlyWhenEnabled pins the 501 contract: a disabled
// verifier leaves both fields nil, which is what makes the verification routes
// answer verification_unavailable instead of pretending a record is missing.
func TestBuildWiresVerificationOnlyWhenEnabled(t *testing.T) {
	t.Parallel()
	disabled, err := Build(context.Background(), Config{
		Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory",
	})
	if err != nil {
		t.Fatalf("Build (disabled): %v", err)
	}
	defer disabled.Close()
	if disabled.Verifier != nil || disabled.VerifyPlanner != nil {
		t.Errorf("a disabled verifier was wired: %+v", disabled.Verifier)
	}

	// A script with no steps is a valid configuration: the executor reports every
	// step as unsupported rather than pretending it ran.
	enabled, err := Build(context.Background(), Config{
		Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory",
		Verification: VerificationConfig{Enabled: true, Executor: VerifyExecutorScripted},
	})
	if err != nil {
		t.Fatalf("Build (enabled): %v", err)
	}
	defer enabled.Close()
	if enabled.Verifier == nil || enabled.VerifyPlanner == nil {
		t.Fatal("the enabled verification layer was not wired")
	}
	if enabled.Verifier.Store == nil || enabled.Verifier.Executor == nil {
		t.Errorf("the verifier is incomplete: %+v", enabled.Verifier)
	}
	if enabled.VerifyPlanner.Store == nil {
		t.Errorf("the planner lost its store: %+v", enabled.VerifyPlanner)
	}
	if caps := enabled.Verifier.Executor.Capabilities(); caps.Name != VerifyExecutorScripted {
		t.Errorf("executor name = %q, want %q", caps.Name, VerifyExecutorScripted)
	}
}

// TestBuildResolvesScriptedSteps pins the dry-run entry point: a scripted executor
// can be given a script as JSON (or @file), malformed JSON fails construction, and
// an empty script is accepted but warned about, because a silent BLOCKED run is the
// one outcome an operator may read as a finding.
//
// It is not parallel: it installs a logger to capture the warning, and the Go test
// runner only resumes parallel tests after the sequential ones have finished.
func TestBuildResolvesScriptedSteps(t *testing.T) {
	script, err := json.Marshal([]verify.StepOutcome{
		{Kind: verify.EvidenceTest, Content: "ok the claim reproduced", Command: "verify test claim"},
		{Kind: verify.EvidenceRuntimeLog, Content: "runtime log: the claim reproduced"},
	})
	if err != nil {
		t.Fatalf("marshal a script: %v", err)
	}
	build := func(cfg VerificationConfig) (*Runtime, error) {
		return Build(context.Background(), Config{
			Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory", Verification: cfg,
		})
	}

	// The raw JSON form, and the same document through @file.
	raw, err := build(VerificationConfig{
		Enabled: true, Executor: VerifyExecutorScripted, ScriptedStepsJSON: string(script),
	})
	if err != nil {
		t.Fatalf("Build with a JSON script: %v", err)
	}
	defer raw.Close()
	if len(raw.VerificationConfig.ScriptedSteps) != 2 {
		t.Fatalf("the JSON script resolved to %d step(s), want 2", len(raw.VerificationConfig.ScriptedSteps))
	}
	if got := raw.VerificationConfig.ScriptedSteps[0].Kind; got != verify.EvidenceTest {
		t.Errorf("step 0 kind = %q, want %q", got, verify.EvidenceTest)
	}

	path := filepath.Join(t.TempDir(), "steps.json")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatalf("write the script file: %v", err)
	}
	fromFile, err := build(VerificationConfig{
		Enabled: true, Executor: VerifyExecutorScripted, ScriptedStepsJSON: "@" + path,
	})
	if err != nil {
		t.Fatalf("Build with @file: %v", err)
	}
	defer fromFile.Close()
	if len(fromFile.VerificationConfig.ScriptedSteps) != 2 {
		t.Errorf("@file resolved to %d step(s), want 2", len(fromFile.VerificationConfig.ScriptedSteps))
	}

	// A malformed script, an unknown field, a missing file and two forms at once are
	// all wiring errors: each would otherwise surface as a run that fails later.
	bad := []struct {
		name string
		cfg  VerificationConfig
	}{
		{"malformed json", VerificationConfig{Enabled: true, Executor: VerifyExecutorScripted, ScriptedStepsJSON: "{not json"}},
		{"unknown field", VerificationConfig{Enabled: true, Executor: VerifyExecutorScripted, ScriptedStepsJSON: `[{"kind":"test","nope":1}]`}},
		{"missing file", VerificationConfig{Enabled: true, Executor: VerifyExecutorScripted, ScriptedStepsJSON: "@" + filepath.Join(t.TempDir(), "absent.json")}},
		{"@ without a path", VerificationConfig{Enabled: true, Executor: VerifyExecutorScripted, ScriptedStepsJSON: "@"}},
		{"both forms", VerificationConfig{
			Enabled: true, Executor: VerifyExecutorScripted, ScriptedStepsJSON: string(script),
			ScriptedSteps: []verify.StepOutcome{{Kind: verify.EvidenceTest}},
		}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := build(tc.cfg)
			if err == nil {
				rt.Close()
				t.Fatalf("Build accepted %+v", tc.cfg)
			}
			if !strings.Contains(err.Error(), "verification") {
				t.Errorf("error %q does not name the verification layer", err)
			}
		})
	}

	// An empty script is legal, and Build says out loud what it will do.
	var logged bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	defer slog.SetDefault(previous)
	empty, err := build(VerificationConfig{Enabled: true, Executor: VerifyExecutorScripted})
	if err != nil {
		t.Fatalf("Build with an empty script: %v", err)
	}
	defer empty.Close()
	if !strings.Contains(logged.String(), "BLOCKED") {
		t.Errorf("Build did not warn about an empty script:\n%s", logged.String())
	}
}

// schedulerTestAgentConfig is a valid scripted agent. The scheduler only needs an
// adapter to exist at construction time; nothing here runs a pass.
func schedulerTestAgentConfig() AgentConfig {
	return AgentConfig{
		Enabled: true, Runtime: AgentRuntimeScripted,
		ScriptedAnswerJSON: `{"schema_version":1,"security_goal":"g","hypothesis":{"statement":"s","status":"candidate","confidence":"low"},
			"supporting_evidence":[{"kind":"source","ref":"ev-1"}],"finding_candidate":false}`,
	}
}

// TestBuildRejectsMisconfiguredScheduler pins the contract that a scheduler which
// cannot run what it claims fails at construction: an enabled scheduler without an
// adapter would claim leases it can never execute, and a negative bound would make
// the loop misbehave rather than refuse.
func TestBuildRejectsMisconfiguredScheduler(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		cfg        SchedulerConfig
		withoutAge bool
	}{
		{name: "enabled without an agent", cfg: SchedulerConfig{Enabled: true}, withoutAge: true},
		{name: "blank audit id", cfg: SchedulerConfig{Enabled: true, Audits: []string{" "}}},
		{name: "negative interval", cfg: SchedulerConfig{Enabled: true, Interval: -time.Second}},
		{name: "negative concurrency", cfg: SchedulerConfig{Enabled: true, MaxConcurrent: -1}},
		{name: "negative lease ttl", cfg: SchedulerConfig{Enabled: true, LeaseTTL: -time.Second}},
		{name: "negative backoff", cfg: SchedulerConfig{Enabled: true, Backoff: path.Backoff{Base: -time.Second}}},
		{name: "negative jitter", cfg: SchedulerConfig{Enabled: true, Backoff: path.Backoff{Jitter: -0.5}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory",
				Scheduler: tc.cfg,
			}
			if !tc.withoutAge {
				cfg.Agent = schedulerTestAgentConfig()
			}
			rt, err := Build(context.Background(), cfg)
			if err == nil {
				rt.Close()
				t.Fatalf("Build accepted %+v", tc.cfg)
			}
			if !strings.Contains(err.Error(), "scheduler") {
				t.Errorf("error %q does not name the scheduler", err)
			}
		})
	}
}

// TestBuildWiresSchedulerOnlyWhenEnabled pins the 501 contract and the effective
// configuration: a disabled scheduler leaves the fields nil, and an enabled one
// normalises the audit set it was given.
func TestBuildWiresSchedulerOnlyWhenEnabled(t *testing.T) {
	t.Parallel()
	disabled, err := Build(context.Background(), Config{
		Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory",
	})
	if err != nil {
		t.Fatalf("Build (disabled): %v", err)
	}
	defer disabled.Close()
	if disabled.Scheduler != nil || disabled.Metrics != nil {
		t.Fatalf("a disabled scheduler was wired: %v", disabled.Scheduler)
	}

	enabled, err := Build(context.Background(), Config{
		Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory",
		Agent: schedulerTestAgentConfig(),
		Scheduler: SchedulerConfig{
			Enabled: true, Audits: []string{" audit-1 ", "audit-1", "audit-2"},
			Interval: time.Minute, MaxConcurrent: 2, LeaseTTL: time.Minute, Owner: "worker-scheduler",
		},
	})
	if err != nil {
		t.Fatalf("Build (enabled): %v", err)
	}
	defer enabled.Close()
	if enabled.Scheduler == nil || enabled.Metrics == nil {
		t.Fatal("the enabled scheduler was not wired")
	}
	if enabled.Scheduler.IsRunning() {
		t.Error("a freshly built scheduler reports itself running before Run is called")
	}
	effective := enabled.Scheduler.Config()
	if effective.Owner != "worker-scheduler" || effective.MaxConcurrent != 2 {
		t.Errorf("scheduler config = %+v, want the configured owner and concurrency", effective)
	}
	if len(effective.Audits) != 2 || effective.Audits[0] != "audit-1" || effective.Audits[1] != "audit-2" {
		t.Errorf("audits = %v, want the trimmed, de-duplicated set", effective.Audits)
	}
	if effective.IntervalSeconds != 60 {
		t.Errorf("interval = %vs, want 60", effective.IntervalSeconds)
	}
}

func TestBuildInstallsADeploymentProcessPackage(t *testing.T) {
	t.Parallel()
	packages := t.TempDir()
	directory := filepath.Join(packages, "codexploit.static-patterns@1.0.0")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	name := "scanner"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), scanner.Manifest(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), executable, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rt, err := Build(ctx, Config{Workspace: filepath.Join(t.TempDir(), "work"), PluginPackages: packages})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer rt.Close()
	record, err := rt.PluginCatalog.Get(ctx, scanner.ID, scanner.Version)
	if err != nil {
		t.Fatalf("Get scanner: %v", err)
	}
	if !record.Installed || !record.Executable {
		t.Fatalf("scanner status = %+v", record)
	}
	if _, ok := rt.WorkflowCompiler.AdapterInputs[scanner.ID+"@"+scanner.Version]; !ok {
		t.Fatal("scanner adapter input contract was not wired into the workflow compiler")
	}
}
