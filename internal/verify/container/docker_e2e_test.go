package container

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// recordingProvider remembers the handle so the test can prove the container is
// gone after the verdict, not only that Destroy was called.
type recordingProvider struct {
	*Provider
	handle verify.EnvironmentHandle
}

func (p *recordingProvider) Provision(ctx context.Context, request verify.EnvironmentRequest) (verify.EnvironmentHandle, error) {
	handle, err := p.Provider.Provision(ctx, request)
	if err == nil {
		p.handle = handle
	}
	return handle, err
}

func TestDockerSingleServiceVerification(t *testing.T) {
	if os.Getenv("CODEXPLOIT_DOCKER_TESTS") != "1" {
		t.Skip("set CODEXPLOIT_DOCKER_TESTS=1 to run the real single-service verification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	image := buildSingleServiceFixture(t, ctx)
	provider := &recordingProvider{Provider: &Provider{}}
	t.Cleanup(func() {
		if provider.handle.ID != "" {
			_ = provider.Destroy(context.Background(), provider.handle)
		}
		_ = exec.Command("docker", "rmi", "-f", image).Run()
	})

	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "app.txt"), []byte("frozen source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sourceDigest, err := DigestSource(source)
	if err != nil {
		t.Fatalf("source digest: %v", err)
	}
	now := time.Now().UTC()
	plan := verify.ExecutionPlan{
		SchemaVersion: verify.ExecutionPlanSchemaVersion, ID: "plan-single-service", ProjectID: "proj-e2e",
		HypothesisID: "hyp-e2e", FindingID: "finding-hyp-e2e", PathID: "path-e2e",
		AuditID: "audit-e2e", SnapshotID: "snap-e2e",
		SecurityGoal: "data_exposure", Claim: "the target returns the seeded secret to an unauthenticated caller",
		Verifier: verify.PlanVerifier{Adapter: "container", Version: "1.0.0", Capability: "verification"},
		Steps: []verify.Step{
			{Kind: verify.StepDynamicProof, Command: []string{"/probe", "data"}, Expectation: "SECRET_TOKEN", Contradiction: "PERMISSION_DENIED", TimeoutSeconds: 30, RequiresApproval: true},
			{Kind: verify.StepDynamicProof, Command: []string{"/probe", "write", "/source/escape"}, Expectation: "write_denied", Contradiction: "write_succeeded", TimeoutSeconds: 30, RequiresApproval: true},
		},
		Assertions: []verify.PlanAssertion{
			{ID: "a1", Kind: "stdout_contains", Expectation: "SECRET_TOKEN", Contradiction: "PERMISSION_DENIED", Required: true},
			{ID: "a2", Kind: "http_status", Expectation: "200", Contradiction: "500", Required: true},
			{ID: "a3", Kind: "stdout_contains", Expectation: "write_denied", Contradiction: "write_succeeded", Required: true},
		},
		Environment: verify.PlanEnvironment{
			OS: "linux", Arch: "amd64",
			Provider: verify.PlanProvider{Name: "docker", Version: "1.0.0", Capabilities: []string{"container", "network_none", "read_only_source", "controlled_exec", "environment_logs"}},
			Template: image, Network: verify.PlanNetwork{Mode: "none"}, SourceReadOnly: true,
			ScratchMB: 16, TTLSeconds: 120, Permissions: []string{"dynamic_exec"},
			Resources: verify.PlanResources{CPUMillis: 200, MemoryMB: 128, DiskMB: 64, MaxProcesses: 32, MaxWrites: 10},
			Services: []verify.ServiceSpec{{
				Name: "target", Role: "target", Template: image, Command: []string{"/server"},
				Readiness: []verify.ReadinessProbe{{Kind: "command", Command: []string{"/probe", "health"}, TimeoutSeconds: 30, IntervalSeconds: 1}},
			}},
		},
		Scope:       verify.Scope{Repository: "repo-e2e", SnapshotID: "snap-e2e", RequiresHumanApproval: true},
		Budget:      verify.PlanBudget{MaxSeconds: 60, MaxSteps: 2, MaxCommands: 2},
		Limitations: []string{"single synthetic service; no database dependency"},
		ExpiresAt:   now.Add(time.Hour).Format(time.RFC3339),
		CreatedAt:   now.Format(time.RFC3339),
	}
	plan.Digest = plan.DigestOf()
	approval := verify.PlanApproval{
		PlanID: plan.ID, PlanDigest: plan.DigestOf(), Decision: verify.PlanApproved,
		Actor: "operator", ActorRole: "writer", Permissions: []string{"dynamic_exec"},
		Reason: "approved synthetic single-service verification", DecidedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	approval.Digest = approval.DigestOf()

	leases := verify.NewMemoryEnvironmentLeases()
	executor, err := NewExecutor(provider, ExecutorConfig{
		Plan: plan, Approval: approval,
		Source: verify.EnvironmentSource{SnapshotID: plan.SnapshotID, Digest: sourceDigest, ReadOnly: true, Path: source},
		Leases: leases, Owner: "e2e-worker", LeaseTTL: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	store := storage.NewMemory()
	verifier := verify.NewVerifier(store, executor)
	run, err := verifier.Verify(ctx, verify.VerifyRequest{
		Plan: verify.LegacyPlan(plan), Approved: true, ApprovedBy: "operator", Owner: "e2e",
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if run.Outcome != verify.OutcomeConfirmed || run.Status != verify.VerifySucceeded {
		t.Fatalf("run outcome=%s status=%s stop=%s error=%s", run.Outcome, run.Status, run.StopReason, run.Error)
	}
	if len(run.EvidenceIDs) < 4 {
		t.Fatalf("evidence ids = %v", run.EvidenceIDs)
	}
	finding, err := store.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if finding.Status != verify.FindingConfirmed {
		t.Fatalf("finding status = %s", finding.Status)
	}
	lease, err := leases.GetEnvironmentLease(ctx, plan.ID)
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if lease.State != verify.EnvironmentDestroyed || lease.Cleanup != verify.CleanupSucceeded {
		t.Fatalf("lease after verification = %+v", lease)
	}
	if lease.ReceiptDigest == "" || lease.ImageDigest == "" {
		t.Fatalf("lease did not record the applied receipt: %+v", lease)
	}
	if provider.handle.ID == "" {
		t.Fatal("no environment handle was recorded")
	}
	if _, err := provider.Status(context.Background(), provider.handle); err == nil {
		t.Fatalf("environment %s still exists after the verification", provider.handle.ID)
	}
	if !hasApplied(provider.handle.Receipt.Applied, "read_only_source") || !hasApplied(provider.handle.Receipt.Applied, "network_none") {
		t.Fatalf("receipt applied = %v", provider.handle.Receipt.Applied)
	}
	// The receipt records the applied limits, not the requested ones.
	if provider.handle.Receipt.CPUMillis != 200 || provider.handle.Receipt.MemoryMB != 128 || provider.handle.Receipt.MaxProcesses != 32 {
		t.Fatalf("receipt limits = %+v", provider.handle.Receipt)
	}
}

func hasApplied(applied []string, want string) bool {
	for _, value := range applied {
		if value == want {
			return true
		}
	}
	return false
}

// buildSingleServiceFixture compiles two static Linux binaries and an image from
// a frozen source tree. Nothing is pulled at test time, so the fixture is
// reproducible on a machine with the Go toolchain and a local Docker daemon.
func buildSingleServiceFixture(t *testing.T, ctx context.Context) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("server.go", `package main

import (
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SECRET_TOKEN=seeded\n"))
	})
	_ = http.ListenAndServe("127.0.0.1:8080", mux)
}
`, 0o644)
	write("probe.go", `package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	switch os.Args[1] {
	case "health", "data":
		resp, err := http.Get("http://127.0.0.1:8080/" + os.Args[1])
		if err != nil {
			fmt.Println("request_failed", err)
			os.Exit(2)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fmt.Printf("status=%d\n%s", resp.StatusCode, body)
	case "write":
		if err := os.WriteFile(os.Args[2], []byte("escape"), 0o644); err != nil {
			fmt.Println("write_denied", err)
			return
		}
		fmt.Println("write_succeeded")
		os.Exit(1)
	default:
		fmt.Println("unknown probe")
		os.Exit(2)
	}
}
`, 0o644)
	write("Dockerfile", "FROM scratch\nCOPY server /server\nCOPY probe /probe\nENTRYPOINT [\"/server\"]\n", 0o644)
	for _, target := range []string{"server", "probe"} {
		command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-s -w", "-o", filepath.Join(dir, target), filepath.Join(dir, target+".go"))
		command.Dir = dir
		command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GO111MODULE=off")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", target, err, output)
		}
	}
	image := fmt.Sprintf("codexploit/verify-fixture:%d", time.Now().UnixNano())
	build := exec.CommandContext(ctx, "docker", "build", "-q", "-t", image, dir)
	// The legacy builder avoids BuildKit's per-user activity cache, which is not
	// available in a locked-down CI workspace; the build itself is still real.
	build.Env = append(os.Environ(), "DOCKER_BUILDKIT=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, output)
	}
	return image
}
