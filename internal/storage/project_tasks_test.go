package storage

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func TestProjectTaskPersistenceAndPause(t *testing.T) {
	runForEachStore(t, func(t *testing.T, base Store) {
		store := base.(FullStore)
		ctx := context.Background()
		if err := store.PutProject(ctx, testProject("project-one")); err != nil {
			t.Fatal(err)
		}
		if err := store.PutSnapshot(ctx, "project-one", testSnapshot(auditSnapID)); err != nil {
			t.Fatal(err)
		}
		audit := newAuditFixture(auditMainID, auditSnapID, 1)
		audit.Name, audit.Objective, audit.Scope, audit.Paused = "API task", "Review authorization", []string{"internal/api"}, true
		if err := store.CreateAudit(audit); err != nil {
			t.Fatal(err)
		}
		item := newPathFixture("path-task-1", audit.ID, auditSnapID, "entry", "sink", .8)
		item.EntrySubject, item.EntryKind = "GET /report", "http"
		item.TargetSubject, item.TargetKind = "sink:file_read", "SensitiveOperation"
		if err := store.ReplacePaths(audit.ID, []path.Path{item}); err != nil {
			t.Fatal(err)
		}
		storedPath, err := store.GetPath(item.ID)
		if err != nil || storedPath.EntrySubject != item.EntrySubject || storedPath.TargetSubject != item.TargetSubject || storedPath.EntryKind != item.EntryKind || storedPath.TargetKind != item.TargetKind {
			t.Fatalf("path labels lost: %+v %v", storedPath, err)
		}
		got, err := store.GetAudit(audit.ID)
		if err != nil || got.Name != audit.Name || got.Objective != audit.Objective || len(got.Scope) != 1 || !got.Paused {
			t.Fatalf("task roundtrip: %+v %v", got, err)
		}
		_, count, err := store.ListAudits(path.AuditQuery{ProjectID: "project-one"})
		if err != nil || count != 1 {
			t.Fatalf("project tasks: %d %v", count, err)
		}
		_, count, err = store.ListAudits(path.AuditQuery{ProjectID: "other-project"})
		if err != nil || count != 0 {
			t.Fatalf("project isolation: %d %v", count, err)
		}
		_, err = store.ClaimPath(item.ID, "worker", path.NowString(time.Now().Add(time.Minute)), []path.Status{path.StatusQueued}, "worker")
		if !errors.Is(err, path.ErrNotClaimable) {
			t.Fatalf("paused claim: %v", err)
		}
	})
}

func TestFindingGradeCASAndVerificationMerge(t *testing.T) {
	runForEachStore(t, func(t *testing.T, base Store) {
		store := base.(FullStore)
		ctx := context.Background()
		if err := store.PutProject(ctx, testProject("project-grade")); err != nil {
			t.Fatal(err)
		}
		if err := store.PutSnapshot(ctx, "project-grade", testSnapshot(verificationSnapID)); err != nil {
			t.Fatal(err)
		}
		finding := verify.Finding{HypothesisID: "hyp-grade", SnapshotID: verificationSnapID, Title: "fixture", Status: verify.FindingCandidate}
		if err := store.UpsertFinding(finding); err != nil {
			t.Fatal(err)
		}
		findingID := verify.FindingID(finding.HypothesisID)
		stored, err := store.GetFinding(findingID)
		if err != nil {
			t.Fatal(err)
		}
		var successes atomic.Int32
		var wg sync.WaitGroup
		for _, grade := range []string{"high", "medium", "low"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := store.SetFindingSeverity(findingID, grade, stored.Version)
				if err == nil {
					successes.Add(1)
				} else if !errors.Is(err, verify.ErrConflict) {
					t.Errorf("grade: %v", err)
				}
			}()
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatalf("concurrent grades succeeded: %d", successes.Load())
		}
		graded, err := store.GetFinding(findingID)
		if err != nil {
			t.Fatal(err)
		}
		finding.Severity = ""
		if err := store.UpsertFinding(finding); err != nil {
			t.Fatal(err)
		}
		merged, err := store.GetFinding(findingID)
		if err != nil || merged.Severity != graded.Severity {
			t.Fatalf("verification overwrote grade: %+v %v", merged, err)
		}
		_, count, err := store.ListFindings(verify.FindingQuery{ProjectID: "other-project"})
		if err != nil || count != 0 {
			t.Fatalf("project finding leak: %d %v", count, err)
		}
	})
}
