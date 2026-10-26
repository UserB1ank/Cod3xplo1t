package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

func TestProjectSourceUsesReadOnlyDirectoryAndSizeConfirmationBeforeCreatingWork(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	input := readAuditInput(t, env.ts, project)
	source, err := env.rt.Manager.Load(input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if source.Commit != "project-source" || !source.Frozen {
		t.Fatalf("source: %+v", source)
	}
	endpoint := "/api/v1/projects/" + project + "/analysis-runs"
	refs, err := env.server.Artifacts.List(t.Context(), artifact.Scope{ProjectID: project, SourceID: input.SourceID, SnapshotID: input.SnapshotID}, "", 100)
	if err != nil || len(refs) != 0 {
		t.Fatalf("source archives were generated: %+v %v", refs, err)
	}
	// A sparse source file checks the actual directory size without allocating
	// hundreds of MiB or turning this into a content-hashing test.
	if err := os.Chmod(source.TreeDir(), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(source.TreeDir(), "large.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, size := range []int64{artifact.SourceWarningBytes - input.Bytes, artifact.SourceWarningBytes - input.Bytes + 1} {
		if err := file.Truncate(size); err != nil {
			t.Fatal(err)
		}
		result := do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1"}, nil)
		if size+input.Bytes == artifact.SourceWarningBytes {
			if result.status != 503 || !strings.Contains(string(result.body), "analysis_engine_unavailable") {
				t.Fatalf("500 MiB rejected: %d %s", result.status, result.body)
			}
		} else {
			if result.status != 409 || !strings.Contains(string(result.body), "source_size_confirmation_required") {
				t.Fatalf("confirmation missing: %d %s", result.status, result.body)
			}
			var receipt struct {
				Bytes int64 `json:"source_bytes"`
			}
			result.decode(t, &receipt)
			if receipt.Bytes != size+input.Bytes {
				t.Fatalf("wrong source size: %+v", receipt)
			}
			result = do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "confirm_source_bytes": receipt.Bytes}, nil)
			if result.status != 503 || !strings.Contains(string(result.body), "analysis_engine_unavailable") {
				t.Fatalf("confirmation not accepted: %d %s", result.status, result.body)
			}
		}
	}
	runs, err := env.rt.Store.ListAnalysisRuns(t.Context(), project, 20)
	if err != nil || len(runs) != 0 {
		t.Fatalf("preflight created work: %+v %v", runs, err)
	}
}
