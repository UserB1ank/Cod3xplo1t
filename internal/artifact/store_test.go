package artifact_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func artifactFixture(t *testing.T) (*artifact.Local, artifact.Ref, string) {
	t.Helper()
	ctx := context.Background()
	index := storage.NewMemory()
	if err := index.PutProject(ctx, storage.Project{ID: "project-example"}); err != nil {
		t.Fatal(err)
	}
	if err := index.PutSnapshot(ctx, "project-example", &repository.Snapshot{SnapshotID: "snap-example"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store, err := artifact.NewLocal(root, index)
	if err != nil {
		t.Fatal(err)
	}
	ref := artifact.Ref{ID: "artifact-example", Kind: "source.snapshot", Scope: artifact.Scope{ProjectID: "project-example", SourceID: "legacy-project-example", SnapshotID: "snap-example"}, SHA256: "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03", Bytes: 6, MediaType: "text/plain", SchemaID: "codexploit/example/v1", Producer: artifact.Producer{PluginID: "builtin.snapshot", PluginVersion: "1.0.0", InvocationID: "capture-example", ConfigDigest: strings.Repeat("0", 64)}}
	return store, ref, root
}

func TestArtifactDuplicatePublishCannotReplaceAnImmutableReference(t *testing.T) {
	store, ref, _ := artifactFixture(t)
	ctx := context.Background()
	for range 2 {
		if got, err := store.Put(ctx, ref, strings.NewReader("hello\n"), 100); err != nil || got != ref {
			t.Fatalf("idempotent publish: %+v %v", got, err)
		}
	}
	other := ref
	other.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("other\n")))
	if _, err := store.Put(ctx, other, strings.NewReader("other\n"), 100); !errors.Is(err, artifact.ErrConflict) {
		t.Fatalf("replacement: %v", err)
	}
	for _, scope := range []artifact.Scope{{ProjectID: "another", SourceID: ref.Scope.SourceID, SnapshotID: ref.Scope.SnapshotID}, {ProjectID: ref.Scope.ProjectID, SourceID: "wrong-source", SnapshotID: ref.Scope.SnapshotID}} {
		if _, _, err := store.Open(ctx, scope, ref.ID, 100); !errors.Is(err, artifact.ErrNotFound) {
			t.Fatalf("scope escape: %v", err)
		}
	}
	if _, _, err := store.Open(ctx, ref.Scope, ref.ID, 5); !errors.Is(err, artifact.ErrBudget) {
		t.Fatalf("read budget: %v", err)
	}
	refs, err := store.List(ctx, ref.Scope, "", 10)
	if err != nil || len(refs) != 1 || refs[0] != ref {
		t.Fatalf("published refs: %+v %v", refs, err)
	}
}

type interruptedReader struct {
	read   bool
	cancel context.CancelFunc
}

func (r *interruptedReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		copy(p, "hel")
		if r.cancel != nil {
			r.cancel()
		}
		return 3, nil
	}
	return 0, io.ErrUnexpectedEOF
}

func TestFailedOrCancelledArtifactPublicationLeavesNoVisibleReference(t *testing.T) {
	for _, reason := range []string{"short", "long", "digest", "source error", "cancel", "budget", "invalid"} {
		t.Run(reason, func(t *testing.T) {
			store, ref, _ := artifactFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var input io.Reader = strings.NewReader("hello\n")
			budget := int64(100)
			want := artifact.ErrIntegrity
			switch reason {
			case "short":
				input = strings.NewReader("hel")
			case "long":
				input = strings.NewReader("hello\nextra")
			case "digest":
				ref.SHA256 = strings.Repeat("0", 64)
			case "source error":
				input = &interruptedReader{}
				want = io.ErrUnexpectedEOF
			case "cancel":
				input = &interruptedReader{cancel: cancel}
				want = context.Canceled
			case "budget":
				budget = 5
				want = artifact.ErrBudget
			case "invalid":
				ref.Kind = "invented"
				want = artifact.ErrInvalid
			}
			if _, err := store.Put(ctx, ref, input, budget); !errors.Is(err, want) {
				t.Fatalf("publication: %v, want %v", err, want)
			}
			refs, err := store.List(context.Background(), ref.Scope, "", 10)
			if err != nil || len(refs) != 0 {
				t.Fatalf("partial became visible: %+v %v", refs, err)
			}
			if _, _, err := store.Open(context.Background(), ref.Scope, ref.ID, 100); !errors.Is(err, artifact.ErrNotFound) {
				t.Fatalf("unpublished read: %v", err)
			}
		})
	}
}

func TestArtifactReadsDetectMissingCorruptAndEscapingObjects(t *testing.T) {
	for _, reason := range []string{"missing", "corrupt", "symlink"} {
		t.Run(reason, func(t *testing.T) {
			store, ref, root := artifactFixture(t)
			ctx := context.Background()
			if _, err := store.Put(ctx, ref, strings.NewReader("hello\n"), 100); err != nil {
				t.Fatal(err)
			}
			object := filepath.Join(root, "objects", ref.SHA256)
			if reason == "corrupt" {
				if err := os.WriteFile(object, []byte("other\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(object); err != nil {
					t.Fatal(err)
				}
				if reason == "symlink" {
					outside := filepath.Join(t.TempDir(), "object")
					if err := os.WriteFile(outside, []byte("hello\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, object); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
				}
			}
			if _, err := store.Stat(ctx, ref.Scope, ref.ID, 100); err == nil {
				t.Fatal("unhealthy object reported available")
			}
			if _, _, err := store.Open(ctx, ref.Scope, ref.ID, 100); err == nil {
				t.Fatal("unhealthy object downloadable")
			}
		})
	}
}

func TestLargeArtifactReadStopsOnCancellation(t *testing.T) {
	store, ref, _ := artifactFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	data := strings.Repeat("A", 2<<20)
	ref.Bytes = int64(len(data))
	ref.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
	if _, err := store.Put(ctx, ref, strings.NewReader(data), ref.Bytes); err != nil {
		t.Fatal(err)
	}
	r, _, err := store.Open(ctx, ref.Scope, ref.ID, ref.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	buffer := make([]byte, 8192)
	n, err := r.Read(buffer)
	if n != 8192 || err != nil {
		t.Fatalf("first bounded read: %d %v", n, err)
	}
	cancel()
	if n, err := r.Read(buffer); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stream: %d %v", n, err)
	}
}

func TestPublishedArtifactCanBeReadByItsScope(t *testing.T) {
	ctx := context.Background()
	index := storage.NewMemory()
	if err := index.PutProject(ctx, storage.Project{ID: "project-example"}); err != nil {
		t.Fatal(err)
	}
	if err := index.PutSnapshot(ctx, "project-example", &repository.Snapshot{SnapshotID: "snap-example"}); err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewLocal(t.TempDir(), index)
	if err != nil {
		t.Fatal(err)
	}
	ref := artifact.Ref{ID: "artifact-example", Kind: "source.snapshot", Scope: artifact.Scope{ProjectID: "project-example", SourceID: "legacy-project-example", SnapshotID: "snap-example"}, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("hello\n"))), Bytes: 6, MediaType: "text/plain", SchemaID: "codexploit/source-example/v1", Producer: artifact.Producer{PluginID: "builtin.snapshot", PluginVersion: "1.0.0", InvocationID: "capture-example", ConfigDigest: strings.Repeat("0", 64)}}
	got, err := store.Put(ctx, ref, strings.NewReader("hello\n"), 100)
	if err != nil || got != ref {
		t.Fatalf("publish: %+v %v", got, err)
	}
	reader, observed, err := store.Open(ctx, ref.Scope, ref.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != "hello\n" || observed != ref {
		t.Fatalf("read: %q %+v %v", data, observed, err)
	}
}

func TestArtifactRejectsAnUnsafeDownloadMediaType(t *testing.T) {
	store, ref, _ := artifactFixture(t)
	ref.MediaType = "text/plain\r\nInjected: value"
	if _, err := store.Put(context.Background(), ref, strings.NewReader("hello\n"), 100); !errors.Is(err, artifact.ErrInvalid) {
		t.Fatalf("unsafe response metadata accepted: %v", err)
	}
}
