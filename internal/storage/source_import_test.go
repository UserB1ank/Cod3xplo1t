package storage

import (
	"context"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/sourceimport"
)

func TestImportedSourceCoverageCannotBeChangedThroughReturnedReferences(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	if err := store.PutProject(ctx, Project{ID: "project-import", Name: "Fixture"}); err != nil {
		t.Fatal(err)
	}
	source := SourceDefinition{ID: "source-import", ProjectID: "project-import", Import: &sourceimport.Report{Skipped: 1, Excluded: []string{"fixture/generated"}}}
	if err := store.CreateSource(ctx, source); err != nil {
		t.Fatal(err)
	}
	source.Import.Excluded[0] = "changed-at-write"
	read, err := store.GetSource(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if read.Import.Excluded[0] != "fixture/generated" {
		t.Fatal("caller changed stored coverage after CreateSource")
	}
	read.Import.Excluded[0] = "changed-at-read"
	page, err := store.ListSources(ctx, source.ProjectID, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].Import.Excluded[0] != "fixture/generated" {
		t.Fatal("GetSource exposed stored coverage")
	}
	page[0].Import.Excluded[0] = "changed-at-list"
	read, err = store.GetSource(ctx, source.ID)
	if err != nil || read.Import.Excluded[0] != "fixture/generated" {
		t.Fatal("ListSources exposed stored coverage")
	}
}
