package pluginsdk_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

func TestFileJobV2CarriesFixedArtifactIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.json")
	raw := []byte(`{"api_version":"codexploit/file-job/v2","invocation_id":"inv","operation_id":"taint","output_directory":"outputs","budget":{"max_input_bytes":1024,"max_output_bytes":1024},"inputs":[{"artifact_id":"artifact-fixed","port":"code","path":"inputs/code.json","bytes":0,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	job, err := pluginsdk.ReadJob(path)
	if err != nil {
		t.Fatalf("fixed input identity: %v", err)
	}
	if job.Inputs[0].ArtifactID != "artifact-fixed" {
		t.Fatal("artifact identity lost")
	}
}

func TestDirectorySourceBindingDoesNotReadOrHashFileContents(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0400); err != nil {
		t.Fatal(err)
	}
	request := pluginsdk.JobRequest{Inputs: []pluginsdk.LocalInput{{Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-directory/v1", Path: dir, Bytes: 12}}, Budget: pluginsdk.Budget{MaxInputBytes: 500 << 20}}
	got, files, err := pluginsdk.SourceDirectory(request, "source")
	if err != nil || got != dir || !files["main.go"] {
		t.Fatalf("directory binding: %s %v %v", got, files, err)
	}
}
