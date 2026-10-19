package sourceimport_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/textproto"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/sourceimport"
)

// A directory selection records an excluded directory once instead of listing
// every file under it. A generated directory can hold tens of thousands of files,
// and counting them per file made a hundred-file project report tens of thousands
// of exclusions.
func TestExtractDirectoryCountsAnExcludedDirectoryOnce(t *testing.T) {
	content := []byte("package main\n")
	digest := sha256.Sum256(content)
	manifest := sourceimport.DirectoryManifest{
		Files: []sourceimport.DirectoryFile{
			{Path: "internal/main.go", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])},
		},
		Excluded: []string{"node_modules", ".git", ".env"},
	}
	body, contentType := directoryBody(t, manifest, map[string][]byte{"internal/main.go": content})

	upload, err := sourceimport.ExtractDirectory(context.Background(), bytes.NewReader(body), contentType)
	if err != nil {
		t.Fatalf("ExtractDirectory: %v", err)
	}
	defer upload.Close()

	if got := upload.Report.Skipped; got != len(manifest.Excluded) {
		t.Errorf("skipped = %d, want one entry per excluded directory/file (%d)", got, len(manifest.Excluded))
	}
	if got := upload.Report.Files; got != 1 {
		t.Errorf("files = %d, want 1", got)
	}
	if got := len(upload.Report.Excluded); got != len(manifest.Excluded) {
		t.Errorf("excluded entries = %d, want %d", got, len(manifest.Excluded))
	}
}

func directoryBody(t *testing.T, manifest sourceimport.DirectoryManifest, files map[string][]byte) ([]byte, string) {
	t.Helper()
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	manifestPart, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {"form-data; name=\"manifest\""},
		"Content-Type":        {"application/json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifestPart.Write(encoded); err != nil {
		t.Fatal(err)
	}

	for name, content := range files {
		part, err := writer.CreatePart(textproto.MIMEHeader{
			"Content-Disposition": {"form-data; name=\"files\"; filename=\"" + name + "\""},
			"Content-Type":        {"application/octet-stream"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes(), writer.FormDataContentType()
}
