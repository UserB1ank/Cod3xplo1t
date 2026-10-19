package sourceimport_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/sourceimport"
)

func TestExpiredUploadCleanupKeepsFreshAndUnrelatedDirectories(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	for _, name := range []string{"codexploit-source-import-old", "codexploit-source-import-fresh", "unrelated"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(root, "codexploit-source-import-old")
	if err := os.Chtimes(old, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := sourceimport.CleanupExpired(context.Background(), root, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired upload was retained: %v", err)
	}
	for _, name := range []string{"codexploit-source-import-fresh", "unrelated"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatalf("cleanup removed %s: %v", name, err)
		}
	}
}

func TestArchiveBudgetsCRCAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		size     int
		corrupt  bool
		canceled bool
		want     error
	}{
		{"large", int(sourceimport.MaxFileBytes) + 1, false, false, sourceimport.ErrBudget},
		{"crc", 20, true, false, sourceimport.ErrInvalid},
		{"cancel", 20, false, true, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			entry, err := writer.CreateHeader(&zip.FileHeader{Name: "main.go", Method: zip.Store})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write(bytes.Repeat([]byte("a"), tc.size)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			content := archive.Bytes()
			if tc.corrupt {
				content[37] ^= 0xff
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			upload, err := sourceimport.Extract(ctx, bytes.NewReader(content), "zip")
			if upload != nil {
				upload.Close()
				t.Fatal("failed upload returned a usable tree")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUploadCloseRemovesOnlyItsOwnedTree(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("package main\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	upload, err := sourceimport.Extract(context.Background(), bytes.NewReader(archive.Bytes()), "zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(upload.Tree); err != nil {
		t.Fatal(err)
	}
	if err := upload.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(upload.Tree); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary upload still readable: %v", err)
	}
	if err := upload.Close(); err != nil {
		t.Fatalf("repeated close: %v", err)
	}
}
