package artifact

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

type FileEntry struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// PublishSnapshot inventories only the frozen tree, never the live source.
// Repeating publication compares the immutable reference instead of rebasing it.
func PublishSnapshot(ctx context.Context, store Store, scope Scope, snap *repository.Snapshot) error {
	root, err := os.OpenRoot(snap.TreeDir())
	if err != nil {
		return ErrNotFound
	}
	defer root.Close()
	archive, err := os.CreateTemp(snap.Dir, ".source-tar-*")
	if err != nil {
		return err
	}
	defer os.Remove(archive.Name())
	defer archive.Close()
	archiveHash := sha256.New()
	output := &budgetWriter{writer: io.MultiWriter(archive, archiveHash), remaining: MaxBytes}
	tw := tar.NewWriter(output)
	files := []FileEntry{}
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrNotFound
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return ErrIntegrity
		}
		if info.Size() > MaxBytes-total || len(files) >= 100000 {
			return ErrBudget
		}
		f, err := root.Open(filepath.FromSlash(name))
		if err != nil {
			return ErrNotFound
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o444, Size: info.Size(), Typeflag: tar.TypeReg}); err != nil {
			f.Close()
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(h, tw), io.LimitReader(contextReader{ctx, f}, info.Size()+1))
		f.Close()
		if err != nil {
			return err
		}
		if n != info.Size() {
			return ErrIntegrity
		}
		total += n
		files = append(files, FileEntry{Path: name, Bytes: n, SHA256: fmt.Sprintf("%x", h.Sum(nil))})
		return nil
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if len(files) != snap.Stats.Files || total != snap.Stats.Bytes {
		return ErrIntegrity
	}
	document := struct {
		APIVersion  string      `json:"api_version"`
		Scope       Scope       `json:"scope"`
		Revision    string      `json:"revision"`
		Files       []FileEntry `json:"files"`
		Limitations []string    `json:"limitations"`
	}{"codexploit/v1", scope, snap.Commit, files, snap.Limitations}
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	config, _ := json.Marshal(snap.Limits)
	ref := Ref{ID: "artifact-" + scope.SnapshotID + "-files", Kind: "source.snapshot", Scope: scope, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), Bytes: int64(len(raw)), MediaType: "application/json", SchemaID: "codexploit/source-files/v1", Producer: Producer{PluginID: "builtin.snapshot", PluginVersion: "1.0.0", InvocationID: "capture-" + scope.SnapshotID, ConfigDigest: fmt.Sprintf("%x", sha256.Sum256(config))}}
	if _, err = store.Put(ctx, ref, bytes.NewReader(raw), MaxBytes); err != nil {
		return err
	}
	ref.ID = "artifact-" + scope.SnapshotID + "-tree"
	ref.SHA256 = fmt.Sprintf("%x", archiveHash.Sum(nil))
	ref.Bytes = MaxBytes - output.remaining
	ref.MediaType = "application/x-tar"
	ref.SchemaID = "codexploit/source-tar/v1"
	if _, err = archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err = store.Put(ctx, ref, archive, MaxBytes)
	return err
}

type budgetWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, ErrBudget
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}
