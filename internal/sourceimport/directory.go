package sourceimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DirectoryManifest describes the exact bytes selected by the browser. Paths
// are relative to the selected root; the root's local name is never transmitted.
type DirectoryManifest struct {
	Files    []DirectoryFile `json:"files"`
	Excluded []string        `json:"excluded"`
}

type DirectoryFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ExtractDirectory streams multipart file parts through the same screened tree
// used for archives. A canonical manifest digest makes retries independent of
// the browser's random multipart boundary and file enumeration order.
func ExtractDirectory(ctx context.Context, input io.Reader, contentType string) (_ *Upload, err error) {
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil || media != "multipart/form-data" || params["boundary"] == "" {
		return nil, ErrInvalid
	}
	bounded := &io.LimitedReader{R: contextReader{ctx, input}, N: 192<<20 + 1}
	r := multipart.NewReader(bounded, params["boundary"])
	part, err := r.NextPart()
	if err != nil || part.FormName() != "manifest" {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(part, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		return nil, ErrBudget
	}
	var manifest DirectoryManifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrInvalid
	}
	if len(manifest.Files) == 0 {
		return nil, ErrInvalid
	}
	if len(manifest.Files)+len(manifest.Excluded) > MaxFiles {
		return nil, ErrBudget
	}
	wanted := make(map[string]DirectoryFile, len(manifest.Files))
	var total int64
	for _, file := range manifest.Files {
		digest, decodeErr := hex.DecodeString(file.SHA256)
		if !validName(file.Path) || decodeErr != nil || len(digest) != 32 || strings.ToLower(file.SHA256) != file.SHA256 {
			return nil, ErrInvalid
		}
		if file.Size < 0 || file.Size > MaxFileBytes || file.Size > MaxExpandedBytes-total {
			return nil, ErrBudget
		}
		if _, exists := wanted[file.Path]; exists {
			return nil, ErrInvalid
		}
		wanted[file.Path] = file
		total += file.Size
	}
	for _, name := range manifest.Excluded {
		if !validName(name) || !ExcludedPath(name) {
			return nil, ErrInvalid
		}
	}
	if total == 0 {
		return nil, ErrInvalid
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	sort.Strings(manifest.Excluded)
	canonical, _ := json.Marshal(manifest)
	dir, err := os.MkdirTemp("", "codexploit-source-import-*")
	if err != nil {
		return nil, err
	}
	u := &Upload{dir: dir, Tree: filepath.Join(dir, "tree"), Report: Report{Format: "directory", SHA256: fmt.Sprintf("%x", sha256.Sum256(canonical)), Bytes: total, Excluded: []string{}}}
	defer func() {
		if err != nil {
			_ = u.Close()
		}
	}()
	if err := os.Mkdir(u.Tree, 0700); err != nil {
		return nil, err
	}
	stage := extractor{upload: u, seen: map[string]bool{}}
	// Excluded names carry no file content, but still obey duplicate/path rules.
	for _, name := range manifest.Excluded {
		if err := stage.add(ctx, name, false, 0, strings.NewReader("")); err != nil {
			return nil, err
		}
	}
	for {
		part, readErr := r.NextPart()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, ErrInvalid
		}
		_, disposition, parseErr := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		name := disposition["filename"] // Part.FileName intentionally strips nested paths.
		file, exists := wanted[name]
		if parseErr != nil || part.FormName() != "files" || !exists {
			return nil, ErrInvalid
		}
		hash := sha256.New()
		if err := stage.add(ctx, name, false, file.Size, io.TeeReader(part, hash)); err != nil {
			return nil, err
		}
		if fmt.Sprintf("%x", hash.Sum(nil)) != file.SHA256 {
			return nil, ErrInvalid
		}
		delete(wanted, name)
	}
	if bounded.N <= 0 {
		return nil, ErrBudget
	}
	if len(wanted) != 0 || u.Report.Files == 0 {
		return nil, ErrInvalid
	}
	return u, nil
}
