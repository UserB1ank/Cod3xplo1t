// Package sourceimport receives bounded uploads as isolated, data-only trees.
package sourceimport

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

const (
	MaxUploadBytes   int64 = 64 << 20
	MaxExpandedBytes int64 = 128 << 20
	MaxFileBytes     int64 = 4 << 20
	MaxFiles               = 10000
)

var (
	ErrInvalid = errors.New("源码包无效：请使用 ZIP、TAR 或 TAR.GZ，且只包含普通文件与目录")
	ErrBudget  = errors.New("源码上传超限：压缩包最多 64 MiB，展开最多 128 MiB、10000 项，单文件最多 4 MiB")
)

type Report struct {
	Format   string   `json:"format"`
	SHA256   string   `json:"sha256"`
	Bytes    int64    `json:"bytes"`
	Files    int      `json:"files"`
	Skipped  int      `json:"skipped"`
	Excluded []string `json:"excluded"`
}

type Upload struct {
	Report Report
	Tree   string
	dir    string
}

func (u *Upload) Close() error { return os.RemoveAll(u.dir) }

// CleanupExpired removes abandoned upload staging after a process crash. Live
// uploads have a two-minute deadline; one hour leaves a conservative grace.
// It never follows links or removes directories belonging to another feature.
func CleanupExpired(ctx context.Context, parent string, now time.Time) error {
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	checked := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, readErr := directory.ReadDir(100)
		for _, entry := range entries {
			checked++
			if checked > 10000 {
				return ErrBudget
			}
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "codexploit-source-import-") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if now.Sub(info.ModTime()) < time.Hour {
				continue
			}
			if err := root.RemoveAll(entry.Name()); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

// ExcludedPath is shared by directory selection and server-side validation.
func ExcludedPath(name string) bool {
	for _, part := range strings.Split(name, "/") {
		lower := strings.ToLower(part)
		if strings.HasPrefix(lower, ".env") || strings.HasPrefix(lower, "._") || lower == "__macosx" || lower == ".ssh" || strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") {
			return true
		}
		for _, key := range []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"} {
			if strings.HasPrefix(lower, key) {
				return true
			}
		}
		for _, ignored := range repository.DefaultIgnoreDirs {
			if lower == strings.ToLower(ignored) {
				return true
			}
		}
	}
	return false
}

func validName(name string) bool {
	if len(name) > 2048 || !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\\:\x00") || strings.Count(name, "/") >= 32 {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.TrimRight(part, " .") != part {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9') {
			return false
		}
	}
	return !strings.ContainsFunc(name, unicode.IsControl)
}

type contextReader struct {
	context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.Context.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

// Extract cleans up every unsuccessful request. Only the screened tree is
// handed to the snapshot manager; the original archive is never published.
func Extract(ctx context.Context, input io.Reader, format string) (_ *Upload, err error) {
	if format != "zip" && format != "tar" && format != "tar.gz" {
		return nil, ErrInvalid
	}
	dir, err := os.MkdirTemp("", "codexploit-source-import-*")
	if err != nil {
		return nil, err
	}
	u := &Upload{dir: dir, Tree: filepath.Join(dir, "tree"), Report: Report{Format: format, Excluded: []string{}}}
	defer func() {
		if err != nil {
			_ = u.Close()
		}
	}()
	if err := os.Mkdir(u.Tree, 0700); err != nil {
		return nil, err
	}
	archive, err := os.Create(filepath.Join(dir, "archive"))
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(contextReader{ctx, input}, MaxUploadBytes+1))
	if err != nil {
		return nil, err
	}
	if n > MaxUploadBytes {
		return nil, ErrBudget
	}
	u.Report.Bytes, u.Report.SHA256 = n, fmt.Sprintf("%x", hash.Sum(nil))
	stage := extractor{upload: u, seen: map[string]bool{}}
	if format == "zip" {
		if err := checkZipDirectory(archive, n); err != nil {
			return nil, err
		}
		zr, err := zip.NewReader(archive, n)
		if err != nil {
			return nil, ErrInvalid
		}
		if len(zr.File) > MaxFiles {
			return nil, ErrBudget
		}
		for _, file := range zr.File {
			if file.Flags&1 != 0 {
				return nil, ErrInvalid
			}
			if !file.Mode().IsRegular() && !file.FileInfo().IsDir() {
				return nil, ErrInvalid
			}
			if file.UncompressedSize64 > uint64(MaxFileBytes) {
				return nil, ErrBudget
			}
			reader, err := file.Open()
			if err != nil {
				return nil, ErrInvalid
			}
			err = stage.add(ctx, file.Name, file.FileInfo().IsDir(), int64(file.UncompressedSize64), reader)
			closeErr := reader.Close()
			if err != nil {
				return nil, err
			}
			if closeErr != nil {
				return nil, ErrInvalid
			}
		}
	} else {
		if _, err := archive.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		var input io.Reader = archive
		if format == "tar.gz" {
			gz, err := gzip.NewReader(archive)
			if err != nil {
				return nil, ErrInvalid
			}
			defer gz.Close()
			input = gz
		}
		bounded := &io.LimitedReader{R: contextReader{ctx, input}, N: MaxExpandedBytes + 1}
		tr := tar.NewReader(bounded)
		var padding int64
		for {
			remaining := bounded.N
			header, err := tr.Next()
			if bounded.N == 0 {
				return nil, ErrBudget
			}
			if errors.Is(err, io.EOF) {
				if remaining-bounded.N < padding+1024 {
					return nil, ErrInvalid
				}
				break
			}
			if err != nil {
				return nil, ErrInvalid
			}
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
				return nil, ErrInvalid
			}
			if err := stage.add(ctx, header.Name, header.Typeflag == tar.TypeDir, header.Size, tr); err != nil {
				return nil, err
			}
			padding = (512 - header.Size%512) % 512
		}
		// Read to the actual end, verifying the gzip trailer and rejecting
		// concatenated non-padding data after the tar end marker.
		var tail [4096]byte
		for {
			n, err := bounded.Read(tail[:])
			if bounded.N == 0 {
				return nil, ErrBudget
			}
			for _, value := range tail[:n] {
				if value != 0 {
					return nil, ErrInvalid
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, ErrInvalid
			}
		}
	}
	if u.Report.Files == 0 {
		return nil, ErrInvalid
	}
	entries, err := os.ReadDir(u.Tree)
	if err != nil {
		return nil, err
	}
	if len(entries) == 1 && entries[0].IsDir() {
		u.Tree = filepath.Join(u.Tree, entries[0].Name())
	}
	return u, nil
}

// Bound the central directory before archive/zip allocates its File list. The
// ZIP record count is untrusted and may understate the actual directory size.
func checkZipDirectory(archive io.ReaderAt, size int64) error {
	length := min(size, int64(65535+22))
	if length < 22 {
		return ErrInvalid
	}
	tail := make([]byte, int(length))
	if _, err := archive.ReadAt(tail, size-length); err != nil {
		return ErrInvalid
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == 0x06054b50 && i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) == len(tail) {
			end = i
			break
		}
	}
	if end < 0 {
		return ErrInvalid
	}
	record := tail[end:]
	count := int(binary.LittleEndian.Uint16(record[10:]))
	if count > MaxFiles {
		return ErrBudget
	}
	if binary.LittleEndian.Uint16(record[4:]) != 0 || binary.LittleEndian.Uint16(record[6:]) != 0 || int(binary.LittleEndian.Uint16(record[8:])) != count {
		return ErrInvalid
	}
	position := int64(binary.LittleEndian.Uint32(record[16:]))
	directoryEnd := position + int64(binary.LittleEndian.Uint32(record[12:]))
	if directoryEnd != size-length+int64(end) {
		return ErrInvalid
	}
	var header [46]byte
	actual := 0
	for position < directoryEnd {
		actual++
		if actual > MaxFiles {
			return ErrBudget
		}
		if position+46 > directoryEnd {
			return ErrInvalid
		}
		if _, err := archive.ReadAt(header[:], position); err != nil || binary.LittleEndian.Uint32(header[:]) != 0x02014b50 {
			return ErrInvalid
		}
		name := int64(binary.LittleEndian.Uint16(header[28:]))
		if name > 2048 {
			return ErrInvalid
		}
		position += 46 + name + int64(binary.LittleEndian.Uint16(header[30:])) + int64(binary.LittleEndian.Uint16(header[32:]))
		if position > directoryEnd {
			return ErrInvalid
		}
	}
	if actual != count {
		return ErrInvalid
	}
	return nil
}

type extractor struct {
	upload   *Upload
	seen     map[string]bool
	entries  int
	expanded int64
}

func (s *extractor) add(ctx context.Context, raw string, directory bool, size int64, reader io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.entries++
	if s.entries > MaxFiles {
		return ErrBudget
	}
	name := strings.TrimSuffix(raw, "/")
	if !validName(name) || size < 0 || (directory && size != 0) {
		return ErrInvalid
	}
	key := strings.ToLower(name)
	if _, exists := s.seen[key]; exists {
		return ErrInvalid
	}
	for parent := path.Dir(key); parent != "."; parent = path.Dir(parent) {
		if isDir, exists := s.seen[parent]; exists && !isDir {
			return ErrInvalid
		}
	}
	if !directory {
		for prior := range s.seen {
			if strings.HasPrefix(prior, key+"/") {
				return ErrInvalid
			}
		}
	}
	s.seen[key] = directory
	if directory {
		return nil
	}
	if size > MaxFileBytes || size > MaxExpandedBytes-s.expanded {
		return ErrBudget
	}
	var target io.Writer = io.Discard
	var output *os.File
	if ExcludedPath(name) {
		s.upload.Report.Skipped++
		if len(s.upload.Report.Excluded) < 200 {
			s.upload.Report.Excluded = append(s.upload.Report.Excluded, name)
		}
	} else {
		filename := filepath.Join(s.upload.Tree, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			return ErrInvalid
		}
		var err error
		output, err = os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return ErrInvalid
		}
		target = output
	}
	copied, copyErr := io.Copy(target, io.LimitReader(contextReader{ctx, reader}, MaxFileBytes+1))
	if output != nil {
		if err := output.Close(); copyErr == nil {
			copyErr = err
		}
	}
	if copyErr != nil || copied != size {
		return ErrInvalid
	}
	s.expanded += copied
	if output != nil {
		s.upload.Report.Files++
	}
	return nil
}
