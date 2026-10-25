package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func safeRelative(path string) bool {
	return path != "" && path != "." && path != ".." && !filepath.IsAbs(path) && !strings.HasPrefix(path, "../") && !strings.ContainsAny(path, "\\:\x00\r\n") && filepath.ToSlash(filepath.Clean(path)) == path
}

func sourceTree(raw []byte, destination string) (map[string]bool, error) {
	if err := os.Mkdir(destination, 0700); err != nil {
		return nil, err
	}
	files, seen := map[string]bool{}, map[string]bool{}
	reader := tar.NewReader(bytes.NewReader(raw))
	var total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(header.Name, "/")
		if !safeRelative(name) || seen[strings.ToLower(name)] || len(seen) >= 20000 || header.Size < 0 || header.Size > 64<<20 || header.Size > int64(len(raw))-total {
			return nil, pluginsdk.ErrJob
		}
		seen[strings.ToLower(name)] = true
		path := filepath.Join(destination, filepath.FromSlash(name))
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(path, 0700); err != nil {
				return nil, err
			}
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return nil, pluginsdk.ErrJob
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
		if err != nil {
			return nil, err
		}
		written, copyErr := io.CopyN(file, reader, header.Size)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != header.Size {
			return nil, pluginsdk.ErrJob
		}
		files[name] = true
		total += written
	}
	return files, nil
}
