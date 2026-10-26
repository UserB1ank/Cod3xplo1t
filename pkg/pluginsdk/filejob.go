package pluginsdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var ErrJob = errors.New("plugin SDK: invalid or unbound file job")

// ReadJob rejects unknown fields and oversized requests. Execution identity is
// fixed by the host; a caller must not substitute arbitrary local input paths.
func ReadJob(path string) (JobRequest, error) {
	var request JobRequest
	f, err := os.Open(path)
	if err != nil {
		return request, ErrJob
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return request, ErrJob
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || (request.APIVersion != "codexploit/file-job/v1" && request.APIVersion != "codexploit/file-job/v2") || request.InvocationID == "" || request.OperationID == "" || !safeRelative(request.OutputDirectory) || request.Budget.MaxInputBytes < 1 || request.Budget.MaxOutputBytes < 1 {
		return JobRequest{}, ErrJob
	}
	for _, input := range request.Inputs {
		if request.APIVersion == "codexploit/file-job/v2" && input.ArtifactID == "" {
			return JobRequest{}, ErrJob
		}
		if (!safeRelative(input.Path) && !(input.SchemaID == "codexploit/source-directory/v1" && filepath.IsAbs(input.Path))) || input.Bytes < 0 || len(input.SHA256) != 64 {
			return JobRequest{}, ErrJob
		}
	}
	return request, nil
}

func safeRelative(path string) bool {
	return path != "" && path != "." && path != ".." && !filepath.IsAbs(path) && !strings.HasPrefix(path, "../") && !strings.ContainsAny(path, "\\:\x00\r\n") && filepath.ToSlash(filepath.Clean(path)) == path
}

// ReadInput reads only the selected bound port and verifies the host's content
// digest. Larger integrations can stream through os.Root and apply the same
// byte and SHA-256 checks while materializing a private input tree.
func ReadInput(jobRoot string, request JobRequest, port string) ([]byte, error) {
	var selected *LocalInput
	for i := range request.Inputs {
		if request.Inputs[i].Port == port {
			if selected != nil {
				return nil, ErrJob
			}
			selected = &request.Inputs[i]
		}
	}
	if selected == nil || !safeRelative(selected.Path) || selected.Bytes > request.Budget.MaxInputBytes {
		return nil, ErrJob
	}
	root, err := os.OpenRoot(jobRoot)
	if err != nil {
		return nil, ErrJob
	}
	defer root.Close()
	info, err := root.Lstat(filepath.FromSlash(selected.Path))
	if err != nil || !info.Mode().IsRegular() || info.Size() != selected.Bytes {
		return nil, ErrJob
	}
	file, err := root.Open(filepath.FromSlash(selected.Path))
	if err != nil {
		return nil, ErrJob
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, selected.Bytes+1))
	if err != nil || int64(len(raw)) != selected.Bytes || fmt.Sprintf("%x", sha256.Sum256(raw)) != selected.SHA256 {
		return nil, ErrJob
	}
	return raw, nil
}

// WriteResult writes the protocol response atomically within the exclusive job.
// All output files must already be complete; success still requires host checks.
func WriteResult(path string, result JobResult) error {
	if (result.APIVersion != "codexploit/file-job/v1" && result.APIVersion != "codexploit/file-job/v2") || result.InvocationID == "" {
		return ErrJob
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 1<<20 {
		return ErrJob
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".plugin-result-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// SourceDirectory resolves a host-bound read-only directory. It inventories
// paths and sizes only; source content digests and archives are not required.
func SourceDirectory(request JobRequest, port string) (string, map[string]bool, error) {
	var selected *LocalInput
	for i := range request.Inputs {
		if request.Inputs[i].Port == port {
			if selected != nil {
				return "", nil, ErrJob
			}
			selected = &request.Inputs[i]
		}
	}
	if selected == nil || selected.SchemaID != "codexploit/source-directory/v1" || !filepath.IsAbs(selected.Path) || selected.Bytes > request.Budget.MaxInputBytes {
		return "", nil, ErrJob
	}
	root, err := os.OpenRoot(selected.Path)
	if err != nil {
		return "", nil, ErrJob
	}
	defer root.Close()
	files := map[string]bool{}
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 {
			return ErrJob
		}
		if info.Size() > request.Budget.MaxInputBytes-total {
			return ErrJob
		}
		total += info.Size()
		files[name] = true
		return nil
	})
	if err != nil {
		return "", nil, ErrJob
	}
	return selected.Path, files, nil
}
