package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/jsonschema-go/jsonschema"
)

type FileLock struct {
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable"`
}

type FilesLock struct {
	APIVersion string     `json:"api_version"`
	Files      []FileLock `json:"files"`
}

var filesLockSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) { return resolveV2Schema("files.lock.schema.json") })

// BuildFilesLock prepares a deterministic payload inventory without installing
// or executing code. The caller writes it and registers the expected release.
func BuildFilesLock(directory string) ([]byte, error) {
	files, err := packageFilesBounded(directory, MaxStagePackageBytes, MaxStagePackageFiles)
	if err != nil {
		return nil, err
	}
	lock := FilesLock{APIVersion: "codexploit/plugin-files/v2", Files: []FileLock{}}
	for _, f := range files {
		if f.name != "files.lock.json" {
			lock.Files = append(lock.Files, FileLock{f.name, f.size, f.digest, f.executable})
		}
	}
	raw, err := json.Marshal(lock)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

func verifyFilesLock(directory string, manifest []byte, files []packageFile) (string, error) {
	path := filepath.Join(directory, "files.lock.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return "", ErrInvalid
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", ErrInvalid
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return "", ErrInvalid
	}
	var value any
	if json.Unmarshal(canonical, &value) != nil {
		return "", ErrInvalid
	}
	schema, err := filesLockSchema()
	if err != nil {
		return "", err
	}
	if schema.Validate(value) != nil {
		return "", ErrInvalid
	}
	var lock FilesLock
	if json.Unmarshal(canonical, &lock) != nil || len(lock.Files) != len(files) {
		return "", ErrInvalid
	}
	for i, file := range files {
		wanted := lock.Files[i]
		if wanted.Path != file.name || wanted.Bytes != file.size || wanted.SHA256 != file.digest || wanted.Executable != file.executable {
			return "", ErrConflict
		}
	}
	return digest([]byte("codexploit/plugin-release/v2\n" + digest(manifest) + "\n" + digest(canonical) + "\n")), nil
}
