package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// A process plugin package is a directory containing manifest.json and the
// files it declares. The package digest binds the canonical manifest and every
// other regular file, so two installs of one version cannot silently differ.
const (
	MaxPackageFiles  = 1000
	MaxPackageBytes  = 128 << 20
	maxManifestBytes = 256 << 10
)

// Package is one verified, locally installed process plugin package.
type Package struct {
	Directory        string
	Manifest         Manifest
	RawManifest      json.RawMessage
	ManifestDigest   string
	PackageDigest    string
	Entrypoint       string
	Executable       string
	ExecutableSHA256 string
	ExecutableBytes  int64
}

// LoadPackage verifies one package directory without executing anything. A
// missing entrypoint is reported as unsupported; a malformed or escaping one is
// invalid.
func LoadPackage(directory string) (Package, error) {
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return Package{}, ErrInvalid
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() > maxManifestBytes {
		return Package{}, ErrInvalid
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Package{}, ErrInvalid
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return Package{}, ErrInvalid
	}
	schema, err := manifestSchema()
	if err != nil {
		return Package{}, err
	}
	if schema.Validate(value) != nil {
		return Package{}, ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return Package{}, ErrInvalid
	}
	var manifest Manifest
	if json.Unmarshal(canonical, &manifest) != nil {
		return Package{}, ErrInvalid
	}
	if _, err := resolveConfig(manifest.ConfigSchema); err != nil {
		return Package{}, err
	}
	if manifest.Runtime.Kind != "process" {
		return Package{}, ErrUnsupported
	}
	entrypoint, err := safeEntrypoint(manifest.Runtime.Entrypoint)
	if err != nil {
		return Package{}, err
	}

	files, err := packageFiles(directory, manifestPath)
	if err != nil {
		return Package{}, err
	}
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, "codexploit/plugin-package/v1\n")
	hasher.Write(canonical)
	hasher.Write([]byte{'\n'})
	for _, file := range files {
		hasher.Write([]byte(file.name))
		hasher.Write([]byte{0})
		hasher.Write([]byte(fmt.Sprintf("%d", file.size)))
		hasher.Write([]byte{0})
		hasher.Write([]byte(file.digest))
		hasher.Write([]byte{'\n'})
	}
	executable, err := resolveEntrypoint(directory, entrypoint)
	if err != nil {
		return Package{}, err
	}
	relative, err := filepath.Rel(directory, executable)
	if err != nil {
		return Package{}, ErrInvalid
	}
	relative = filepath.ToSlash(relative)
	var executableDigest string
	var executableBytes int64
	for _, file := range files {
		if file.name == relative {
			executableDigest, executableBytes = file.digest, file.size
		}
	}
	if executableDigest == "" {
		return Package{}, ErrInvalid
	}
	return Package{
		Directory:        directory,
		Manifest:         manifest,
		RawManifest:      canonical,
		ManifestDigest:   digest(canonical),
		PackageDigest:    hex.EncodeToString(hasher.Sum(nil)),
		Entrypoint:       entrypoint,
		Executable:       executable,
		ExecutableSHA256: executableDigest,
		ExecutableBytes:  executableBytes,
	}, nil
}

type packageFile struct {
	name   string
	size   int64
	digest string
}

// packageFiles walks the package once. Symlinks, special files, duplicate
// case-folded names and names outside the package are rejected rather than
// followed.
func packageFiles(directory, manifestPath string) ([]packageFile, error) {
	var files []packageFile
	seen := map[string]bool{}
	var total int64
	err := filepath.WalkDir(directory, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrInvalid
		}
		if current == directory {
			return nil
		}
		relative, err := filepath.Rel(directory, current)
		if err != nil {
			return ErrInvalid
		}
		relative = filepath.ToSlash(relative)
		if relative == "manifest.json" {
			return nil
		}
		if relative == "" || strings.HasPrefix(relative, "../") || strings.HasPrefix(relative, "/") || strings.ContainsAny(relative, "\\\x00\n\r:") {
			return ErrInvalid
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
			return ErrInvalid
		}
		folded := strings.ToLower(relative)
		if seen[folded] {
			return ErrInvalid
		}
		seen[folded] = true
		total += info.Size()
		if total > MaxPackageBytes || len(files) >= MaxPackageFiles {
			return ErrBudget
		}
		file, err := os.Open(filepath.Join(directory, filepath.FromSlash(relative)))
		if err != nil {
			return ErrInvalid
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(hasher, io.LimitReader(file, MaxPackageBytes+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != info.Size() {
			return ErrInvalid
		}
		files = append(files, packageFile{name: relative, size: info.Size(), digest: hex.EncodeToString(hasher.Sum(nil))})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files, nil
}

func safeEntrypoint(entrypoint string) (string, error) {
	if entrypoint == "" || len(entrypoint) > 240 || strings.ContainsAny(entrypoint, "\\\x00\n\r:") {
		return "", ErrInvalid
	}
	if path.IsAbs(entrypoint) {
		return "", ErrInvalid
	}
	cleaned := path.Clean(entrypoint)
	if cleaned != entrypoint || cleaned == "." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return "", ErrInvalid
	}
	return cleaned, nil
}

func resolveEntrypoint(directory, entrypoint string) (string, error) {
	candidates := []string{filepath.Join(directory, filepath.FromSlash(entrypoint))}
	if runtime.GOOS == "windows" && filepath.Ext(entrypoint) == "" {
		candidates = append(candidates, filepath.Join(directory, filepath.FromSlash(entrypoint)+".exe"))
	}
	for _, candidate := range candidates {
		relative, err := filepath.Rel(directory, candidate)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", ErrInvalid
		}
		info, err := os.Lstat(candidate)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			return "", ErrInvalid
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
			return "", ErrUnsupported
		}
		return candidate, nil
	}
	return "", ErrUnsupported
}

// DiscoverPackages returns every verified process package below root, sorted by
// ID@version. A missing root is an empty installation, not an error.
func DiscoverPackages(root string) ([]Package, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return []Package{}, nil
	}
	if err != nil {
		return nil, err
	}
	var packages []Package
	seen := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		directory := filepath.Join(root, entry.Name())
		if _, err := os.Lstat(filepath.Join(directory, "manifest.json")); err != nil {
			continue
		}
		pkg, err := LoadPackage(directory)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", directory, err)
		}
		key := pkg.Manifest.ID + "@" + pkg.Manifest.Version
		if seen[key] {
			return nil, fmt.Errorf("%w: duplicate package %s", ErrConflict, key)
		}
		seen[key] = true
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Manifest.ID != packages[j].Manifest.ID {
			return packages[i].Manifest.ID < packages[j].Manifest.ID
		}
		return packages[i].Manifest.Version < packages[j].Manifest.Version
	})
	return packages, nil
}
