// Package plugin defines versioned manifests and the execution host ports.
package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
)

var (
	ErrInvalid           = errors.New("plugin: invalid manifest, configuration or execution request")
	ErrConflict          = errors.New("plugin: immutable version or invocation conflicts")
	ErrNotFound          = errors.New("plugin: record not found in scope")
	ErrUnsupported       = errors.New("plugin: this version is not installed or executable")
	ErrExecutionFailed   = errors.New("plugin: executor reported failure")
	ErrProtocolViolation = errors.New("plugin: process protocol violation")
)

// ExecutionError is a bounded, non-secret failure code reported by an executor.
type ExecutionError struct{ Code string }

func (e *ExecutionError) Error() string { return "plugin: execution failed: " + e.Code }
func (e *ExecutionError) Unwrap() error { return ErrExecutionFailed }

type Manifest struct {
	APIVersion  string   `json:"api_version"`
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Kind        string   `json:"kind"`
	Languages   []string `json:"languages"`
	Runtime     struct {
		Kind       string `json:"kind"`
		Entrypoint string `json:"entrypoint,omitempty"`
	} `json:"runtime"`
	Consumes    []string `json:"consumes"`
	Produces    []string `json:"produces"`
	Permissions struct {
		Network     string `json:"network"`
		SourceWrite bool   `json:"source_write"`
	} `json:"permissions"`
	ConfigSchema json.RawMessage `json:"config_schema"`
}

type Record struct {
	Manifest       Manifest `json:"manifest"`
	PackageDigest  string   `json:"package_digest"`
	ManifestDigest string   `json:"manifest_digest"`
	Source         string   `json:"source"`
	Installed      bool     `json:"installed"`
	Executable     bool     `json:"executable"`
	Reason         string   `json:"reason,omitempty"`
}

type CatalogRepository interface {
	PutPlugin(context.Context, Record) error
	GetPlugin(context.Context, string, string) (Record, error)
	ListPlugins(context.Context, string, int) ([]Record, error)
}

type Catalog struct {
	Repository CatalogRepository
	mu         sync.RWMutex
	installed  map[string]string
	executable map[string]bool
}

var manifestSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile("plugin.schema.json")
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
})

func digest(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func resolveConfig(raw json.RawMessage) (*jsonschema.Resolved, error) {
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, ErrInvalid
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{Loader: func(*url.URL) (*jsonschema.Schema, error) { return nil, ErrInvalid }})
	if err != nil {
		return nil, ErrInvalid
	}
	return resolved, nil
}

func (c *Catalog) Register(ctx context.Context, raw json.RawMessage, packageDigest, source string) (Record, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return Record{}, ErrInvalid
	}
	schema, err := manifestSchema()
	if err != nil {
		return Record{}, err
	}
	if schema.Validate(value) != nil {
		return Record{}, ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return Record{}, err
	}
	var manifest Manifest
	if json.Unmarshal(canonical, &manifest) != nil {
		return Record{}, ErrInvalid
	}
	if _, err := resolveConfig(manifest.ConfigSchema); err != nil {
		return Record{}, err
	}
	if len(packageDigest) != 64 || len(source) == 0 || len(source) > 200 {
		return Record{}, ErrInvalid
	}
	for _, r := range packageDigest {
		if !((r >= 'a' && r <= 'f') || (r >= '0' && r <= '9')) {
			return Record{}, ErrInvalid
		}
	}
	record := Record{Manifest: manifest, PackageDigest: packageDigest, ManifestDigest: digest(canonical), Source: source}
	if err := c.Repository.PutPlugin(ctx, record); err != nil {
		return Record{}, err
	}
	return c.Get(ctx, manifest.ID, manifest.Version)
}

func (c *Catalog) availability(record Record) Record {
	key := record.Manifest.ID + "@" + record.Manifest.Version
	identity := record.ManifestDigest + ":" + record.PackageDigest
	c.mu.RLock()
	record.Installed = c.installed[key] == identity
	record.Executable = record.Installed && c.executable[key]
	c.mu.RUnlock()
	switch {
	case record.Executable:
		record.Reason = ""
	case record.Installed:
		record.Reason = "Package installed; this host has no execution adapter for its runtime"
	default:
		record.Reason = "Manifest registered; this package has no installed execution adapter"
	}
	return record
}

func (c *Catalog) Get(ctx context.Context, id, version string) (Record, error) {
	r, err := c.Repository.GetPlugin(ctx, id, version)
	if err != nil {
		return Record{}, err
	}
	return c.availability(r), nil
}
func (c *Catalog) List(ctx context.Context, cursor string, limit int) ([]Record, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := c.Repository.ListPlugins(ctx, cursor, limit)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i] = c.availability(rows[i])
	}
	return rows, nil
}

func NewCatalog(ctx context.Context, repo CatalogRepository) (*Catalog, error) {
	c := &Catalog{Repository: repo, installed: map[string]string{}, executable: map[string]bool{}}
	err := c.install(ctx, BuiltinManifest(), BuiltinPackageDigest(), "compiled builtin")
	return c, err
}

func (c *Catalog) install(ctx context.Context, manifest json.RawMessage, packageDigest, source string) error {
	record, err := c.Register(ctx, manifest, packageDigest, source)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.installed[record.Manifest.ID+"@"+record.Manifest.Version] = record.ManifestDigest + ":" + record.PackageDigest
	c.executable[record.Manifest.ID+"@"+record.Manifest.Version] = true
	c.mu.Unlock()
	return nil
}

// InstallPackage registers a verified local process package and marks it
// installed. The manifest is the package's own canonical manifest, so the
// caller cannot claim a different package digest than the bytes on disk.
func (c *Catalog) InstallPackage(ctx context.Context, directory string) (Record, error) {
	pkg, err := LoadPackage(directory)
	if err != nil {
		return Record{}, err
	}
	record, err := c.Register(ctx, pkg.RawManifest, pkg.PackageDigest, "local package "+pkg.Manifest.ID+"@"+pkg.Manifest.Version)
	if err != nil {
		return Record{}, err
	}
	c.mu.Lock()
	c.installed[record.Manifest.ID+"@"+record.Manifest.Version] = record.ManifestDigest + ":" + record.PackageDigest
	c.executable[record.Manifest.ID+"@"+record.Manifest.Version] = true
	c.mu.Unlock()
	return c.Get(ctx, record.Manifest.ID, record.Manifest.Version)
}
