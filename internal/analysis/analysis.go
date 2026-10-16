// Package analysis implements the P1 Repository Analyzer: it turns a frozen
// snapshot tree into a repository manifest (languages, frameworks, entrypoints,
// dependencies, build configuration, layout) plus an explicit statement of what
// the analysis could not determine.
//
// Every fact in a manifest is either observed in a file or produced by a named
// rule, and every rule carries an evidence pointer. Nothing is inferred from
// file names alone unless the resulting confidence class says so. Detectors are
// pluggable so language and framework coverage grows without touching this
// package's core.
package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

// SchemaVersion is the version of the manifest document.
const SchemaVersion = 1

// DefaultMaxReadBytes bounds how much of a single file a detector may read.
// Parsers must state when a file was truncated instead of reporting a partial
// parse as complete.
const DefaultMaxReadBytes = 1 << 20 // 1 MiB

// ConfidenceClass states how a fact was obtained. It is a class, never a
// probability: the design doc forbids presenting heuristic confidence as one.
type ConfidenceClass string

const (
	// Observed means the fact was read directly from file content.
	Observed ConfidenceClass = "observed"
	// Inferred means a named rule derived the fact from other observed facts.
	Inferred ConfidenceClass = "inferred"
	// Unresolved means the analysis could not establish the fact.
	Unresolved ConfidenceClass = "unresolved"
)

// Kind classifies a detection.
type Kind string

const (
	KindLanguage    Kind = "language"
	KindDataFormat  Kind = "data_format"
	KindFramework   Kind = "framework"
	KindDependency  Kind = "dependency"
	KindEntrypoint  Kind = "entrypoint"
	KindBuildConfig Kind = "build_config"
	KindLayout      Kind = "layout"
)

// Evidence points at the file that justifies a claim.
type Evidence struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	Note string `json:"note,omitempty"`
}

// Detection is one fact produced by a detector. Counts carries numeric payloads
// (file and byte counts) and Packages carries declared dependencies; both are
// optional and only meaningful for the kinds that document them.
type Detection struct {
	Kind        Kind              `json:"kind"`
	Subject     string            `json:"subject"`
	Detail      map[string]string `json:"detail,omitempty"`
	Counts      map[string]int64  `json:"counts,omitempty"`
	Packages    []Package         `json:"packages,omitempty"`
	Limitations []string          `json:"limitations,omitempty"`
	Confidence  ConfidenceClass   `json:"confidence"`
	Evidence    []Evidence        `json:"evidence,omitempty"`
	// Detector is filled in by the registry with the producing detector name.
	Detector string `json:"detector,omitempty"`
}

// FileInfo describes one file in the snapshot tree.
type FileInfo struct {
	Path string // slash-separated, relative to the tree root
	Size int64
	Base string // file name
	Ext  string // lower-case extension including the dot, or ""
}

// Input is the read-only view of a snapshot tree that detectors work against.
// Detectors cannot escape it: there is no path outside the tree, and reads are
// bounded and accounted for.
type Input struct {
	SnapshotID string
	TreeDir    string
	Files      []FileInfo
	// MaxReadBytes is the effective per-file read limit for this pass. Detectors
	// cannot read more than this, whatever bound they request.
	MaxReadBytes int64

	byPath map[string]FileInfo
	byBase map[string][]FileInfo

	mu        sync.Mutex
	readPaths map[string]bool
	readCalls int
	readBytes int64
	truncated int
}

// ReadStats reports how much of the tree detectors actually read. Coverage in
// the manifest comes from here, not from an assumption about what was read.
// Files counts distinct files; Calls counts every read, which is larger when
// several detectors inspect the same file.
type ReadStats struct {
	Files     int
	Calls     int
	Bytes     int64
	Truncated int
}

// ReadStats returns the accumulated read accounting.
func (in *Input) ReadStats() ReadStats {
	in.mu.Lock()
	defer in.mu.Unlock()
	return ReadStats{Files: len(in.readPaths), Calls: in.readCalls, Bytes: in.readBytes, Truncated: in.truncated}
}

// NewInput walks a frozen tree and indexes its files.
func NewInput(snapshotID, treeDir string) (*Input, error) {
	in := &Input{
		SnapshotID: snapshotID,
		TreeDir:    treeDir,
		byPath:     map[string]FileInfo{},
		byBase:     map[string][]FileInfo{},
		readPaths:  map[string]bool{},
	}
	err := filepath.WalkDir(treeDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(treeDir, p)
		if rerr != nil {
			return rerr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		name := filepath.Base(rel)
		fi := FileInfo{
			Path: filepath.ToSlash(rel),
			Size: info.Size(),
			Base: name,
			Ext:  strings.ToLower(filepath.Ext(name)),
		}
		in.Files = append(in.Files, fi)
		in.byPath[fi.Path] = fi
		in.byBase[fi.Base] = append(in.byBase[fi.Base], fi)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(in.Files, func(i, j int) bool { return in.Files[i].Path < in.Files[j].Path })
	return in, nil
}

// Exists reports whether a path is present in the tree.
func (in *Input) Exists(rel string) bool {
	_, ok := in.byPath[filepath.ToSlash(rel)]
	return ok
}

// ByBase returns every file with the given base name, sorted by path.
func (in *Input) ByBase(base string) []FileInfo {
	out := append([]FileInfo(nil), in.byBase[base]...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// ByExt returns every file with the given lower-case extension, sorted by path.
func (in *Input) ByExt(ext string) []FileInfo {
	ext = strings.ToLower(ext)
	var out []FileInfo
	for _, f := range in.Files {
		if f.Ext == ext {
			out = append(out, f)
		}
	}
	return out
}

// Match returns every file whose record satisfies fn, in path order.
func (in *Input) Match(fn func(FileInfo) bool) []FileInfo {
	var out []FileInfo
	for _, f := range in.Files {
		if fn(f) {
			out = append(out, f)
		}
	}
	return out
}

// readLimit is the enforced per-file read limit of this input.
func (in *Input) readLimit() int64 {
	if in.MaxReadBytes > 0 {
		return in.MaxReadBytes
	}
	return DefaultMaxReadBytes
}

// ReadFile reads at most maxBytes of a tree file, never more than the input's
// own limit. A non-positive maxBytes means "use the input limit". The second
// return value reports truncation so a parser can mark its result as partial
// rather than pretending the whole file was seen.
func (in *Input) ReadFile(rel string, maxBytes int64) ([]byte, bool, error) {
	rel = filepath.ToSlash(rel)
	if _, ok := in.byPath[rel]; !ok {
		return nil, false, fmt.Errorf("analysis: %s is not part of snapshot %s", rel, in.SnapshotID)
	}
	limit := in.readLimit()
	if maxBytes <= 0 || maxBytes > limit {
		maxBytes = limit
	}
	f, err := os.Open(filepath.Join(in.TreeDir, filepath.FromSlash(rel)))
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	buf := make([]byte, maxBytes+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false, err
	}
	truncated := int64(n) > maxBytes
	if truncated {
		n = int(maxBytes)
	}
	in.mu.Lock()
	in.readPaths[rel] = true
	in.readCalls++
	in.readBytes += int64(n)
	if truncated {
		in.truncated++
	}
	in.mu.Unlock()
	return buf[:n], truncated, nil
}

// Detector is the extension point for language, framework and tooling rules.
// Implementations must be deterministic and must cite evidence for every claim.
type Detector interface {
	Name() string
	Version() string
	Detect(ctx context.Context, in *Input) ([]Detection, error)
}

// Registry holds the detectors used by an analyzer, in a deterministic order.
type Registry struct {
	detectors []Detector
}

// NewRegistry builds a registry from the given detectors.
func NewRegistry(detectors ...Detector) *Registry {
	r := &Registry{}
	for _, d := range detectors {
		r.Register(d)
	}
	return r
}

// Register appends a detector. Duplicate names are ignored so that building the
// default registry twice cannot double-count detections.
func (r *Registry) Register(d Detector) {
	if d == nil {
		return
	}
	for _, existing := range r.detectors {
		if existing.Name() == d.Name() {
			return
		}
	}
	r.detectors = append(r.detectors, d)
}

// Detectors returns the registered detectors in evaluation order.
func (r *Registry) Detectors() []Detector {
	return append([]Detector(nil), r.detectors...)
}

// RulesetHash identifies the exact detector set and versions, so that manifests
// produced by different rule sets are never compared as if they were the same
// analysis.
func (r *Registry) RulesetHash() string {
	h := sha256.New()
	fmt.Fprintf(h, "codexploit/ruleset/v%d:%d\n", SchemaVersion, len(r.detectors))
	for _, d := range r.detectors {
		fmt.Fprintf(h, "%d:%s@%s\n", len(d.Name()), d.Name(), d.Version())
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// DefaultRegistry returns the built-in P1 detector set.
func DefaultRegistry() *Registry {
	return NewRegistry(
		NewLanguageDetector(),
		NewDependencyDetector(DefaultParsers()...),
		NewFrameworkDetector(),
		NewEntrypointDetector(),
		NewBuildConfigDetector(),
		NewLayoutDetector(),
	)
}

// Config is the analyzer configuration that participates in the analysis id.
type Config struct {
	MaxReadBytes int64 `json:"max_read_bytes"`
	// MaxPackages caps how many declared dependencies are recorded per manifest.
	// The cap is stated in the manifest instead of silently dropping entries.
	MaxPackages int `json:"max_packages"`
}

// WithDefaults fills zero fields.
func (c Config) WithDefaults() Config {
	if c.MaxReadBytes <= 0 {
		c.MaxReadBytes = DefaultMaxReadBytes
	}
	if c.MaxPackages <= 0 {
		c.MaxPackages = 5000
	}
	return c
}

// Hash is the config_hash component of the analysis id.
func (c Config) Hash() string {
	data, err := json.Marshal(c.WithDefaults())
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}

// Analyzer produces manifests from snapshot trees.
type Analyzer struct {
	Registry *Registry
	Engine   repository.EngineInfo
	Config   Config
}

// DefaultEngine is the engine identity recorded in manifests.
var DefaultEngine = repository.EngineInfo{Name: "codexploit/analysis", Version: "0.1.0"}

// NewAnalyzer builds an analyzer over a detector registry.
func NewAnalyzer(reg *Registry, cfg Config) *Analyzer {
	if reg == nil {
		reg = DefaultRegistry()
	}
	return &Analyzer{Registry: reg, Engine: DefaultEngine, Config: cfg.WithDefaults()}
}

// Analyze inspects a frozen snapshot and returns its manifest. It does not
// write anything: persisting the manifest is an explicit separate step so that
// callers keep control over snapshot immutability.
func (a *Analyzer) Analyze(ctx context.Context, snap *repository.Snapshot) (*Manifest, error) {
	if snap == nil {
		return nil, errors.New("analysis: nil snapshot")
	}
	in, err := NewInput(snap.SnapshotID, snap.TreeDir())
	if err != nil {
		return nil, err
	}
	in.MaxReadBytes = a.Config.WithDefaults().MaxReadBytes
	m, err := a.AnalyzeInput(ctx, in)
	if err != nil {
		return nil, err
	}
	m.Repository = RepositoryInfo{
		Identity:        snap.Identity.Name,
		IdentityKind:    snap.Identity.Kind,
		VCS:             snap.VCS,
		Commit:          snap.Commit,
		RequestedRef:    snap.RequestedRef,
		WorktreeDirty:   snap.WorktreeDirty,
		DirtyPathCount:  snap.DirtyPathCount,
		SubmoduleCount:  len(snap.SubmoduleState),
		SnapshotFiles:   snap.Stats.Files,
		SnapshotBytes:   snap.Stats.Bytes,
		SnapshotSkipped: snap.Stats.SkippedTotal(),
	}
	m.SnapshotLimitations = append(m.SnapshotLimitations, snap.Limitations...)
	m.finishUnknowns()
	return m, nil
}

// AnalyzeInput runs every detector over an input tree.
func (a *Analyzer) AnalyzeInput(ctx context.Context, in *Input) (*Manifest, error) {
	cfg := a.Config.WithDefaults()
	if in.MaxReadBytes <= 0 {
		in.MaxReadBytes = cfg.MaxReadBytes
	}
	// List fields start empty rather than nil so the serialised document always
	// contains arrays: consumers never have to treat null and [] differently.
	m := &Manifest{
		SchemaVersion:       SchemaVersion,
		SnapshotID:          in.SnapshotID,
		Engine:              a.Engine,
		RulesetHash:         a.Registry.RulesetHash(),
		ConfigHash:          cfg.Hash(),
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		Languages:           []LanguageStat{},
		DataFormats:         []FormatStat{},
		Frameworks:          []FrameworkHit{},
		Entrypoints:         []EntrypointHit{},
		BuildConfigs:        []BuildConfigHit{},
		Unknowns:            []string{},
		SnapshotLimitations: []string{},
		Dependencies: DependencySummary{
			Managers: []DependencyManager{},
			Packages: []Package{},
		},
		Layout: LayoutInfo{
			TopLevelDirs:    []string{},
			ModuleRoots:     []string{},
			MonorepoSignals: []LayoutSignal{},
		},
	}
	m.AnalysisID = repository.AnalysisID(in.SnapshotID, a.Engine.Name, a.Engine.Version, m.RulesetHash, m.ConfigHash)

	var detections []Detection
	for _, d := range a.Registry.Detectors() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		got, err := d.Detect(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("analysis: detector %s: %w", d.Name(), err)
		}
		for i := range got {
			got[i].Detector = d.Name()
			if got[i].Confidence == "" {
				got[i].Confidence = Unresolved
			}
			if got[i].Kind == "" {
				got[i].Kind = KindLayout
			}
		}
		detections = append(detections, got...)
	}
	sortDetections(detections)
	m.applyDetections(detections, cfg)

	read := in.ReadStats()
	m.Coverage = Coverage{
		FilesInTree:    len(in.Files),
		FilesRead:      read.Files,
		ReadCalls:      read.Calls,
		BytesRead:      read.Bytes,
		TruncatedReads: read.Truncated,
		Detectors:      detectorNames(a.Registry),
	}
	m.Unknowns = append(m.Unknowns, m.coverageUnknowns()...)
	m.finishUnknowns()
	return m, nil
}

func detectorNames(r *Registry) []string {
	var names []string
	for _, d := range r.Detectors() {
		names = append(names, d.Name()+"@"+d.Version())
	}
	sort.Strings(names)
	return names
}

// sortDetections gives manifests a stable order independent of detector run
// order, which keeps diffs and hashes meaningful.
func sortDetections(ds []Detection) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Kind != ds[j].Kind {
			return ds[i].Kind < ds[j].Kind
		}
		if ds[i].Subject != ds[j].Subject {
			return ds[i].Subject < ds[j].Subject
		}
		return ds[i].Detector < ds[j].Detector
	})
}
