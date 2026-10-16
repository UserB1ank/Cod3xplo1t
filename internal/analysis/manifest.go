package analysis

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

// RepositoryInfo restates the facts the snapshot already pinned, so a manifest
// can be interpreted without loading the snapshot separately.
type RepositoryInfo struct {
	Identity        string `json:"identity"`
	IdentityKind    string `json:"identity_kind"`
	VCS             string `json:"vcs"`
	Commit          string `json:"commit"`
	RequestedRef    string `json:"requested_ref,omitempty"`
	WorktreeDirty   bool   `json:"worktree_dirty"`
	DirtyPathCount  int    `json:"dirty_path_count"`
	SubmoduleCount  int    `json:"submodule_count"`
	SnapshotFiles   int    `json:"snapshot_files"`
	SnapshotBytes   int64  `json:"snapshot_bytes"`
	SnapshotSkipped int    `json:"snapshot_skipped"`
}

// LanguageStat is the file and byte footprint of one source language.
type LanguageStat struct {
	Name     string     `json:"name"`
	Files    int        `json:"files"`
	Bytes    int64      `json:"bytes"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// FormatStat is the footprint of a non-source format (JSON, YAML, Markdown...).
type FormatStat struct {
	Name  string `json:"name"`
	Files int    `json:"files"`
	Bytes int64  `json:"bytes"`
}

// FrameworkHit is one detected web/service framework.
type FrameworkHit struct {
	Name       string            `json:"name"`
	Language   string            `json:"language,omitempty"`
	Confidence ConfidenceClass   `json:"confidence"`
	Detail     map[string]string `json:"detail,omitempty"`
	Evidence   []Evidence        `json:"evidence,omitempty"`
	Detector   string            `json:"detector,omitempty"`
}

// EntrypointHit is one executable or request entry into the repository.
type EntrypointHit struct {
	Path       string          `json:"path"`
	Type       string          `json:"type"`
	Language   string          `json:"language,omitempty"`
	Confidence ConfidenceClass `json:"confidence"`
	Evidence   []Evidence      `json:"evidence,omitempty"`
}

// BuildConfigHit is one build, packaging, CI or deployment descriptor.
type BuildConfigHit struct {
	Path     string     `json:"path"`
	Type     string     `json:"type"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// LayoutSignal is one structural signal, for example a monorepo marker.
type LayoutSignal struct {
	Name     string     `json:"name"`
	Detail   string     `json:"detail,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// LayoutInfo describes the shape of the repository.
type LayoutInfo struct {
	TopLevelDirs    []string       `json:"top_level_dirs"`
	ModuleRoots     []string       `json:"module_roots"`
	MonorepoSignals []LayoutSignal `json:"monorepo_signals"`
}

// Package is one declared dependency. Version is whatever the manifest states:
// a pinned version, a range specifier, or empty when the manifest omits it.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Scope   string `json:"scope,omitempty"` // runtime, dev, build, peer, optional, unknown
	Manager string `json:"manager"`
	Direct  bool   `json:"direct"`
	Source  string `json:"source"`
}

// DependencyManager summarises one package manager's manifests.
type DependencyManager struct {
	Name          string          `json:"name"`
	ManifestFiles []string        `json:"manifest_files"`
	ParseStatus   string          `json:"parse_status"` // ok, partial, unparsed, absent
	Parsers       []string        `json:"parsers,omitempty"`
	Packages      int             `json:"packages"`
	Limitations   []string        `json:"limitations,omitempty"`
	Confidence    ConfidenceClass `json:"confidence"`
	Evidence      []Evidence      `json:"evidence,omitempty"`
}

// DependencySummary is the dependency section of a manifest.
type DependencySummary struct {
	Managers     []DependencyManager `json:"managers"`
	Packages     []Package           `json:"packages"`
	PackageCount int                 `json:"package_count"`
	Truncated    bool                `json:"truncated"`
}

// Coverage states how much of the tree the analysis actually examined. It is
// the difference between "not found" and "not looked at".
type Coverage struct {
	FilesInTree int `json:"files_in_tree"`
	// FilesRead counts distinct files; ReadCalls counts every read, which is
	// higher when several detectors inspect the same file.
	FilesRead      int      `json:"files_read"`
	ReadCalls      int      `json:"read_calls"`
	BytesRead      int64    `json:"bytes_read"`
	TruncatedReads int      `json:"truncated_reads"`
	Detectors      []string `json:"detectors"`
}

// Manifest is the repository_manifest.json document defined by the P1 phase.
type Manifest struct {
	SchemaVersion int                   `json:"schema_version"`
	SnapshotID    string                `json:"snapshot_id"`
	AnalysisID    string                `json:"analysis_id"`
	Engine        repository.EngineInfo `json:"engine"`
	RulesetHash   string                `json:"ruleset_hash"`
	ConfigHash    string                `json:"config_hash"`
	Repository    RepositoryInfo        `json:"repository"`

	PrimaryLanguage string            `json:"primary_language,omitempty"`
	Languages       []LanguageStat    `json:"languages"`
	DataFormats     []FormatStat      `json:"data_formats"`
	Frameworks      []FrameworkHit    `json:"frameworks"`
	Dependencies    DependencySummary `json:"dependencies"`
	Entrypoints     []EntrypointHit   `json:"entrypoints"`
	BuildConfigs    []BuildConfigHit  `json:"build_configs"`
	Layout          LayoutInfo        `json:"layout"`
	Coverage        Coverage          `json:"coverage"`

	// Unknowns lists what this analysis could not establish about this tree.
	Unknowns []string `json:"unknowns"`
	// SnapshotLimitations restates what the snapshot itself left out (ignored
	// directories, binary files, unexpanded submodules...).
	SnapshotLimitations []string `json:"snapshot_limitations"`
	GeneratedAt         string   `json:"generated_at"`
}

// JSON renders the manifest deterministically (stable field order, trailing
// newline) so that identical analyses produce identical bytes.
func (m *Manifest) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// WriteTo stores the manifest next to the frozen tree. Snapshots are immutable,
// so an existing manifest is never overwritten.
func (m *Manifest) WriteTo(snap *repository.Snapshot) error {
	data, err := m.JSON()
	if err != nil {
		return err
	}
	return snap.WriteManifest(data)
}

// applyDetections folds detector output into the manifest sections. The
// conversion is intentionally conservative: anything a detector does not state
// stays empty rather than being guessed here.
func (m *Manifest) applyDetections(ds []Detection, cfg Config) {
	type langAgg struct {
		stat LanguageStat
	}
	langs := map[string]*langAgg{}
	formats := map[string]*FormatStat{}
	deps := map[string]*DependencyManager{}
	var packages []Package
	var unattributed int64
	var unattributedBytes int64

	for _, d := range ds {
		switch d.Kind {
		case KindLanguage:
			if d.Subject == unattributedSubject {
				unattributed += d.Counts["files"]
				unattributedBytes += d.Counts["bytes"]
				continue
			}
			agg, ok := langs[d.Subject]
			if !ok {
				agg = &langAgg{stat: LanguageStat{Name: d.Subject}}
				langs[d.Subject] = agg
			}
			agg.stat.Files += int(d.Counts["files"])
			agg.stat.Bytes += d.Counts["bytes"]
			agg.stat.Evidence = append(agg.stat.Evidence, d.Evidence...)
		case KindDataFormat:
			f, ok := formats[d.Subject]
			if !ok {
				f = &FormatStat{Name: d.Subject}
				formats[d.Subject] = f
			}
			f.Files += int(d.Counts["files"])
			f.Bytes += d.Counts["bytes"]
		case KindFramework:
			m.Frameworks = append(m.Frameworks, FrameworkHit{
				Name:       d.Subject,
				Language:   d.Detail["language"],
				Confidence: d.Confidence,
				Detail:     d.Detail,
				Evidence:   d.Evidence,
				Detector:   d.Detector,
			})
		case KindEntrypoint:
			m.Entrypoints = append(m.Entrypoints, EntrypointHit{
				Path:       d.Subject,
				Type:       d.Detail["type"],
				Language:   d.Detail["language"],
				Confidence: d.Confidence,
				Evidence:   d.Evidence,
			})
		case KindBuildConfig:
			m.BuildConfigs = append(m.BuildConfigs, BuildConfigHit{
				Path:     d.Subject,
				Type:     d.Detail["type"],
				Evidence: d.Evidence,
			})
		case KindDependency:
			manager := d.Detail["manager"]
			agg, ok := deps[manager]
			if !ok {
				// Managers with no manifest in this tree are reported too, so
				// "not found" is never confused with "not considered".
				agg = &DependencyManager{Name: manager, ManifestFiles: []string{}}
				deps[manager] = agg
			}
			if file := d.Detail["manifest_file"]; file != "" && !containsString(agg.ManifestFiles, file) {
				agg.ManifestFiles = append(agg.ManifestFiles, file)
			}
			if parser := d.Detail["parser"]; parser != "" && !containsString(agg.Parsers, parser) {
				agg.Parsers = append(agg.Parsers, parser)
			}
			agg.ParseStatus = worseStatus(agg.ParseStatus, d.Detail["parse_status"])
			agg.Packages += len(d.Packages)
			for _, lim := range d.Limitations {
				if !containsString(agg.Limitations, lim) {
					agg.Limitations = append(agg.Limitations, lim)
				}
			}
			agg.Confidence = worseConfidence(agg.Confidence, d.Confidence)
			agg.Evidence = append(agg.Evidence, d.Evidence...)
			packages = append(packages, d.Packages...)
		case KindLayout:
			switch {
			case d.Detail["top_level_dir"] != "":
				m.Layout.TopLevelDirs = append(m.Layout.TopLevelDirs, d.Detail["top_level_dir"])
			case d.Detail["module_root"] != "":
				m.Layout.ModuleRoots = append(m.Layout.ModuleRoots, d.Detail["module_root"])
			case d.Detail["monorepo_signal"] != "":
				m.Layout.MonorepoSignals = append(m.Layout.MonorepoSignals, LayoutSignal{
					Name:     d.Detail["monorepo_signal"],
					Detail:   d.Detail["signal_detail"],
					Evidence: d.Evidence,
				})
			}
		}
	}

	for _, agg := range langs {
		sort.Slice(agg.stat.Evidence, func(i, j int) bool { return agg.stat.Evidence[i].Path < agg.stat.Evidence[j].Path })
		if len(agg.stat.Evidence) > 3 {
			agg.stat.Evidence = agg.stat.Evidence[:3]
		}
		m.Languages = append(m.Languages, agg.stat)
	}
	sort.Slice(m.Languages, func(i, j int) bool {
		if m.Languages[i].Bytes != m.Languages[j].Bytes {
			return m.Languages[i].Bytes > m.Languages[j].Bytes
		}
		if m.Languages[i].Files != m.Languages[j].Files {
			return m.Languages[i].Files > m.Languages[j].Files
		}
		return m.Languages[i].Name < m.Languages[j].Name
	})
	if len(m.Languages) > 0 {
		m.PrimaryLanguage = m.Languages[0].Name
	}

	for _, f := range formats {
		m.DataFormats = append(m.DataFormats, *f)
	}
	sort.Slice(m.DataFormats, func(i, j int) bool { return m.DataFormats[i].Name < m.DataFormats[j].Name })

	sort.Slice(m.Frameworks, func(i, j int) bool { return m.Frameworks[i].Name < m.Frameworks[j].Name })
	sort.Slice(m.Entrypoints, func(i, j int) bool { return m.Entrypoints[i].Path < m.Entrypoints[j].Path })
	sort.Slice(m.BuildConfigs, func(i, j int) bool { return m.BuildConfigs[i].Path < m.BuildConfigs[j].Path })

	seen := map[string]bool{}
	deduped := make([]Package, 0, len(packages))
	for _, p := range packages {
		key := strings.Join([]string{p.Manager, p.Name, p.Version, p.Scope, p.Source}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, p)
	}
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].Manager != deduped[j].Manager {
			return deduped[i].Manager < deduped[j].Manager
		}
		if deduped[i].Name != deduped[j].Name {
			return deduped[i].Name < deduped[j].Name
		}
		return deduped[i].Version < deduped[j].Version
	})
	m.Dependencies.PackageCount = len(deduped)
	if len(deduped) > cfg.MaxPackages {
		deduped = deduped[:cfg.MaxPackages]
		m.Dependencies.Truncated = true
		m.Unknowns = append(m.Unknowns,
			fmt.Sprintf("dependency list truncated at %d entries; the manifest declares more packages", cfg.MaxPackages))
	}
	m.Dependencies.Packages = deduped

	for _, agg := range deps {
		sort.Strings(agg.ManifestFiles)
		sort.Strings(agg.Parsers)
		sort.Strings(agg.Limitations)
		m.Dependencies.Managers = append(m.Dependencies.Managers, *agg)
	}
	sort.Slice(m.Dependencies.Managers, func(i, j int) bool {
		return m.Dependencies.Managers[i].Name < m.Dependencies.Managers[j].Name
	})

	sort.Strings(m.Layout.TopLevelDirs)
	m.Layout.TopLevelDirs = dedupeStrings(m.Layout.TopLevelDirs)
	sort.Strings(m.Layout.ModuleRoots)
	m.Layout.ModuleRoots = dedupeStrings(m.Layout.ModuleRoots)
	sort.Slice(m.Layout.MonorepoSignals, func(i, j int) bool {
		return m.Layout.MonorepoSignals[i].Name < m.Layout.MonorepoSignals[j].Name
	})

	if unattributed > 0 {
		m.Unknowns = append(m.Unknowns, fmt.Sprintf(
			"%d file(s) (%d bytes) have no recognised source-language extension and were not attributed to a language",
			unattributed, unattributedBytes))
	}
}

// coverageUnknowns states the structural limits of this analysis pass.
func (m *Manifest) coverageUnknowns() []string {
	var out []string
	if m.Coverage.TruncatedReads > 0 {
		out = append(out, fmt.Sprintf(
			"%d file(s) were truncated at the read limit (%d bytes); parsers may have missed trailing content",
			m.Coverage.TruncatedReads, DefaultMaxReadBytes))
	}
	if m.Coverage.FilesInTree > 0 && len(m.Languages) == 0 {
		out = append(out, "no source language was recognised in this tree; language rules cover extensions only")
	}
	for _, mgr := range m.Dependencies.Managers {
		switch mgr.ParseStatus {
		case "unparsed":
			out = append(out, fmt.Sprintf("%s manifest(s) could not be parsed by any registered parser", mgr.Name))
		case "partial":
			out = append(out, fmt.Sprintf("%s dependency data is partial; see dependency limitations", mgr.Name))
		}
	}
	out = append(out,
		"framework detection is rule based over manifest declarations and source markers that appear in the manifest rules",
		"entrypoints are detected from file names and package markers; framework-registered implicit handlers are not enumerated")
	return out
}

// finishUnknowns normalises the unknown list for stable output.
func (m *Manifest) finishUnknowns() {
	sort.Strings(m.Unknowns)
	m.Unknowns = dedupeStrings(m.Unknowns)
	sort.Strings(m.SnapshotLimitations)
	m.SnapshotLimitations = dedupeStrings(m.SnapshotLimitations)
}

// unattributedSubject marks language detections for files whose extension is
// not mapped to a language or a known format.
const unattributedSubject = "unattributed"

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i > 0 && in[i-1] == s {
			continue
		}
		out = append(out, s)
	}
	return out
}

// statusRank orders parse statuses so that a manager's status is the worst of
// its parsers: a partial parse never hides behind a successful one.
func statusRank(status string) int {
	switch status {
	case "":
		return 0
	case "ok":
		return 1
	case "partial":
		return 2
	case "unparsed":
		return 3
	case "absent":
		return 0
	default:
		return 2
	}
}

func worseStatus(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if statusRank(b) > statusRank(a) {
		return b
	}
	return a
}

// confidenceRank orders confidence classes: unresolved is the weakest claim.
func confidenceRank(c ConfidenceClass) int {
	switch c {
	case Observed:
		return 3
	case Inferred:
		return 2
	case Unresolved:
		return 1
	default:
		return 1
	}
}

func worseConfidence(a, b ConfidenceClass) ConfidenceClass {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if confidenceRank(b) < confidenceRank(a) {
		return b
	}
	return a
}
