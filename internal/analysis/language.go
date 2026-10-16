package analysis

import (
	"context"
	"path"
	"sort"
	"strings"
)

// LanguageRules is the (data-driven) extension and file-name table used to
// attribute files to languages. Source maps an extension or a plain file name to
// a source language; Format maps an extension to a non-source format. Tooling
// names are files that are neither language nor format (build descriptors,
// licences, lock files) and must not be reported as unattributed code.
type LanguageRules struct {
	Source  map[string]string
	Format  map[string]string
	Tooling map[string]bool
	// ToolingPrefixes matches tooling file name prefixes, e.g. "Dockerfile.".
	ToolingPrefixes []string
}

// DefaultLanguageRules returns the built-in P1 table. It is deliberately
// conservative: an extension that is not listed stays unattributed and is
// reported as unknown instead of being guessed.
func DefaultLanguageRules() *LanguageRules {
	return &LanguageRules{
		Source: map[string]string{
			".go": "Go", ".py": "Python", ".pyi": "Python", ".pyx": "Python",
			".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
			".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
			".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
			".rb": "Ruby", ".php": "PHP", ".cs": "C#",
			".c": "C", ".h": "C",
			".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++", ".hxx": "C++",
			".rs": "Rust", ".swift": "Swift", ".m": "Objective-C", ".mm": "Objective-C++",
			".scala": "Scala", ".sc": "Scala", ".groovy": "Groovy",
			".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".ksh": "Shell", ".fish": "Shell",
			".ps1": "PowerShell", ".psm1": "PowerShell",
			".sql": "SQL", ".lua": "Lua", ".pl": "Perl", ".pm": "Perl", ".r": "R",
			".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".hrl": "Erlang",
			".hs": "Haskell", ".clj": "Clojure", ".cljs": "Clojure", ".jl": "Julia",
			".tf": "Terraform", ".proto": "Protobuf", ".vue": "Vue", ".svelte": "Svelte",
			".f90": "Fortran", ".pas": "Pascal", ".vb": "Visual Basic", ".asm": "Assembly", ".s": "Assembly",

			// Source-like files identified by name rather than extension.
			"Rakefile":      "Ruby",
			"Podfile":       "Ruby",
			"Vagrantfile":   "Ruby",
			"Jenkinsfile":   "Groovy",
			"BUILD":         "Starlark",
			"BUILD.bazel":   "Starlark",
			"WORKSPACE":     "Starlark",
			"Package.swift": "Swift",
		},
		Format: map[string]string{
			".json": "JSON", ".jsonc": "JSON", ".json5": "JSON",
			".yaml": "YAML", ".yml": "YAML", ".toml": "TOML",
			".ini": "INI", ".cfg": "INI", ".conf": "INI", ".properties": "Properties",
			".xml": "XML", ".md": "Markdown", ".markdown": "Markdown", ".rst": "reStructuredText",
			".txt": "Text", ".csv": "CSV", ".tsv": "CSV",
			".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "SCSS", ".sass": "SCSS", ".less": "LESS",
			".svg": "SVG", ".graphql": "GraphQL", ".gql": "GraphQL", ".hcl": "HCL", ".lock": "Lockfile",
		},
		Tooling: map[string]bool{
			"Dockerfile": true, "Makefile": true, "GNUmakefile": true, "makefile": true,
			"go.mod": true, "go.sum": true, "go.work": true,
			"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
			"requirements.txt": true, "poetry.lock": true, "Pipfile": true, "Pipfile.lock": true,
			"pyproject.toml": true, "setup.py": true, "setup.cfg": true,
			"Cargo.toml": true, "Cargo.lock": true,
			"pom.xml": true, "build.gradle": true, "build.gradle.kts": true, "settings.gradle": true,
			"Gemfile": true, "Gemfile.lock": true,
			"composer.json": true, "composer.lock": true,
			"Procfile": true, "CMakeLists.txt": true,
			".gitignore": true, ".gitattributes": true, ".dockerignore": true, ".editorconfig": true,
			".npmrc": true, ".nvmrc": true, ".tool-versions": true, ".python-version": true,
			".golangci.yml": true, ".golangci.yaml": true,
		},
		ToolingPrefixes: []string{"Dockerfile.", "LICENSE", "COPYING", "NOTICE", "README", "CHANGELOG", "AUTHORS", "CONTRIBUTING"},
	}
}

// countAgg accumulates the file and byte footprint of one label.
type countAgg struct {
	files    int64
	bytes    int64
	evidence []Evidence
}

func (a *countAgg) add(f FileInfo, note string) {
	a.files++
	a.bytes += f.Size
	if note != "" {
		a.evidence = append(a.evidence, Evidence{Path: f.Path, Note: note})
	}
}

// LanguageDetector counts files and bytes per language and per format. It is the
// only detector whose output feeds PrimaryLanguage.
type LanguageDetector struct {
	Rules *LanguageRules
}

// NewLanguageDetector returns a detector over the default rules.
func NewLanguageDetector() *LanguageDetector { return &LanguageDetector{Rules: DefaultLanguageRules()} }

// NewLanguageDetectorWithRules returns a detector over custom rules, which is
// how additional languages are added without touching this package.
func NewLanguageDetectorWithRules(r *LanguageRules) *LanguageDetector {
	if r == nil {
		r = DefaultLanguageRules()
	}
	return &LanguageDetector{Rules: r}
}

// Name implements Detector.
func (d *LanguageDetector) Name() string { return "language/extensions" }

// Version implements Detector.
func (d *LanguageDetector) Version() string { return "1" }

// Detect implements Detector.
func (d *LanguageDetector) Detect(_ context.Context, in *Input) ([]Detection, error) {
	langs := map[string]*countAgg{}
	formats := map[string]*countAgg{}
	var unattributed, unattributedBytes int64

	for _, f := range in.Files {
		if f.Base == "" {
			continue
		}
		if lang, ok := d.Rules.Source[f.Base]; ok {
			agg(langs, lang).add(f, "sample file for this language")
			continue
		}
		if lang, ok := d.Rules.Source[f.Ext]; ok {
			agg(langs, lang).add(f, "sample file for this language")
			continue
		}
		if format, ok := d.Rules.Format[f.Ext]; ok {
			agg(formats, format).add(f, "")
			continue
		}
		if d.Rules.Tooling[f.Base] || d.Rules.Tooling[f.Path] || hasToolingPrefix(d.Rules.ToolingPrefixes, f.Base) {
			continue
		}
		if strings.HasPrefix(f.Base, ".") {
			// Dot-files (CI configs, formatter settings) are tooling by
			// convention; they are not counted as unattributed source.
			continue
		}
		if f.Ext == "" && path.Dir(f.Path) != "." {
			continue
		}
		unattributed++
		unattributedBytes += f.Size
	}

	var out []Detection
	for name, a := range langs {
		out = append(out, Detection{
			Kind:       KindLanguage,
			Subject:    name,
			Counts:     map[string]int64{"files": a.files, "bytes": a.bytes},
			Confidence: Observed,
			Evidence:   capEvidence(a.evidence, 3),
			Detail:     map[string]string{"rule": "extension or file name table"},
		})
	}
	for name, a := range formats {
		out = append(out, Detection{
			Kind:       KindDataFormat,
			Subject:    name,
			Counts:     map[string]int64{"files": a.files, "bytes": a.bytes},
			Confidence: Observed,
		})
	}
	if unattributed > 0 {
		out = append(out, Detection{
			Kind:       KindLanguage,
			Subject:    unattributedSubject,
			Counts:     map[string]int64{"files": unattributed, "bytes": unattributedBytes},
			Confidence: Unresolved,
			Detail:     map[string]string{"note": "extension is not mapped to a language"},
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Subject < out[j].Subject
	})
	return out, nil
}

func agg(m map[string]*countAgg, key string) *countAgg {
	a, ok := m[key]
	if !ok {
		a = &countAgg{}
		m[key] = a
	}
	return a
}

func hasToolingPrefix(prefixes []string, base string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	return false
}

func capEvidence(in []Evidence, max int) []Evidence {
	sort.Slice(in, func(i, j int) bool { return in[i].Path < in[j].Path })
	if len(in) > max {
		return in[:max]
	}
	return in
}
