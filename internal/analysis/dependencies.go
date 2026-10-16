package analysis

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Parse status values. "partial" is the honest answer whenever a parser could
// not interpret everything it was given; it is never silently upgraded to "ok".
const (
	ParseOK       = "ok"
	ParsePartial  = "partial"
	ParseUnparsed = "unparsed"
	ParseAbsent   = "absent"
)

// Package scopes.
const (
	ScopeRuntime  = "runtime"
	ScopeDev      = "dev"
	ScopeBuild    = "build"
	ScopePeer     = "peer"
	ScopeOptional = "optional"
	ScopeUnknown  = "unknown"
)

// ParseResult is what one parser learned from one manifest file.
type ParseResult struct {
	Packages    []Package
	Status      string
	Limitations []string
}

// ManifestParser reads declared dependencies out of one kind of manifest file.
// Parsers are pluggable: adding an ecosystem means adding a parser, not editing
// the detector.
type ManifestParser interface {
	// ParserName identifies the parser in the manifest for reproducibility.
	ParserName() string
	// Manager is the package manager the parser belongs to (npm, pip, ...).
	Manager() string
	// Matches returns the tree-relative paths the parser can read.
	Matches(in *Input) []string
	// Parse reads one manifest. It must not fail for malformed input: a
	// malformed manifest is an unparsed result with a limitation.
	Parse(ctx context.Context, in *Input, file string, maxBytes int64) (ParseResult, error)
}

// DefaultParsers returns the built-in P1 parser set.
func DefaultParsers() []ManifestParser {
	return []ManifestParser{
		GoModParser{},
		NpmPackageJSONParser{},
		PipRequirementsParser{},
		PyProjectParser{},
		CargoTomlParser{},
		MavenPomParser{},
		BundlerGemfileParser{},
		BundlerLockParser{},
		ComposerJSONParser{},
	}
}

// DependencyDetector runs every parser over the manifests present in a tree.
// MaxReadBytes is an optional detector-level cap; zero means "whatever the input
// allows".
type DependencyDetector struct {
	Parsers      []ManifestParser
	MaxReadBytes int64
}

// NewDependencyDetector builds a detector over the given parsers.
func NewDependencyDetector(parsers ...ManifestParser) *DependencyDetector {
	if len(parsers) == 0 {
		parsers = DefaultParsers()
	}
	return &DependencyDetector{Parsers: parsers}
}

// Name implements Detector.
func (d *DependencyDetector) Name() string { return "dependency/manifests" }

// Version implements Detector.
func (d *DependencyDetector) Version() string { return "1" }

// Detect implements Detector.
func (d *DependencyDetector) Detect(ctx context.Context, in *Input) ([]Detection, error) {
	maxBytes := d.MaxReadBytes // zero defers to the input limit
	var out []Detection
	managersWithFiles := map[string]bool{}

	for _, p := range d.Parsers {
		paths := append([]string(nil), p.Matches(in)...)
		sort.Strings(paths)
		for _, file := range paths {
			res, err := p.Parse(ctx, in, file, maxBytes)
			if err != nil {
				return nil, err
			}
			status := res.Status
			if status == "" {
				status = ParseOK
			}
			confidence := Observed
			switch status {
			case ParseUnparsed:
				confidence = Unresolved
			}
			managersWithFiles[p.Manager()] = true
			out = append(out, Detection{
				Kind:    KindDependency,
				Subject: file,
				Detail: map[string]string{
					"manager":       p.Manager(),
					"parser":        p.ParserName(),
					"manifest_file": file,
					"parse_status":  status,
				},
				Packages:    res.Packages,
				Limitations: res.Limitations,
				Confidence:  confidence,
				Evidence:    []Evidence{{Path: file, Note: "declared dependencies"}},
			})
		}
	}

	// Package managers that are recognised but have no manifest in this tree are
	// still reported, so "no npm dependency found" cannot be confused with
	// "npm was not considered".
	for _, manager := range d.managers() {
		if managersWithFiles[manager] {
			continue
		}
		out = append(out, Detection{
			Kind:       KindDependency,
			Subject:    manager,
			Detail:     map[string]string{"manager": manager, "parse_status": ParseAbsent},
			Confidence: Unresolved,
			Limitations: []string{
				"no " + manager + " manifest was found in this snapshot; absence of a manifest is not proof that the ecosystem is unused",
			},
		})
	}
	return out, nil
}

func (d *DependencyDetector) managers() []string {
	set := map[string]bool{}
	for _, p := range d.Parsers {
		set[p.Manager()] = true
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// --- matching helpers -------------------------------------------------------

func matchBases(in *Input, bases ...string) []string {
	want := map[string]bool{}
	for _, b := range bases {
		want[b] = true
	}
	var out []string
	for _, f := range in.Files {
		if want[f.Base] {
			out = append(out, f.Path)
		}
	}
	return out
}

func matchGlob(in *Input, glob string) []string {
	var out []string
	for _, f := range in.Files {
		if ok, err := path.Match(glob, f.Path); err == nil && ok {
			out = append(out, f.Path)
		}
	}
	return out
}

// --- go.mod -----------------------------------------------------------------

// GoModParser reads `require` declarations from go.mod.
type GoModParser struct{}

// ParserName implements ManifestParser.
func (GoModParser) ParserName() string { return "go.mod" }

// Manager implements ManifestParser.
func (GoModParser) Manager() string { return "go-modules" }

// Matches implements ManifestParser.
func (GoModParser) Matches(in *Input) []string { return matchBases(in, "go.mod") }

// Parse implements ManifestParser.
func (GoModParser) Parse(_ context.Context, in *Input, file string, maxBytes int64) (ParseResult, error) {
	data, truncated, err := in.ReadFile(file, maxBytes)
	if err != nil {
		return ParseResult{}, err
	}
	res := ParseResult{Status: ParseOK}
	inRequire := false
	replaced := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "require (":
			inRequire = true
			continue
		case inRequire && line == ")":
			inRequire = false
			continue
		case strings.HasPrefix(line, "//"):
			continue
		case strings.HasPrefix(line, "replace "):
			replaced = true
			continue
		}
		entry := ""
		switch {
		case inRequire:
			entry = line
		case strings.HasPrefix(line, "require "):
			entry = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		default:
			continue
		}
		if entry == "" {
			continue
		}
		fields := strings.Fields(entry)
		if len(fields) < 2 {
			continue
		}
		res.Packages = append(res.Packages, Package{
			Name:    fields[0],
			Version: fields[1],
			Scope:   ScopeRuntime,
			Manager: "go-modules",
			Direct:  !strings.Contains(raw, "// indirect"),
			Source:  file,
		})
	}
	if replaced {
		res.Status = ParsePartial
		res.Limitations = append(res.Limitations, "replace directives are recorded as declared but not applied; resolved versions may differ")
	}
	if truncated {
		res.Status = ParsePartial
		res.Limitations = append(res.Limitations, "go.mod was truncated at the read limit; later require blocks were not read")
	}
	return res, nil
}

// --- package.json -----------------------------------------------------------

// NpmPackageJSONParser reads dependency sections from package.json.
type NpmPackageJSONParser struct{}

// ParserName implements ManifestParser.
func (NpmPackageJSONParser) ParserName() string { return "package.json" }

// Manager implements ManifestParser.
func (NpmPackageJSONParser) Manager() string { return "npm" }

// Matches implements ManifestParser.
func (NpmPackageJSONParser) Matches(in *Input) []string { return matchBases(in, "package.json") }

// Parse implements ManifestParser.
func (NpmPackageJSONParser) Parse(_ context.Context, in *Input, file string, maxBytes int64) (ParseResult, error) {
	data, truncated, err := in.ReadFile(file, maxBytes)
	if err != nil {
		return ParseResult{}, err
	}
	if truncated {
		return ParseResult{
			Status:      ParseUnparsed,
			Limitations: []string{"package.json was truncated at the read limit and could not be parsed"},
		}, nil
	}
	var doc struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return ParseResult{
			Status:      ParseUnparsed,
			Limitations: []string{"package.json is not valid JSON: " + err.Error()},
		}, nil
	}
	res := ParseResult{Status: ParseOK}
	res.Packages = append(res.Packages, packagesFromMap(doc.Dependencies, "npm", ScopeRuntime, file)...)
	res.Packages = append(res.Packages, packagesFromMap(doc.DevDependencies, "npm", ScopeDev, file)...)
	res.Packages = append(res.Packages, packagesFromMap(doc.PeerDependencies, "npm", ScopePeer, file)...)
	res.Packages = append(res.Packages, packagesFromMap(doc.OptionalDependencies, "npm", ScopeOptional, file)...)
	res.Limitations = append(res.Limitations, "declared ranges are recorded verbatim; the installed tree is not resolved from a lockfile")
	return res, nil
}

func packagesFromMap(m map[string]string, manager, scope, source string) []Package {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Package, 0, len(names))
	for _, name := range names {
		out = append(out, Package{Name: name, Version: m[name], Scope: scope, Manager: manager, Direct: true, Source: source})
	}
	return out
}

// --- requirements.txt -------------------------------------------------------

// PipRequirementsParser reads a requirements.txt style file.
type PipRequirementsParser struct{}

// ParserName implements ManifestParser.
func (PipRequirementsParser) ParserName() string { return "requirements.txt" }

// Manager implements ManifestParser.
func (PipRequirementsParser) Manager() string { return "pip" }

// Matches implements ManifestParser.
func (PipRequirementsParser) Matches(in *Input) []string {
	var out []string
	for _, f := range in.Files {
		if f.Ext == ".txt" && strings.HasPrefix(f.Base, "requirements") {
			out = append(out, f.Path)
		}
	}
	return out
}

// Parse implements ManifestParser.
func (PipRequirementsParser) Parse(_ context.Context, in *Input, file string, maxBytes int64) (ParseResult, error) {
	data, truncated, err := in.ReadFile(file, maxBytes)
	if err != nil {
		return ParseResult{}, err
	}
	res := ParseResult{Status: ParseOK}
	unsupported := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") || strings.Contains(line, "://") {
			unsupported = true
			continue
		}
		name, version := splitRequirement(line)
		if name == "" {
			unsupported = true
			continue
		}
		res.Packages = append(res.Packages, Package{
			Name: name, Version: version, Scope: ScopeRuntime,
			Manager: "pip", Direct: true, Source: file,
		})
	}
	if unsupported {
		res.Status = ParsePartial
		res.Limitations = append(res.Limitations, "include (-r), editable (-e) and URL requirements are not resolved")
	}
	if truncated {
		res.Status = ParsePartial
		res.Limitations = append(res.Limitations, "requirements file was truncated at the read limit")
	}
	res.Limitations = append(res.Limitations, "transitive dependencies require a lockfile; only direct requirements are listed here")
	return res, nil
}

// splitRequirement separates a requirement line into name and version
// specifier. Extras and environment markers are removed from the name.
func splitRequirement(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	// Strip environment markers: "name; python_version < '3.9'".
	if idx := strings.Index(line, ";"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	cut := len(line)
	for i, r := range line {
		if strings.ContainsRune("<>=!~[ ", r) {
			cut = i
			break
		}
	}
	name := strings.TrimSpace(line[:cut])
	rest := strings.TrimSpace(line[cut:])
	rest = strings.TrimPrefix(rest, "==")
	if name == "" {
		return "", ""
	}
	return name, strings.TrimSpace(rest)
}

// --- pyproject.toml ---------------------------------------------------------

// PyProjectParser reads [project] and [tool.poetry] dependencies with a
// line-based scanner.
type PyProjectParser struct{}

// ParserName implements ManifestParser.
func (PyProjectParser) ParserName() string { return "pyproject.toml" }

// Manager implements ManifestParser.
func (PyProjectParser) Manager() string { return "pip" }

// Matches implements ManifestParser.
func (PyProjectParser) Matches(in *Input) []string { return matchBases(in, "pyproject.toml") }

var quotedString = regexp.MustCompile(`["']([^"']+)["']`)

// Parse implements ManifestParser.
func (PyProjectParser) Parse(_ context.Context, in *Input, file string, maxBytes int64) (ParseResult, error) {
	data, truncated, err := in.ReadFile(file, maxBytes)
	if err != nil {
		return ParseResult{}, err
	}
	res := ParseResult{Status: ParsePartial}
	res.Limitations = append(res.Limitations,
		"pyproject.toml is read with a line-based scanner: only the [project] dependencies array and the poetry dependency tables are interpreted")

	section := ""
	inArray := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[]")
			inArray = false
			continue
		}
		switch section {
		case "project":
			if strings.HasPrefix(line, "dependencies") {
				inArray = true
				// A single-line array is handled by the same quoted-string scan.
				for _, q := range quotedString.FindAllStringSubmatch(line, -1) {
					if name, version := splitRequirement(q[1]); name != "" {
						res.Packages = append(res.Packages, Package{Name: name, Version: version, Scope: ScopeRuntime, Manager: "pip", Direct: true, Source: file})
					}
				}
				if strings.Contains(line, "]") {
					inArray = false
				}
				continue
			}
			if inArray {
				if strings.HasPrefix(line, "]") {
					inArray = false
				}
				for _, q := range quotedString.FindAllStringSubmatch(line, -1) {
					if name, version := splitRequirement(q[1]); name != "" {
						res.Packages = append(res.Packages, Package{Name: name, Version: version, Scope: ScopeRuntime, Manager: "pip", Direct: true, Source: file})
					}
				}
			}
		case "tool.poetry.dependencies":
			if name, version, ok := tomlKV(line); ok && !strings.EqualFold(name, "python") {
				res.Packages = append(res.Packages, Package{Name: name, Version: version, Scope: ScopeRuntime, Manager: "pip", Direct: true, Source: file})
			}
		case "tool.poetry.dev-dependencies", "tool.poetry.group.dev.dependencies":
			if name, version, ok := tomlKV(line); ok {
				res.Packages = append(res.Packages, Package{Name: name, Version: version, Scope: ScopeDev, Manager: "pip", Direct: true, Source: file})
			}
		}
	}
	if truncated {
		res.Limitations = append(res.Limitations, "pyproject.toml was truncated at the read limit")
	}
	return res, nil
}

// tomlKV parses `name = "version"` or `name = { version = "..." }` style lines.
func tomlKV(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	name := strings.Trim(strings.TrimSpace(key), `"'`)
	if name == "" || strings.ContainsAny(name, " []{}") {
		return "", "", false
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "{") {
		// Inline table: look for a version field inside it.
		if m := quotedString.FindAllStringSubmatch(value, -1); len(m) > 0 {
			for i := 0; i+1 < len(m); i++ {
				if strings.Contains(m[i][1], "version") {
					return name, m[i+1][1], true
				}
			}
		}
		return name, "", true
	}
	return name, strings.Trim(value, `"'`), true
}

// --- Cargo.toml -------------------------------------------------------------

// CargoTomlParser reads dependency tables from Cargo.toml.
type CargoTomlParser struct{}

// ParserName implements ManifestParser.
func (CargoTomlParser) ParserName() string { return "Cargo.toml" }

// Manager implements ManifestParser.
func (CargoTomlParser) Manager() string { return "cargo" }

// Matches implements ManifestParser.
func (CargoTomlParser) Matches(in *Input) []string { return matchBases(in, "Cargo.toml") }

// Parse implements ManifestParser.
func (CargoTomlParser) Parse(_ context.Context, in *Input, file string, maxBytes int64) (ParseResult, error) {
	data, truncated, err := in.ReadFile(file, maxBytes)
	if err != nil {
		return ParseResult{}, err
	}
	res := ParseResult{Status: ParsePartial}
	res.Limitations = append(res.Limitations,
		"line-based Cargo.toml scanner: workspace inheritance, target-specific tables and feature resolution are not interpreted")
	scope := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.Trim(line, "[]") {
			case "dependencies", "workspace.dependencies":
				scope = ScopeRuntime
			case "dev-dependencies":
				scope = ScopeDev
			case "build-dependencies":
				scope = ScopeBuild
			default:
				scope = ""
			}
			continue
		}
		if scope == "" {
			continue
		}
		name, version, ok := tomlKV(line)
		if !ok {
			continue
		}
		res.Packages = append(res.Packages, Package{Name: name, Version: version, Scope: scope, Manager: "cargo", Direct: true, Source: file})
	}
	if truncated {
		res.Limitations = append(res.Limitations, "Cargo.toml was truncated at the read limit")
	}
	return res, nil
}

// --- pom.xml ----------------------------------------------------------------

// MavenPomParser reads <dependencies> from pom.xml.
type MavenPomParser struct{}

// ParserName implements ManifestParser.
func (MavenPomParser) ParserName() string { return "pom.xml" }

// Manager implements ManifestParser.
func (MavenPomParser) Manager() string { return "maven" }

// Matches implements ManifestParser.
func (MavenPomParser) Matches(in *Input) []string { return matchBases(in, "pom.xml") }

type pomDocument struct {
	Dependencies []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
		Optional   string `xml:"optional"`
	} `xml:"dependencies>dependency"`
}

// Parse implements ManifestParser.
func (MavenPomParser) Parse(_ context.Context, in *Input, file string, maxBytes int64) (ParseResult, error) {
	data, truncated, err := in.ReadFile(file, maxBytes)
	if err != nil {
		return ParseResult{}, err
	}
	if truncated {
		return ParseResult{
			Status:      ParseUnparsed,
			Limitations: []string{"pom.xml was truncated at the read limit and could not be parsed"},
		}, nil
	}
	var doc pomDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		return ParseResult{
			Status:      ParseUnparsed,
			Limitations: []string{"pom.xml is not valid XML: " + err.Error()},
		}, nil
	}
	res := ParseResult{Status: ParsePartial}
	res.Limitations = append(res.Limitations,
		"dependencyManagement and property-based versions are recorded verbatim and not resolved")
	for _, dep := range doc.Dependencies {
		name := strings.TrimSpace(dep.GroupID + ":" + dep.ArtifactID)
		scope := ScopeRuntime
		switch strings.TrimSpace(dep.Scope) {
		case "test":
			scope = ScopeDev
		case "provided", "system":
			scope = ScopeBuild
		}
		res.Packages = append(res.Packages, Package{
			Name: name, Version: strings.TrimSpace(dep.Version), Scope: scope,
			Manager: "maven", Direct: true, Source: file,
		})
	}
	return res, nil
}

// --- Ruby -------------------------------------------------------------------

// BundlerGemfileParser reads `gem` lines from a Gemfile.
type BundlerGemfileParser struct{}

// ParserName implements ManifestParser.
func (BundlerGemfileParser) ParserName() string { return "Gemfile" }

// Manager implements ManifestParser.
func (BundlerGemfileParser) Manager() string { return "bundler" }

// Matches implements ManifestParser.
func (BundlerGemfileParser) Matches(in *Input) []string { return matchBases(in, "Gemfile") }

var gemLine = regexp.MustCompile(`^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])`)

// Parse implements ManifestParser.
func (BundlerGemfileParser) Parse(_ context.Context, in *Input, file string, maxBytes int64) (ParseResult, error) {
	data, truncated, err := in.ReadFile(file, maxBytes)
	if err != nil {
		return ParseResult{}, err
	}
	res := ParseResult{Status: ParsePartial}
	res.Limitations = append(res.Limitations,
		"Gemfile group blocks are not evaluated; gems are recorded as runtime regardless of their group")
	for _, raw := range strings.Split(string(data), "\n") {
		m := gemLine.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		res.Packages = append(res.Packages, Package{
			Name: m[1], Version: m[2], Scope: ScopeRuntime,
			Manager: "bundler", Direct: true, Source: file,
		})
	}
	if truncated {
		res.Limitations = append(res.Limitations, "Gemfile was truncated at the read limit")
	}
	return res, nil
}

// BundlerLockParser reads the specs section of Gemfile.lock.
type BundlerLockParser struct{}

// ParserName implements ManifestParser.
func (BundlerLockParser) ParserName() string { return "Gemfile.lock" }

// Manager implements ManifestParser.
func (BundlerLockParser) Manager() string { return "bundler" }

// Matches implements ManifestParser.
func (BundlerLockParser) Matches(in *Input) []string { return matchBases(in, "Gemfile.lock") }

var lockSpecLine = regexp.MustCompile(`^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$`)

// Parse implements ManifestParser.
func (BundlerLockParser) Parse(_ context.Context, in *Input, file string, maxBytes int64) (ParseResult, error) {
	data, truncated, err := in.ReadFile(file, maxBytes)
	if err != nil {
		return ParseResult{}, err
	}
	res := ParseResult{Status: ParseOK}
	res.Limitations = append(res.Limitations,
		"Gemfile.lock does not mark direct dependencies; entries are recorded as transitive")
	inSpecs := false
	for _, raw := range strings.Split(string(data), "\n") {
		switch strings.TrimSpace(raw) {
		case "specs:":
			inSpecs = true
			continue
		case "PLATFORMS:", "DEPENDENCIES:", "BUNDLED WITH:":
			inSpecs = false
			continue
		}
		if !inSpecs {
			continue
		}
		m := lockSpecLine.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		res.Packages = append(res.Packages, Package{
			Name: m[1], Version: m[2], Scope: ScopeRuntime,
			Manager: "bundler", Direct: false, Source: file,
		})
	}
	if truncated {
		res.Status = ParsePartial
		res.Limitations = append(res.Limitations, "Gemfile.lock was truncated at the read limit")
	}
	return res, nil
}

// --- composer.json ----------------------------------------------------------

// ComposerJSONParser reads require sections from composer.json.
type ComposerJSONParser struct{}

// ParserName implements ManifestParser.
func (ComposerJSONParser) ParserName() string { return "composer.json" }

// Manager implements ManifestParser.
func (ComposerJSONParser) Manager() string { return "composer" }

// Matches implements ManifestParser.
func (ComposerJSONParser) Matches(in *Input) []string { return matchBases(in, "composer.json") }

// Parse implements ManifestParser.
func (ComposerJSONParser) Parse(_ context.Context, in *Input, file string, maxBytes int64) (ParseResult, error) {
	data, truncated, err := in.ReadFile(file, maxBytes)
	if err != nil {
		return ParseResult{}, err
	}
	if truncated {
		return ParseResult{
			Status:      ParseUnparsed,
			Limitations: []string{"composer.json was truncated at the read limit and could not be parsed"},
		}, nil
	}
	var doc struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return ParseResult{
			Status:      ParseUnparsed,
			Limitations: []string{"composer.json is not valid JSON: " + err.Error()},
		}, nil
	}
	res := ParseResult{Status: ParseOK}
	res.Packages = append(res.Packages, packagesFromMap(doc.Require, "composer", ScopeRuntime, file)...)
	res.Packages = append(res.Packages, packagesFromMap(doc.RequireDev, "composer", ScopeDev, file)...)
	res.Limitations = append(res.Limitations, "constraint strings are recorded verbatim; the installed versions come from composer.lock")
	return res, nil
}
