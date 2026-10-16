package analysis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// polyglotFixture is a small multi-ecosystem repository used to check that the
// analyzer reports facts per ecosystem instead of picking a winner.
func polyglotFixture(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"go.mod": `module example.invalid/app

go 1.24

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/net v0.20.0 // indirect
)
`,
		"main.go": `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.Run()
}
`,
		"cmd/server/main.go":                 "package main\n\nfunc main() {}\n",
		"cmd/migrate/run.go":                 "package main\n\nimport \"github.com/spf13/cobra\"\n\nvar cmd = &cobra.Command{}\n",
		"app/main.py":                        "from fastapi import FastAPI\n\napp = FastAPI()\n",
		"app/models.py":                      "from pydantic import BaseModel\n\nclass Item(BaseModel):\n    name: str\n",
		"web/index.js":                       "const express = require('express')\nconst app = express()\n",
		"src/lib.rs":                         "fn main() {}\n",
		"src/main/java/example/App.java":     "public class App {\n    public static void main(String[] args) {}\n}\n",
		"app/controllers/home_controller.rb": "class HomeController < ActionController::Base\nend\n",
		"public/index.php":                   "<?php echo 'ok';\n",
		"packages/web/package.json": `{"name": "@example/web", "dependencies": {"express": "^4.18.2"}}
`,
		"packages/web/src/index.js": "console.log('nested module')\n",
		"requirements.txt":          "fastapi==0.110.0\nhttpx>=0.27\n-r dev-requirements.txt\n",
		"pyproject.toml": `[project]
name = "example"
dependencies = [
  "uvicorn>=0.27",
]

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
`,
		"package.json": `{
  "name": "web",
  "workspaces": ["packages/*"],
  "dependencies": {"express": "^4.18.2"},
  "devDependencies": {"jest": "^29.0.0"}
}
`,
		"Cargo.toml": "[package]\nname = \"svc\"\n\n[dependencies]\naxum = \"0.7\"\n",
		"pom.xml":    `<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId><version>3.2.0</version></dependency></dependencies></project>`,
		"Gemfile":    "source 'https://rubygems.org'\n\ngem 'rails', '~> 7.1'\n",
		"Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.3)
    rack (3.0.9)

PLATFORMS
  ruby

DEPENDENCIES
  rails
`,
		"composer.json":              `{"require": {"laravel/framework": "^11.0"}}`,
		"Dockerfile":                 "FROM scratch\n",
		"Makefile":                   "test:\n\tgo test ./...\n",
		".github/workflows/test.yml": "name: test\non: [push]\n",
		"assets/logo.svg":            "<svg/>\n",
		"docs/notes.unknownext":      "no language here\n",
		"README.md":                  "# fixture\n",
	})
}

func analyzeTree(t *testing.T, treeDir string) *Manifest {
	t.Helper()
	in, err := NewInput("snap-0123456789abcdef0123456789abcdef", treeDir)
	if err != nil {
		t.Fatalf("NewInput: %v", err)
	}
	a := NewAnalyzer(nil, Config{})
	m, err := a.AnalyzeInput(context.Background(), in)
	if err != nil {
		t.Fatalf("AnalyzeInput: %v", err)
	}
	return m
}

func TestManifestReportsLanguagesAndFormats(t *testing.T) {
	t.Parallel()
	m := analyzeTree(t, polyglotFixture(t))

	got := map[string]int{}
	for _, l := range m.Languages {
		got[l.Name] = l.Files
	}
	for _, want := range []string{"Go", "Python", "JavaScript", "Ruby", "PHP", "Rust", "Java"} {
		if got[want] == 0 {
			t.Errorf("language %s not reported: %+v", want, m.Languages)
		}
	}
	if m.PrimaryLanguage == "" {
		t.Error("primary language is empty")
	}
	if len(m.Languages) > 0 && m.Languages[0].Name != m.PrimaryLanguage {
		t.Errorf("primary language %q is not the first ranked language %q", m.PrimaryLanguage, m.Languages[0].Name)
	}
	formats := map[string]bool{}
	for _, f := range m.DataFormats {
		formats[f.Name] = true
	}
	for _, want := range []string{"Markdown", "SVG", "YAML"} {
		if !formats[want] {
			t.Errorf("format %s not reported: %+v", want, m.DataFormats)
		}
	}
	// Tooling files must not be counted as unattributed source.
	for _, l := range m.Languages {
		if l.Name == unattributedSubject {
			t.Errorf("tooling files were reported as unattributed: %+v", l)
		}
	}
	for _, u := range m.Unknowns {
		if strings.Contains(u, "no recognised source-language extension") {
			if !strings.Contains(u, "1 file(s)") {
				t.Errorf("unexpected unattributed count: %s", u)
			}
		}
	}
}

func TestManifestReportsFrameworksWithEvidence(t *testing.T) {
	t.Parallel()
	m := analyzeTree(t, polyglotFixture(t))

	want := map[string]string{
		"Gin":           "go.mod",
		"FastAPI":       "requirements.txt",
		"Express":       "package.json",
		"Axum":          "Cargo.toml",
		"Spring Boot":   "pom.xml",
		"Laravel":       "composer.json",
		"Ruby on Rails": "Gemfile",
	}
	got := map[string]FrameworkHit{}
	for _, f := range m.Frameworks {
		got[f.Name] = f
	}
	for name, evidence := range want {
		hit, ok := got[name]
		if !ok {
			t.Errorf("framework %s not detected (got %v)", name, keysOf(got))
			continue
		}
		if len(hit.Evidence) == 0 {
			t.Errorf("framework %s has no evidence", name)
			continue
		}
		foundEvidence := false
		for _, e := range hit.Evidence {
			if e.Path == evidence {
				foundEvidence = true
			}
		}
		if !foundEvidence {
			t.Errorf("framework %s is not backed by %s: %+v", name, evidence, hit.Evidence)
		}
		if hit.Confidence != Observed && hit.Confidence != Inferred {
			t.Errorf("framework %s has confidence %q", name, hit.Confidence)
		}
	}
	// Gin is confirmed by source markers, so it must be Observed.
	if got["Gin"].Confidence != Observed {
		t.Errorf("Gin confidence = %q, want observed (source marker present)", got["Gin"].Confidence)
	}
}

func TestManifestReportsEntrypointsWithMarkers(t *testing.T) {
	t.Parallel()
	m := analyzeTree(t, polyglotFixture(t))

	byPath := map[string]EntrypointHit{}
	for _, e := range m.Entrypoints {
		byPath[e.Path] = e
	}
	for _, want := range []string{"main.go", "cmd/server/main.go", "cmd/migrate/run.go"} {
		hit, ok := byPath[want]
		if !ok {
			t.Errorf("entrypoint %s not reported (got %v)", want, keysOfPaths(byPath))
			continue
		}
		if hit.Confidence != Observed {
			t.Errorf("entrypoint %s confidence = %q, want observed", want, hit.Confidence)
		}
		if len(hit.Evidence) == 0 {
			t.Errorf("entrypoint %s has no evidence", want)
		}
	}
	if !strings.Contains(byPath["cmd/migrate/run.go"].Type, "go-command") {
		t.Errorf("cobra command not classified: %+v", byPath["cmd/migrate/run.go"])
	}
}

func TestManifestReportsDependenciesPerManager(t *testing.T) {
	t.Parallel()
	m := analyzeTree(t, polyglotFixture(t))

	managers := map[string]DependencyManager{}
	for _, mgr := range m.Dependencies.Managers {
		managers[mgr.Name] = mgr
	}
	for _, want := range []string{"go-modules", "npm", "pip", "cargo", "maven", "bundler", "composer"} {
		mgr, ok := managers[want]
		if !ok {
			t.Errorf("manager %s missing from %v", want, managerNames(managers))
			continue
		}
		if mgr.ParseStatus == ParseAbsent || mgr.ParseStatus == "" {
			t.Errorf("manager %s has no manifest parsed: %+v", want, mgr)
		}
		if len(mgr.Evidence) == 0 {
			t.Errorf("manager %s has no evidence", want)
		}
	}
	if managers["pip"].ParseStatus != ParsePartial {
		t.Errorf("pip status = %q, want partial (line-based pyproject scanner)", managers["pip"].ParseStatus)
	}
	if len(managers["pip"].Limitations) == 0 {
		t.Error("partial manager has no stated limitation")
	}
	// A manager without any manifest must still be reported as absent.
	if mgr, ok := managers["cargo"]; !ok || mgr.ParseStatus != ParsePartial {
		t.Errorf("cargo status = %+v, want partial", mgr)
	}

	pkgs := map[string]Package{}
	for _, p := range m.Dependencies.Packages {
		pkgs[p.Manager+"/"+p.Name] = p
	}
	gin, ok := pkgs["go-modules/github.com/gin-gonic/gin"]
	if !ok {
		t.Fatalf("gin dependency missing: %d packages", len(m.Dependencies.Packages))
	}
	if gin.Version != "v1.9.1" || !gin.Direct || gin.Source != "go.mod" {
		t.Errorf("unexpected gin record: %+v", gin)
	}
	indirect, ok := pkgs["go-modules/golang.org/x/net"]
	if !ok || indirect.Direct {
		t.Errorf("indirect dependency not marked: %+v", indirect)
	}
	if _, ok := pkgs["npm/express"]; !ok {
		t.Error("express dependency missing")
	}
	if p, ok := pkgs["npm/jest"]; !ok || p.Scope != ScopeDev {
		t.Errorf("dev dependency scope not recorded: %+v", p)
	}
	if _, ok := pkgs["cargo/axum"]; !ok {
		t.Error("cargo dependency missing")
	}
	if p, ok := pkgs["bundler/rack"]; !ok || p.Direct {
		t.Errorf("lockfile-only dependency should be transitive: %+v", p)
	}
	if m.Dependencies.PackageCount != len(m.Dependencies.Packages) {
		t.Errorf("package count %d != %d", m.Dependencies.PackageCount, len(m.Dependencies.Packages))
	}
}

func TestManifestReportsBuildConfigsAndLayout(t *testing.T) {
	t.Parallel()
	m := analyzeTree(t, polyglotFixture(t))

	builds := map[string]string{}
	for _, b := range m.BuildConfigs {
		builds[b.Path] = b.Type
	}
	for path, wantType := range map[string]string{
		"Dockerfile":                 "dockerfile",
		"Makefile":                   "make",
		"go.mod":                     "go-module",
		".github/workflows/test.yml": "github-actions",
		"package.json":               "npm-project",
		"Cargo.toml":                 "cargo",
	} {
		if got := builds[path]; got != wantType {
			t.Errorf("build config %s = %q, want %q", path, got, wantType)
		}
	}
	if len(m.Layout.TopLevelDirs) == 0 {
		t.Error("no top level directories reported")
	}
	signals := map[string]bool{}
	for _, s := range m.Layout.MonorepoSignals {
		signals[s.Name] = true
	}
	if !signals["npm workspaces"] {
		t.Errorf("npm workspaces signal missing: %+v", m.Layout.MonorepoSignals)
	}
	if !signals["multiple module roots"] {
		t.Errorf("multiple module roots signal missing: %+v", m.Layout.MonorepoSignals)
	}
}

func TestManifestIsDeterministicAndVersioned(t *testing.T) {
	t.Parallel()
	tree := polyglotFixture(t)
	first := analyzeTree(t, tree)
	second := analyzeTree(t, tree)

	first.GeneratedAt, second.GeneratedAt = "", ""
	a, err := first.JSON()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("analysis is not deterministic:\n%s\n---\n%s", a, b)
	}
	if first.AnalysisID != second.AnalysisID || first.RulesetHash != second.RulesetHash {
		t.Errorf("analysis id or ruleset hash is unstable: %s/%s vs %s/%s",
			first.AnalysisID, first.RulesetHash, second.AnalysisID, second.RulesetHash)
	}
	if first.AnalysisID != repository.AnalysisID(first.SnapshotID, first.Engine.Name, first.Engine.Version, first.RulesetHash, first.ConfigHash) {
		t.Error("analysis id does not follow hash(snapshot, engine, version, ruleset, config)")
	}

	// A different configuration must produce a different analysis id.
	other := NewAnalyzer(nil, Config{MaxReadBytes: 4096})
	in, err := NewInput(first.SnapshotID, tree)
	if err != nil {
		t.Fatal(err)
	}
	third, err := other.AnalyzeInput(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if third.AnalysisID == first.AnalysisID {
		t.Error("analysis id ignored the analyzer configuration")
	}
	if third.ConfigHash == first.ConfigHash {
		t.Error("config hash ignored the analyzer configuration")
	}
}

// customDetector proves the extension point works without touching the core.
type customDetector struct{}

func (customDetector) Name() string    { return "custom/always" }
func (customDetector) Version() string { return "9" }
func (customDetector) Detect(_ context.Context, _ *Input) ([]Detection, error) {
	return []Detection{{
		Kind:       KindLayout,
		Subject:    "custom",
		Detail:     map[string]string{"monorepo_signal": "custom signal"},
		Confidence: Observed,
	}}, nil
}

func TestRegistryAcceptsCustomDetectors(t *testing.T) {
	t.Parallel()
	tree := polyglotFixture(t)
	in, err := NewInput("snap-0123456789abcdef0123456789abcdef", tree)
	if err != nil {
		t.Fatal(err)
	}
	base := NewAnalyzer(nil, Config{})
	baseManifest, err := base.AnalyzeInput(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}

	reg := DefaultRegistry()
	reg.Register(customDetector{})
	custom := NewAnalyzer(reg, Config{})
	customManifest, err := custom.AnalyzeInput(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if customManifest.RulesetHash == baseManifest.RulesetHash {
		t.Error("ruleset hash did not change when a detector was registered")
	}
	found := false
	for _, s := range customManifest.Layout.MonorepoSignals {
		if s.Name == "custom signal" {
			found = true
		}
	}
	if !found {
		t.Errorf("custom detector output missing: %+v", customManifest.Layout.MonorepoSignals)
	}
	// Registering the same detector twice must not duplicate output.
	reg.Register(customDetector{})
	again := NewAnalyzer(reg, Config{})
	againManifest, err := again.AnalyzeInput(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(againManifest.Layout.MonorepoSignals) != len(customManifest.Layout.MonorepoSignals) {
		t.Errorf("duplicate registration duplicated detections: %d vs %d",
			len(againManifest.Layout.MonorepoSignals), len(customManifest.Layout.MonorepoSignals))
	}
}

func TestUnparsableAndTruncatedManifestsAreReported(t *testing.T) {
	t.Parallel()
	tree := writeTree(t, map[string]string{
		"package.json": "{ not json",
		"go.mod":       "module x\n\nrequire (\n\tgithub.com/a/b v1.0.0\n)\n",
	})
	in, err := NewInput("snap-0123456789abcdef0123456789abcdef", tree)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAnalyzer(nil, Config{MaxReadBytes: 16})
	m, err := a.AnalyzeInput(context.Background(), in)
	if err != nil {
		t.Fatalf("AnalyzeInput: %v", err)
	}
	managers := map[string]DependencyManager{}
	for _, mgr := range m.Dependencies.Managers {
		managers[mgr.Name] = mgr
	}
	if got := managers["npm"]; got.ParseStatus != ParseUnparsed {
		t.Errorf("invalid package.json status = %q, want unparsed (%+v)", got.ParseStatus, got)
	}
	if got := managers["go-modules"]; got.ParseStatus != ParsePartial {
		t.Errorf("truncated go.mod status = %q, want partial", got.ParseStatus)
	}
	if m.Coverage.TruncatedReads == 0 {
		t.Error("truncated reads were not counted in coverage")
	}
	joined := strings.Join(m.Unknowns, "\n")
	for _, want := range []string{"could not be parsed", "truncated at the read limit", "partial"} {
		if !strings.Contains(joined, want) {
			t.Errorf("unknowns do not mention %q:\n%s", want, joined)
		}
	}
}

func TestInputRefusesPathsOutsideTheTree(t *testing.T) {
	t.Parallel()
	tree := writeTree(t, map[string]string{"main.go": "package main\n"})
	in, err := NewInput("snap-0123456789abcdef0123456789abcdef", tree)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../secret", "/etc/passwd", "missing.go"} {
		if _, _, err := in.ReadFile(bad, 1024); err == nil {
			t.Errorf("ReadFile(%q) was allowed", bad)
		}
	}
	if in.Exists("../secret") {
		t.Error("Exists accepted a path outside the tree")
	}
}

func TestAnalyzeSnapshotAndStoreManifest(t *testing.T) {
	t.Parallel()
	mgr, err := repository.NewManager(filepath.Join(t.TempDir(), "work"))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := mgr.Create(context.Background(), repository.Source{Raw: polyglotFixture(t)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		if err := mgr.Remove(snap.SnapshotID); err != nil {
			t.Errorf("Remove: %v", err)
		}
	})

	a := NewAnalyzer(nil, Config{})
	m, err := a.Analyze(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if m.SnapshotID != snap.SnapshotID {
		t.Errorf("manifest snapshot id = %q, want %q", m.SnapshotID, snap.SnapshotID)
	}
	if m.Repository.Commit != snap.Commit || m.Repository.VCS != snap.VCS {
		t.Errorf("repository section does not restate the snapshot: %+v", m.Repository)
	}
	if len(m.SnapshotLimitations) == 0 {
		t.Error("snapshot limitations were not carried into the manifest")
	}
	if err := m.WriteTo(snap); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	stored, err := snap.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	var decoded Manifest
	if err := json.Unmarshal(stored, &decoded); err != nil {
		t.Fatalf("stored manifest is not valid JSON: %v", err)
	}
	if decoded.AnalysisID != m.AnalysisID {
		t.Errorf("stored analysis id %q != %q", decoded.AnalysisID, m.AnalysisID)
	}
	if err := m.WriteTo(snap); err == nil {
		t.Error("manifest overwrote an existing artifact")
	}
}

func keysOf(m map[string]FrameworkHit) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfPaths(m map[string]EntrypointHit) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func managerNames(m map[string]DependencyManager) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestManifestJSONAlwaysEmitsArrays(t *testing.T) {
	t.Parallel()
	// A tree with nothing to detect must still produce arrays, never null: the
	// manifest is a machine-readable contract.
	m := analyzeTree(t, writeTree(t, map[string]string{"LICENSE": "MIT\n"}))
	data, err := m.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"frameworks": []`, `"entrypoints": []`, `"build_configs": []`,
		`"data_formats": []`, `"languages": []`, `"unknowns": [`, `"snapshot_limitations": []`,
		`"top_level_dirs": []`, `"module_roots": []`, `"monorepo_signals": []`,
		`"managers": [`, `"packages": []`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("manifest JSON is missing %s:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), ": null") {
		t.Errorf("manifest JSON contains null fields:\n%s", data)
	}
}

func TestFrameworkDetectorReadsEachManifestOnce(t *testing.T) {
	t.Parallel()
	tree := polyglotFixture(t)
	in, err := NewInput("snap-0123456789abcdef0123456789abcdef", tree)
	if err != nil {
		t.Fatal(err)
	}
	d := NewFrameworkDetector()
	got, err := d.Detect(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no frameworks detected in the fixture")
	}
	_, calls, _, _ := in.ReadStats().Files, in.ReadStats().Calls, in.ReadStats().Bytes, in.ReadStats().Truncated
	// Without the manifest cache this detector alone would perform about 200
	// reads (22 rules x 9 manifests); the cache keeps it near the file count.
	if calls > 60 {
		t.Errorf("framework detector performed %d read calls; manifests are not being cached", calls)
	}
}
