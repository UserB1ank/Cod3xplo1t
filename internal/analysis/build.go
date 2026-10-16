package analysis

import (
	"context"
	"path"
	"sort"
	"strings"
)

// buildRule recognises one build, packaging, CI or deployment descriptor. Build
// descriptors are facts about how the project is assembled, so a present file is
// an Observed fact; nothing is executed to confirm it.
type buildRule struct {
	Type  string
	Bases []string
	Globs []string
}

// defaultBuildRules is the built-in P1 build descriptor table.
var defaultBuildRules = []buildRule{
	{Type: "dockerfile", Bases: []string{"Dockerfile", "Containerfile"}, Globs: []string{"Dockerfile.*", "*/Dockerfile", "*/Dockerfile.*"}},
	{Type: "docker-compose", Bases: []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}},
	{Type: "make", Bases: []string{"Makefile", "makefile", "GNUmakefile"}},
	{Type: "go-module", Bases: []string{"go.mod", "go.work"}},
	{Type: "npm-project", Bases: []string{"package.json"}},
	{Type: "pnpm-workspace", Bases: []string{"pnpm-workspace.yaml"}},
	{Type: "maven", Bases: []string{"pom.xml"}},
	{Type: "gradle", Bases: []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}},
	{Type: "cargo", Bases: []string{"Cargo.toml"}},
	{Type: "python-packaging", Bases: []string{"pyproject.toml", "setup.py", "setup.cfg", "Pipfile"}},
	{Type: "cmake", Bases: []string{"CMakeLists.txt"}},
	{Type: "bazel", Bases: []string{"BUILD", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"}},
	{Type: "nix", Bases: []string{"flake.nix", "default.nix", "shell.nix"}},
	{Type: "procfile", Bases: []string{"Procfile"}},
	{Type: "github-actions", Globs: []string{".github/workflows/*.yml", ".github/workflows/*.yaml"}},
	{Type: "gitlab-ci", Bases: []string{".gitlab-ci.yml", ".gitlab-ci.yaml"}},
	{Type: "circleci", Globs: []string{".circleci/config.yml", ".circleci/config.yaml"}},
	{Type: "jenkins", Bases: []string{"Jenkinsfile"}},
	{Type: "azure-pipelines", Bases: []string{"azure-pipelines.yml", "azure-pipelines.yaml"}},
	{Type: "drone-ci", Bases: []string{".drone.yml"}},
	{Type: "travis-ci", Bases: []string{".travis.yml"}},
	{Type: "serverless", Bases: []string{"serverless.yml", "serverless.yaml", "serverless.json"}},
	{Type: "kubernetes", Globs: []string{"k8s/*.yml", "k8s/*.yaml", "deploy/*.yml", "deploy/*.yaml", "deployments/*.yml", "deployments/*.yaml"}},
	{Type: "terraform", Globs: []string{"*.tf", "*/*.tf"}},
	{Type: "helm", Bases: []string{"Chart.yaml"}},
}

// BuildConfigDetector lists build, packaging, CI and deployment descriptors.
type BuildConfigDetector struct {
	Rules []buildRule
}

// NewBuildConfigDetector returns a detector over the default rule table.
func NewBuildConfigDetector() *BuildConfigDetector {
	return &BuildConfigDetector{Rules: defaultBuildRules}
}

// Name implements Detector.
func (d *BuildConfigDetector) Name() string { return "build/descriptors" }

// Version implements Detector.
func (d *BuildConfigDetector) Version() string { return "1" }

// Detect implements Detector.
func (d *BuildConfigDetector) Detect(_ context.Context, in *Input) ([]Detection, error) {
	type hit struct {
		types []string
	}
	found := map[string]*hit{}
	add := func(p, typ string) {
		h := found[p]
		if h == nil {
			h = &hit{}
			found[p] = h
		}
		if !containsString(h.types, typ) {
			h.types = append(h.types, typ)
		}
	}
	for _, rule := range d.Rules {
		for _, p := range matchBases(in, rule.Bases...) {
			add(p, rule.Type)
		}
		for _, glob := range rule.Globs {
			for _, p := range matchGlob(in, glob) {
				add(p, rule.Type)
			}
		}
	}
	out := make([]Detection, 0, len(found))
	for p, h := range found {
		sort.Strings(h.types)
		out = append(out, Detection{
			Kind:       KindBuildConfig,
			Subject:    p,
			Detail:     map[string]string{"type": strings.Join(h.types, "+")},
			Confidence: Observed,
			Evidence:   []Evidence{{Path: p, Note: "descriptor present in snapshot"}},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}

// moduleManifestBases are the files that mark a directory as a module root.
var moduleManifestBases = []string{
	"go.mod", "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
	"Cargo.toml", "pyproject.toml", "setup.py", "composer.json", "Gemfile",
	"*.csproj", "*.sln", "Chart.yaml",
}

// monorepoMarkers are files that indicate a multi-module repository.
var monorepoMarkers = map[string]string{
	"go.work":             "Go workspace",
	"pnpm-workspace.yaml": "pnpm workspace",
	"lerna.json":          "lerna",
	"nx.json":             "nx",
	"turbo.json":          "turborepo",
	"rush.json":           "rush",
	"yarn.lock":           "yarn workspace metadata",
	"bazel.rc":            "bazel",
}

// LayoutDetector describes the repository shape: top-level directories, module
// roots and monorepo signals.
type LayoutDetector struct{}

// NewLayoutDetector returns the layout detector.
func NewLayoutDetector() *LayoutDetector { return &LayoutDetector{} }

// Name implements Detector.
func (d *LayoutDetector) Name() string { return "layout/structure" }

// Version implements Detector.
func (d *LayoutDetector) Version() string { return "1" }

// Detect implements Detector.
func (d *LayoutDetector) Detect(_ context.Context, in *Input) ([]Detection, error) {
	var out []Detection

	topDirs := map[string]bool{}
	for _, f := range in.Files {
		segs := strings.Split(f.Path, "/")
		if len(segs) > 1 {
			topDirs[segs[0]] = true
		}
	}
	dirs := make([]string, 0, len(topDirs))
	for dir := range topDirs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		out = append(out, Detection{
			Kind:       KindLayout,
			Subject:    "top_level_dir:" + dir,
			Detail:     map[string]string{"top_level_dir": dir},
			Confidence: Observed,
		})
	}

	moduleRoots := map[string]string{}
	for _, f := range in.Files {
		matched := false
		for _, base := range moduleManifestBases {
			if ok, err := path.Match(base, f.Base); err == nil && ok {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		root := path.Dir(f.Path)
		if root == "." {
			root = "."
		}
		moduleRoots[root] = f.Path
	}
	roots := make([]string, 0, len(moduleRoots))
	for root := range moduleRoots {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, root := range roots {
		out = append(out, Detection{
			Kind:       KindLayout,
			Subject:    "module_root:" + root,
			Detail:     map[string]string{"module_root": root, "manifest": moduleRoots[root]},
			Confidence: Observed,
			Evidence:   []Evidence{{Path: moduleRoots[root], Note: "module manifest"}},
		})
	}

	signals := map[string]string{}
	for _, f := range in.Files {
		if name, ok := monorepoMarkers[f.Base]; ok {
			signals[name] = f.Path
		}
	}
	if len(roots) > 1 {
		signals["multiple module roots"] = ""
	}
	if data, _, err := readFileIfPresent(in, "package.json"); err == nil && data != nil {
		if strings.Contains(string(data), `"workspaces"`) {
			signals["npm workspaces"] = "package.json"
		}
	}
	if data, _, err := readFileIfPresent(in, "Cargo.toml"); err == nil && data != nil {
		if strings.Contains(string(data), "[workspace]") {
			signals["cargo workspace"] = "Cargo.toml"
		}
	}
	names := make([]string, 0, len(signals))
	for name := range signals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		det := Detection{
			Kind:       KindLayout,
			Subject:    "monorepo_signal:" + name,
			Detail:     map[string]string{"monorepo_signal": name, "signal_detail": signals[name]},
			Confidence: Observed,
		}
		if signals[name] != "" {
			det.Evidence = []Evidence{{Path: signals[name], Note: "monorepo marker"}}
		}
		out = append(out, det)
	}
	return out, nil
}

// readFileIfPresent reads a small file when it exists, returning nil data when
// it does not.
func readFileIfPresent(in *Input, file string) ([]byte, bool, error) {
	if !in.Exists(file) {
		return nil, false, nil
	}
	return in.ReadFile(file, 256<<10)
}
