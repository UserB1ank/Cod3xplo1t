package analysis

import (
	"context"
	"path"
	"sort"
	"strings"
)

// EntrypointRule declares how one kind of executable entry is recognised.
//
// A rule with Markers only reports a file when a marker is actually present, and
// the resulting fact is Observed. A rule without markers reports file names,
// which is a weaker claim, so those hits are Inferred by default.
type EntrypointRule struct {
	Type       string
	Language   string
	Bases      []string
	PathGlobs  []string
	Markers    []string
	Confidence ConfidenceClass
	Note       string
	// MaxHits bounds how many files one rule reports; the limit is stated in the
	// detection detail instead of being applied silently.
	MaxHits int
}

// DefaultEntrypointRules returns the built-in P1 entrypoint rules.
func DefaultEntrypointRules() []EntrypointRule {
	return []EntrypointRule{
		{
			Type: "go-main", Language: "Go",
			Bases:   []string{"main.go"},
			Markers: []string{"package main"},
		},
		{
			Type: "go-main", Language: "Go",
			PathGlobs: []string{"cmd/*/main.go", "cmd/*/*/main.go", "*/main.go"},
			Markers:   []string{"package main"},
		},
		{
			Type: "go-command", Language: "Go",
			Markers:    []string{"cobra.Command{"},
			PathGlobs:  []string{"cmd/*.go", "cmd/*/*.go"},
			Confidence: Observed,
		},
		{
			Type: "python-entrypoint", Language: "Python",
			Bases:      []string{"manage.py", "wsgi.py", "asgi.py", "__main__.py"},
			Confidence: Inferred,
			Note:       "recognised by file name; the module is not imported or executed",
		},
		{
			Type: "python-entrypoint", Language: "Python",
			Bases:      []string{"app.py", "main.py", "run.py", "server.py"},
			Markers:    []string{"if __name__ ==", "uvicorn.run", "app.run(", "FastAPI(", "Flask("},
			Confidence: Observed,
		},
		{
			Type: "node-entrypoint", Language: "JavaScript",
			Bases:      []string{"index.js", "server.js", "app.js", "main.js", "index.ts", "server.ts", "main.ts"},
			Confidence: Inferred,
			Note:       "recognised by file name; the process entry declared in package.json is not resolved",
		},
		{
			Type: "java-main", Language: "Java",
			PathGlobs: []string{"*.java", "*/*.java", "*/*/*.java", "*/*/*/*.java", "*/*/*/*/*.java"},
			Markers:   []string{"public static void main"},
		},
		{
			Type: "spring-main", Language: "Java",
			Markers:    []string{"@SpringBootApplication"},
			PathGlobs:  []string{"*.java", "*/*.java", "*/*/*.java", "*/*/*/*.java", "*/*/*/*/*.java"},
			Confidence: Observed,
		},
		{
			Type: "csharp-main", Language: "C#",
			Bases:   []string{"Program.cs"},
			Markers: []string{"static void Main", "static async Task Main"},
		},
		{
			Type: "rust-main", Language: "Rust",
			Bases:   []string{"main.rs"},
			Markers: []string{"fn main("},
		},
		{
			Type: "php-entrypoint", Language: "PHP",
			PathGlobs:  []string{"public/index.php", "index.php"},
			Confidence: Inferred,
		},
		{
			Type: "artisan", Language: "PHP",
			Bases:      []string{"artisan"},
			Confidence: Observed,
			Note:       "Laravel CLI entry point",
		},
	}
}

// EntrypointDetector applies entrypoint rules to a tree.
type EntrypointDetector struct {
	Rules          []EntrypointRule
	MaxMarkerBytes int64
}

// NewEntrypointDetector returns a detector over the default rules.
func NewEntrypointDetector() *EntrypointDetector {
	return &EntrypointDetector{Rules: DefaultEntrypointRules()}
}

// Name implements Detector.
func (d *EntrypointDetector) Name() string { return "entrypoint/rules" }

// Version implements Detector.
func (d *EntrypointDetector) Version() string { return "1" }

// Detect implements Detector.
func (d *EntrypointDetector) Detect(_ context.Context, in *Input) ([]Detection, error) {
	maxBytes := d.MaxMarkerBytes
	if maxBytes <= 0 {
		maxBytes = 128 << 10
	}
	var out []Detection
	for _, rule := range d.Rules {
		maxHits := rule.MaxHits
		if maxHits <= 0 {
			maxHits = 25
		}
		candidates := map[string]FileInfo{}
		for _, base := range rule.Bases {
			for _, f := range in.ByBase(base) {
				candidates[f.Path] = f
			}
		}
		for _, glob := range rule.PathGlobs {
			for _, f := range in.Match(func(f FileInfo) bool {
				ok, err := path.Match(glob, f.Path)
				return err == nil && ok
			}) {
				candidates[f.Path] = f
			}
		}
		paths := make([]string, 0, len(candidates))
		for p := range candidates {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		hits := 0
		truncated := false
		for _, p := range paths {
			if hits >= maxHits {
				truncated = true
				break
			}
			f := candidates[p]
			confidence := rule.Confidence
			if confidence == "" {
				confidence = Inferred
			}
			var evidence []Evidence
			if len(rule.Markers) > 0 {
				data, _, err := in.ReadFile(f.Path, maxBytes)
				if err != nil {
					continue
				}
				matched := ""
				line := 0
				for _, marker := range rule.Markers {
					if l := lineOf(data, marker); l > 0 {
						matched, line = marker, l
						break
					}
				}
				if matched == "" {
					// A rule that requires a marker never claims a file on its
					// name alone.
					continue
				}
				confidence = Observed
				evidence = append(evidence, Evidence{Path: f.Path, Line: line, Note: "marker " + matched})
			} else {
				evidence = append(evidence, Evidence{Path: f.Path, Note: "file name rule"})
			}
			detail := map[string]string{"type": rule.Type, "language": rule.Language}
			if rule.Note != "" {
				detail["note"] = rule.Note
			}
			if truncated {
				detail["truncated"] = "true"
			}
			out = append(out, Detection{
				Kind:       KindEntrypoint,
				Subject:    f.Path,
				Detail:     detail,
				Confidence: confidence,
				Evidence:   evidence,
			})
			hits++
		}
	}
	// The same path can satisfy several rules; keep the strongest claim and
	// record the other rule types in the detail.
	return mergeEntrypoints(out), nil
}

// mergeEntrypoints keeps one hit per path, preferring higher confidence and
// joining the rule types that matched.
func mergeEntrypoints(in []Detection) []Detection {
	best := map[string]Detection{}
	for _, d := range in {
		cur, ok := best[d.Subject]
		if !ok {
			best[d.Subject] = d
			continue
		}
		types := strings.Split(cur.Detail["type"], "+")
		if !containsString(types, d.Detail["type"]) {
			cur.Detail["type"] = cur.Detail["type"] + "+" + d.Detail["type"]
		}
		if confidenceRank(d.Confidence) > confidenceRank(cur.Confidence) {
			cur.Confidence = d.Confidence
		}
		cur.Evidence = append(cur.Evidence, d.Evidence...)
		best[d.Subject] = cur
	}
	out := make([]Detection, 0, len(best))
	for _, d := range best {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}
