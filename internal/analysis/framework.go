package analysis

import (
	"context"
	"path"
	"sort"
	"strings"
)

// FrameworkRule declares how one framework is recognised. Every rule must cite
// either a declared dependency, a source marker or a marker file; a framework is
// never reported on a hunch.
type FrameworkRule struct {
	Name     string
	Language string
	// Dependencies are package names searched in manifest files.
	Dependencies []string
	// ManifestBases restricts which manifests are searched. Empty means the
	// default manifest set.
	ManifestBases []string
	// SourceExts restricts source-marker scanning to these extensions.
	SourceExts []string
	// SourceMarkers are content markers searched in source files.
	SourceMarkers []string
	// FileNames are file names or path globs that indicate the framework.
	FileNames []string
	// Note explains what the rule does and does not cover.
	Note string
}

// defaultManifestBases is the manifest set searched for dependency declarations.
var defaultManifestBases = []string{
	"go.mod", "package.json", "requirements.txt", "pyproject.toml", "Cargo.toml",
	"pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "Gemfile.lock", "composer.json",
}

// DefaultFrameworkRules returns the built-in P1 rules.
func DefaultFrameworkRules() []FrameworkRule {
	return []FrameworkRule{
		{
			Name: "Gin", Language: "Go",
			Dependencies:  []string{"github.com/gin-gonic/gin"},
			SourceExts:    []string{".go"},
			SourceMarkers: []string{"gin.Default()", "gin.New()", "gin.Context"},
		},
		{
			Name: "Echo", Language: "Go",
			Dependencies:  []string{"github.com/labstack/echo"},
			SourceExts:    []string{".go"},
			SourceMarkers: []string{"echo.New()"},
		},
		{
			Name: "Fiber", Language: "Go",
			Dependencies:  []string{"github.com/gofiber/fiber"},
			SourceExts:    []string{".go"},
			SourceMarkers: []string{"fiber.New()", "fiber.Ctx"},
		},
		{
			Name: "Chi", Language: "Go",
			Dependencies:  []string{"github.com/go-chi/chi"},
			SourceExts:    []string{".go"},
			SourceMarkers: []string{"chi.NewRouter()"},
		},
		{
			Name: "gRPC-Go", Language: "Go",
			Dependencies: []string{"google.golang.org/grpc"},
			SourceExts:   []string{".go"},
		},
		{
			Name: "GORM", Language: "Go",
			Dependencies: []string{"gorm.io/gorm"},
			SourceExts:   []string{".go"},
		},
		{
			Name: "FastAPI", Language: "Python",
			Dependencies:  []string{"fastapi"},
			SourceExts:    []string{".py"},
			SourceMarkers: []string{"FastAPI(", "from fastapi import"},
		},
		{
			Name: "Flask", Language: "Python",
			Dependencies:  []string{"flask"},
			SourceExts:    []string{".py"},
			SourceMarkers: []string{"Flask(__name__)", "from flask import"},
		},
		{
			Name: "Django", Language: "Python",
			Dependencies:  []string{"django", "Django"},
			SourceExts:    []string{".py"},
			SourceMarkers: []string{"django.db", "django.http", "DJANGO_SETTINGS_MODULE"},
			FileNames:     []string{"manage.py"},
		},
		{
			Name: "Starlette", Language: "Python",
			Dependencies:  []string{"starlette"},
			SourceExts:    []string{".py"},
			SourceMarkers: []string{"from starlette"},
		},
		{
			Name: "Express", Language: "JavaScript",
			Dependencies:  []string{"\"express\""},
			SourceExts:    []string{".js", ".mjs", ".cjs", ".ts"},
			SourceMarkers: []string{"require('express')", `require("express")`, "from 'express'", `from "express"`},
		},
		{
			Name: "NestJS", Language: "TypeScript",
			Dependencies: []string{"@nestjs/core"},
			SourceExts:   []string{".ts"},
			FileNames:    []string{"nest-cli.json"},
		},
		{
			Name: "Next.js", Language: "JavaScript",
			Dependencies: []string{"\"next\""},
			FileNames:    []string{"next.config.js", "next.config.mjs", "next.config.ts"},
		},
		{
			Name: "React", Language: "JavaScript",
			Dependencies: []string{"\"react\""},
		},
		{
			Name: "Vue", Language: "JavaScript",
			Dependencies: []string{"\"vue\""},
			FileNames:    []string{"vue.config.js"},
		},
		{
			Name: "Spring Boot", Language: "Java",
			Dependencies:  []string{"spring-boot"},
			ManifestBases: []string{"pom.xml", "build.gradle", "build.gradle.kts"},
			SourceExts:    []string{".java", ".kt"},
			SourceMarkers: []string{"@SpringBootApplication"},
		},
		{
			Name: "Ruby on Rails", Language: "Ruby",
			Dependencies:  []string{"rails"},
			SourceExts:    []string{".rb"},
			SourceMarkers: []string{"Rails.application", "ActionController::Base"},
			FileNames:     []string{"config/routes.rb"},
		},
		{
			Name: "Sinatra", Language: "Ruby",
			Dependencies:  []string{"sinatra"},
			SourceExts:    []string{".rb"},
			SourceMarkers: []string{"Sinatra::Base", "require 'sinatra'"},
		},
		{
			Name: "Laravel", Language: "PHP",
			Dependencies: []string{"laravel/framework"},
			FileNames:    []string{"artisan"},
		},
		{
			Name: "ASP.NET Core", Language: "C#",
			SourceExts:    []string{".cs"},
			SourceMarkers: []string{"WebApplication.CreateBuilder"},
			FileNames:     []string{"*.csproj"},
			Note:          "detected from project files or the hosting marker; csproj content is not inspected",
		},
		{
			Name: "Actix Web", Language: "Rust",
			Dependencies: []string{"actix-web"},
		},
		{
			Name: "Axum", Language: "Rust",
			Dependencies: []string{"axum"},
		},
	}
}

// FrameworkDetector matches framework rules against manifests, source markers
// and marker files.
type FrameworkDetector struct {
	Rules          []FrameworkRule
	MaxScanFiles   int
	MaxMarkerBytes int64
}

// NewFrameworkDetector returns a detector over the default rules.
func NewFrameworkDetector() *FrameworkDetector {
	return &FrameworkDetector{Rules: DefaultFrameworkRules()}
}

// Name implements Detector.
func (d *FrameworkDetector) Name() string { return "framework/rules" }

// Version implements Detector.
func (d *FrameworkDetector) Version() string { return "1" }

// Detect implements Detector.
func (d *FrameworkDetector) Detect(_ context.Context, in *Input) ([]Detection, error) {
	maxFiles := d.MaxScanFiles
	if maxFiles <= 0 {
		maxFiles = 200
	}
	maxBytes := d.MaxMarkerBytes
	if maxBytes <= 0 {
		maxBytes = 256 << 10 // still clamped by the input limit
	}
	// Every manifest is read once and reused by every rule: rules are many, the
	// files are few, and repeated reads inflate coverage accounting and cost.
	manifestCache := map[string][]byte{}
	for _, file := range matchBases(in, defaultManifestBases...) {
		if _, ok := manifestCache[file]; ok {
			continue
		}
		data, _, err := in.ReadFile(file, maxBytes)
		if err != nil {
			continue
		}
		manifestCache[file] = data
	}

	var out []Detection
	for _, rule := range d.Rules {
		var evidence []Evidence
		matches := map[string]bool{}

		bases := rule.ManifestBases
		if len(bases) == 0 {
			bases = defaultManifestBases
		}
		for _, file := range matchBases(in, bases...) {
			data, ok := manifestCache[file]
			if !ok {
				continue
			}
			for _, dep := range rule.Dependencies {
				if dep == "" {
					continue
				}
				if line := lineOf(data, dep); line > 0 {
					matches["dependency"] = true
					evidence = append(evidence, Evidence{Path: file, Line: line, Note: "declared dependency " + strings.Trim(dep, `"`)})
					break
				}
			}
		}

		if len(rule.SourceMarkers) > 0 && len(rule.SourceExts) > 0 {
			scanned := 0
			for _, f := range in.Files {
				if scanned >= maxFiles {
					break
				}
				if !containsString(rule.SourceExts, f.Ext) {
					continue
				}
				scanned++
				data, _, err := in.ReadFile(f.Path, maxBytes)
				if err != nil {
					continue
				}
				for _, marker := range rule.SourceMarkers {
					if line := lineOf(data, marker); line > 0 {
						matches["source_marker"] = true
						evidence = append(evidence, Evidence{Path: f.Path, Line: line, Note: "source marker " + marker})
						break
					}
				}
			}
		}

		for _, name := range rule.FileNames {
			var found []FileInfo
			if strings.ContainsAny(name, "*?[") {
				found = in.Match(func(f FileInfo) bool {
					ok, err := path.Match(name, f.Path)
					return err == nil && ok
				})
			} else {
				found = in.ByBase(name)
			}
			for _, f := range found {
				matches["file"] = true
				evidence = append(evidence, Evidence{Path: f.Path, Note: "marker file"})
			}
		}

		if len(matches) == 0 {
			continue
		}
		confidence := Inferred
		if matches["source_marker"] {
			confidence = Observed
		}
		detail := map[string]string{"language": rule.Language}
		if rule.Note != "" {
			detail["note"] = rule.Note
		}
		out = append(out, Detection{
			Kind:       KindFramework,
			Subject:    rule.Name,
			Detail:     detail,
			Confidence: confidence,
			Evidence:   capEvidence(evidence, 3),
			Limitations: []string{
				"rule based detection: frameworks registered only through framework-specific configuration are not detected",
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}

// lineOf returns the 1-based line number of the first occurrence of marker, or 0
// when the marker is absent.
func lineOf(data []byte, marker string) int {
	idx := strings.Index(string(data), marker)
	if idx < 0 {
		return 0
	}
	return 1 + strings.Count(string(data[:idx]), "\n")
}
