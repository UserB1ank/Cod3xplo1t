package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

func (j *job) parse() error {
	var config struct {
		Frontend  string `json:"frontend"`
		Heap      int    `json:"heap_mib"`
		InputPath string `json:"input_path"`
	}
	if err := decodeConfig(j.Request.Config, &config); err != nil {
		return err
	}
	all, err := loadFrontends(j.Package)
	if err != nil {
		return unavailable("dependency_unavailable")
	}
	tree, inventory, err := j.source()
	if err != nil {
		return err
	}
	seenInput := int64(len(inventory))
	j.Result.Coverage.Seen = &seenInput
	// Cargo configuration can supply executable wrappers. Remove it only in
	// the private analysis copy; the immutable source artifact is unchanged.
	for path := range inventory {
		if filepath.Base(filepath.Dir(path)) == ".cargo" && (filepath.Base(path) == "config" || filepath.Base(path) == "config.toml") {
			if len(j.inputs("source")) == 1 && j.inputs("source")[0].SchemaID == "codexploit/source-directory/v1" {
				return failed("invalid_input")
			}
			if e := os.Remove(filepath.Join(tree, filepath.FromSlash(path))); e != nil {
				return failed("invalid_input")
			}
		}
	}
	selected, err := selectFrontends(all, config.Frontend, inventory)
	if err != nil {
		return unavailable("unsupported_language")
	}
	files := map[string]map[string]any{}
	symbols, calls, mappings := []any{}, []any{}, []any{}
	limits := []string{"Static facts cover the selected frontends; exhaustive per-file diagnostics and complete call resolution are not guaranteed.", "Target build scripts, macros, dependency downloads and target execution are disabled.", "Call relationships do not by themselves establish taint flow or a vulnerability verdict."}
	for _, f := range selected {
		if f.ID == "RUST" {
			for _, name := range []string{"cargo", "rustc"} {
				if info, e := os.Stat(filepath.Join(j.Package, "vendor/rust/bin", name)); e != nil || !info.Mode().IsRegular() {
					return unavailable("dependency_unavailable")
				}
			}
		}
		if f.ID == "PHP" {
			if info, e := os.Stat(filepath.Join(j.Package, "vendor/php/bin/php")); e != nil || !info.Mode().IsRegular() {
				return unavailable("dependency_unavailable")
			}
		}
		input := tree
		if config.InputPath != "" {
			if !safeRelative(config.InputPath) {
				return failed("invalid_config")
			}
			input = filepath.Join(tree, filepath.FromSlash(config.InputPath))
			if _, e := os.Lstat(input); e != nil {
				return failed("invalid_input")
			}
		}
		if f.Kind == "binary" {
			info, e := os.Lstat(input)
			if e != nil || !info.Mode().IsRegular() {
				return failed("invalid_config")
			}
		}
		native := filepath.Join(j.Work, "cpg-"+f.ID+".bin")
		args := append([]string{input, "--output", native}, f.Arguments...)
		if err := j.java(f.Module, f.MainClass, config.Heap, args...); err != nil {
			return j.frontendFailure(f.ID, "parse", "", err)
		}
		exported := filepath.Join(j.Work, "export-"+f.ID+".json")
		if err := j.script("export.sc", config.Heap, "cpgFile="+native, "outFile="+exported); err != nil {
			return j.frontendFailure(f.ID, "export", "", err)
		}
		info, e := os.Stat(exported)
		if e != nil {
			return j.frontendFailure(f.ID, "export", "export_unavailable", failed("normalization_failed"))
		}
		if info.Size() > j.Request.Budget.MaxOutputBytes {
			return j.frontendFailure(f.ID, "export", "export_byte_budget", failed("report_budget_exceeded"))
		}
		raw, e := os.ReadFile(exported)
		if e != nil {
			return j.frontendFailure(f.ID, "export", "export_read_failed", failed("normalization_failed"))
		}
		facts, coverage, _, e := normalize(raw, tree, inventory, f, fmt.Sprintf("output:cpg:%d", len(j.Result.Outputs)))
		if e != nil {
			return j.frontendFailure(f.ID, "normalize", "invalid_cpg_export", failed("normalization_failed"))
		}

		for _, row := range facts["files"].([]any) {
			item := row.(map[string]any)
			path := item["path"].(string)
			old := files[path]
			if old == nil || item["parse_status"] == "partial" || (old["parse_status"] == "unhandled" && item["parse_status"] == "unparsed") {
				files[path] = item
			}
		}
		j.Result.Coverage = parsedFileCoverage(inventory, files)
		if coverage.Analyzed == nil || *coverage.Analyzed == 0 {
			j.Result.Limitations = append(j.Result.Limitations, "joern:frontend="+f.ID+";step=normalize;reason=no_analyzed_files;action=continue_other_frontends")
			continue
		}
		symbols = append(symbols, facts["symbols"].([]any)...)
		calls = append(calls, facts["calls"].([]any)...)
		mappings = append(mappings, facts["native_id_mappings"].([]any)...)
		name := "cpg-" + f.ID + ".bin"
		if err := copyFile(filepath.Join(j.Work, "workspace", filepath.Base(native), "cpg.bin"), filepath.Join(j.Output, name), j.Request.Budget.MaxOutputBytes-j.Total); err != nil {
			return err
		}
		if err := j.addOutput("cpg", "tool.native", "joern/cpg/v1", name, "application/octet-stream"); err != nil {
			return err
		}
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	rows := []any{}
	var analyzed, skipped, failedCount int64
	for _, p := range paths {
		item := files[p]
		rows = append(rows, item)
		switch item["parse_status"] {
		case "partial", "parsed":
			analyzed++
		case "unhandled":
			skipped++
		default:
			failedCount++
		}
	}
	if analyzed == 0 {
		return failed("normalization_failed")
	}
	facts := map[string]any{"files": rows, "symbols": symbols, "calls": calls, "native_id_mappings": mappings}
	if err := j.jsonOutput("code", "code.facts", "codexploit/code-facts/v2", "code.json", facts); err != nil {
		return err
	}
	seen := int64(len(inventory))
	j.Result.Coverage = pluginsdk.Coverage{Unit: "files", Seen: &seen, Analyzed: &analyzed, Skipped: &skipped, Failed: &failedCount, Reasons: []string{"frontend_diagnostics_not_exhaustive"}}
	j.Result.Limitations = append(limits, j.Result.Limitations...)
	j.Result.Status = "PARTIAL"
	return nil
}

func parsedFileCoverage(inventory map[string]bool, files map[string]map[string]any) pluginsdk.Coverage {
	seen := int64(len(inventory))
	var analyzed, skipped, failed int64
	for _, row := range files {
		switch row["parse_status"] {
		case "parsed", "partial":
			analyzed++
		case "unhandled":
			skipped++
		default:
			failed++
		}
	}
	return pluginsdk.Coverage{Unit: "files", Seen: &seen, Analyzed: &analyzed, Skipped: &skipped, Failed: &failed, Reasons: []string{"frontend_diagnostics_not_exhaustive"}}
}
