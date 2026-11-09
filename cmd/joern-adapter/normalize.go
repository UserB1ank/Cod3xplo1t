package main

import (
	"encoding/json"
	"errors"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

type nativeLocation struct {
	Filename string `json:"filename"`
	Line     *int   `json:"line"`
	Column   *int   `json:"column"`
}
type nativeExport struct {
	Files []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"files"`
	Methods []struct {
		nativeLocation
		ID        string `json:"id"`
		Name      string `json:"name"`
		FullName  string `json:"full_name"`
		Signature string `json:"signature"`
		External  bool   `json:"external"`
	} `json:"methods"`
	Calls []struct {
		nativeLocation
		ID       string `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"method_full_name"`
		Caller   string `json:"caller"`
		Callees  []struct {
			ID       string `json:"id"`
			External bool   `json:"external"`
		} `json:"callees"`
	} `json:"calls"`
}

func normalize(raw []byte, sourceRoot, inputRoot string, inventory map[string]bool, front frontend, nativeAlias string) (map[string]any, pluginsdk.Coverage, []string, error) {
	var exported nativeExport
	if json.Unmarshal(raw, &exported) != nil || exported.Files == nil || exported.Methods == nil || exported.Calls == nil {
		return nil, pluginsdk.Coverage{}, nil, errors.New("invalid CPG export")
	}
	files, symbols, calls, mappings := []any{}, []any{}, []any{}, []any{}
	inputPrefix := ""
	if relativeInput, err := filepath.Rel(sourceRoot, inputRoot); err == nil {
		relativeInput = filepath.ToSlash(relativeInput)
		if relativeInput != "." && safeRelative(relativeInput) {
			inputPrefix = relativeInput
		}
	}
	frozen := func(name string) string {
		name = filepath.ToSlash(name)
		if safeRelative(name) && inventory[name] {
			return name
		}
		return ""
	}
	inputRelative := func(name string) string {
		if inputPrefix == "" {
			return ""
		}
		return frozen(path.Join(inputPrefix, filepath.ToSlash(name)))
	}
	relative := func(name string) string {
		if filepath.IsAbs(name) {
			rel, err := filepath.Rel(sourceRoot, name)
			if err == nil {
				if canonical := frozen(rel); canonical != "" {
					return canonical
				}
			}
			if inputPrefix != "" {
				rel, err = filepath.Rel(inputRoot, name)
				if err == nil {
					if canonical := inputRelative(rel); canonical != "" {
						return canonical
					}
				}
			}
			// Native tools may resolve /tmp to /private/tmp or copy bytecode to
			// a private frontend directory. Bind only an unambiguous frozen file.
			matched := ""
			for path := range inventory {
				if strings.HasSuffix(filepath.ToSlash(name), "/"+path) {
					if matched != "" {
						return ""
					}
					matched = path
				}
			}
			if matched != "" {
				return matched
			}
			if front.Kind == "bytecode" {
				for path := range inventory {
					if front.matches(path) {
						if matched != "" {
							return ""
						}
						matched = path
					}
				}
				return matched
			}
			return ""
		}
		if canonical := inputRelative(name); canonical != "" {
			return canonical
		}
		if canonical := frozen(name); canonical != "" {
			return canonical
		}
		return ""
	}
	mapping := func(native, canonical string) {
		mappings = append(mappings, map[string]any{"native_artifact_ref": nativeAlias, "native_id": native, "canonical_ref": canonical, "mapping_rule": "joern-node/v2", "mapping_status": "mapped"})
	}
	graphFiles := map[string]bool{}
	for _, f := range exported.Files {
		if path := relative(f.Name); path != "" && (front.matches(path) || front.Kind == "binary") {
			graphFiles[path] = true
			mapping(f.ID, "source:"+path)
		}
	}
	paths := make([]string, 0, len(inventory))
	for path := range inventory {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var analyzed, skipped, failed int64
	for _, path := range paths {
		language, status, reason := "unknown", "unhandled", "unsupported_file_type"
		if front.matches(path) || (front.Kind == "binary" && graphFiles[path]) {
			language = front.language(path)
			status = "unparsed"
			reason = "file_not_in_cpg"
			if graphFiles[path] {
				status = "partial"
				reason = "frontend_diagnostics_not_exhaustive"
				analyzed++
			} else {
				failed++
			}
		} else {
			skipped++
		}
		files = append(files, map[string]any{"file_id": "source:" + path, "path": path, "language": language, "parse_status": status, "reason": reason})
	}
	locate := func(n nativeLocation) any {
		if front.Kind == "binary" || front.Kind == "bytecode" {
			return nil
		}
		path := relative(n.Filename)
		if path == "" || n.Line == nil || *n.Line < 1 {
			return nil
		}
		var column any
		if n.Column != nil && *n.Column > 0 {
			column = *n.Column
		}
		return map[string]any{"file": path, "start_line": *n.Line, "start_column": column, "end_line": nil, "end_column": nil}
	}
	symbolIDs := map[string]bool{}
	sort.Slice(exported.Methods, func(i, j int) bool { return exported.Methods[i].ID < exported.Methods[j].ID })
	for _, method := range exported.Methods {
		path := relative(method.Filename)
		if method.External || path == "" || !graphFiles[path] {
			continue
		}
		if method.ID == "" || method.Name == "" || method.FullName == "" || symbolIDs[method.ID] {
			return nil, pluginsdk.Coverage{}, nil, errors.New("invalid CPG method")
		}
		symbolIDs[method.ID] = true
		id := "joern-method:" + front.ID + ":" + method.ID
		symbols = append(symbols, map[string]any{"id": id, "file_id": "source:" + path, "kind": "function", "name": method.Name, "qualified_name": method.FullName, "signature": method.Signature, "location": locate(method.nativeLocation)})
		mapping(method.ID, id)
	}
	sort.Slice(exported.Calls, func(i, j int) bool { return exported.Calls[i].ID < exported.Calls[j].ID })
	callKeys := map[string]int{}
	key := func(n nativeLocation, text string) string {
		line, column := 0, 0
		if n.Line != nil {
			line = *n.Line
		}
		if n.Column != nil {
			column = *n.Column
		}
		return relative(n.Filename) + ":" + strconv.Itoa(line) + ":" + strconv.Itoa(column) + ":" + text
	}
	for _, call := range exported.Calls {
		text := call.FullName
		if text == "" {
			text = call.Name
		}
		callKeys[key(call.nativeLocation, text)]++
	}
	omitted := false
	ids := map[string]bool{}
	for _, call := range exported.Calls {
		path := relative(call.Filename)
		if path == "" || !graphFiles[path] {
			continue
		}
		text := call.FullName
		if text == "" {
			text = call.Name
		}
		if call.ID == "" || text == "" || ids[call.ID] {
			return nil, pluginsdk.Coverage{}, nil, errors.New("invalid CPG call")
		}
		ids[call.ID] = true
		if callKeys[key(call.nativeLocation, text)] > 1 || locate(call.nativeLocation) == nil {
			omitted = true
			continue
		}
		var caller, callee any
		resolution := "unresolved"
		if symbolIDs[call.Caller] {
			caller = "joern-method:" + front.ID + ":" + call.Caller
		}
		if len(call.Callees) == 1 {
			target := call.Callees[0]
			if target.External {
				resolution = "external"
			} else if symbolIDs[target.ID] && caller != nil {
				callee = "joern-method:" + front.ID + ":" + target.ID
				resolution = "resolved"
			}
		} else if len(call.Callees) > 1 {
			resolution = "dynamic"
		}
		id := "joern-call:" + front.ID + ":" + call.ID
		calls = append(calls, map[string]any{"id": id, "caller_ref": caller, "callee_ref": callee, "callee_text": text, "location": locate(call.nativeLocation), "resolution": resolution, "evidence_refs": []string{}})
		mapping(call.ID, id)
	}
	seen := int64(len(inventory))
	reasons := []string{"frontend_diagnostics_not_exhaustive"}
	if skipped > 0 {
		reasons = append(reasons, "unsupported_file_type")
	}
	if failed > 0 {
		reasons = append(reasons, "file_not_in_cpg")
	}
	if omitted {
		reasons = append(reasons, "ambiguous_call_location_omitted")
	}
	coverage := pluginsdk.Coverage{Unit: "files", Seen: &seen, Analyzed: &analyzed, Skipped: &skipped, Failed: &failed, Reasons: reasons}
	limitations := []string{"Selected frontend only; dependencies are not fetched and target code is not built or executed.", "Analyzed counts files represented in the CPG; exhaustive per-file diagnostics and complete call resolution are not guaranteed.", "Code facts describe structure and calls; they do not assert taint flow or vulnerability verdicts."}
	if omitted {
		limitations = append(limitations, "Calls without unique source positions were omitted; their native nodes remain in the CPG.")
	}
	return map[string]any{"files": files, "symbols": symbols, "calls": calls, "native_id_mappings": mappings}, coverage, limitations, nil
}
