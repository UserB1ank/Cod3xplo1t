package scg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

// moduleManifestBases are the files that mark a directory as a module root.
var moduleManifestBases = []string{
	"go.mod", "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
	"Cargo.toml", "pyproject.toml", "composer.json", "Gemfile", "Chart.yaml",
}

// DefaultEngine identifies the P2 graph builder.
var DefaultEngine = Engine{Name: "codexploit/scg", Version: "0.1.0"}

// BuildLimits bound a graph build. Every limit that is reached is reported as a
// limitation: a partial graph must never look complete.
type BuildLimits struct {
	MaxFiles         int
	MaxFileBytes     int64
	MaxSymbols       int
	MaxCallSites     int
	MaxEdges         int
	MaxManifestBytes int64
	PerFileTimeout   time.Duration
	TotalTimeout     time.Duration
}

// DefaultBuildLimits returns the P2 defaults.
func DefaultBuildLimits() BuildLimits {
	return BuildLimits{
		MaxFiles:         20000,
		MaxFileBytes:     2 << 20,
		MaxSymbols:       200000,
		MaxCallSites:     500000,
		MaxEdges:         1000000,
		MaxManifestBytes: 64 << 10,
		PerFileTimeout:   5 * time.Second,
		TotalTimeout:     10 * time.Minute,
	}
}

// WithDefaults fills zero fields.
func (l BuildLimits) WithDefaults() BuildLimits {
	d := DefaultBuildLimits()
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxSymbols <= 0 {
		l.MaxSymbols = d.MaxSymbols
	}
	if l.MaxCallSites <= 0 {
		l.MaxCallSites = d.MaxCallSites
	}
	if l.MaxEdges <= 0 {
		l.MaxEdges = d.MaxEdges
	}
	if l.MaxManifestBytes <= 0 {
		l.MaxManifestBytes = d.MaxManifestBytes
	}
	if l.PerFileTimeout <= 0 {
		l.PerFileTimeout = d.PerFileTimeout
	}
	if l.TotalTimeout <= 0 {
		l.TotalTimeout = d.TotalTimeout
	}
	return l
}

// Builder turns a frozen snapshot into an SCG.
type Builder struct {
	Registry *Registry
	Engine   Engine
	Limits   BuildLimits
	// LanguageRules attributes files to languages. It defaults to the repository
	// analyzer's table, so the snapshot and the graph agree on what a file is.
	LanguageRules *analysis.LanguageRules
	Now           func() time.Time
}

// NewBuilder builds a Builder over the given frontends.
func NewBuilder(frontends ...Frontend) *Builder {
	return &Builder{
		Registry:      NewRegistry(frontends...),
		Engine:        DefaultEngine,
		Limits:        DefaultBuildLimits(),
		LanguageRules: analysis.DefaultLanguageRules(),
		Now:           func() time.Time { return time.Now().UTC() },
	}
}

// Build builds the graph of a snapshot.
func (b *Builder) Build(ctx context.Context, snap *repository.Snapshot) (*Graph, error) {
	if snap == nil {
		return nil, errors.New("scg: nil snapshot")
	}
	return b.BuildTree(ctx, snap.SnapshotID, snap.TreeDir())
}

// BuildTree builds the graph of a frozen tree. It is exported so tests and
// tooling can build from a directory without a snapshot record.
func (b *Builder) BuildTree(ctx context.Context, snapshotID, treeDir string) (*Graph, error) {
	if strings.TrimSpace(snapshotID) == "" {
		return nil, errors.New("scg: empty snapshot id")
	}
	b.applyDefaults()
	limits := b.Limits.WithDefaults()

	ctx, cancel := context.WithTimeout(ctx, limits.TotalTimeout)
	defer cancel()

	started := b.Now()
	g := &Graph{
		SchemaVersion: SchemaVersion,
		SnapshotID:    snapshotID,
		Engine:        b.Engine,
		Frontends:     b.Registry.Info(),
		Modules:       []Module{},
		Files:         []File{},
		Symbols:       []Symbol{},
		CallSites:     []CallSite{},
		Edges:         []Edge{},
		Limitations:   []string{},
	}
	g.GraphVersion = GraphVersion(snapshotID, g.Engine, g.Frontends)

	// Structural limits apply to every P2 graph, so they are stated up front
	// rather than only when a budget happens to be reached.
	g.addLimitation("CALLS edges are static approximations: calls through function values, callbacks and framework-dispatched handlers are recorded as unresolved call sites, not as edges")
	g.addLimitation("FLOWS_TO and CONTROLS edges are not produced in P2; dataflow and control-flow analysis are later phases")

	disc, err := b.discover(snapshotID, treeDir, limits)
	if err != nil {
		return nil, err
	}
	g.Modules = disc.modules
	g.Coverage.FilesInSnapshot = disc.totalFiles
	g.Coverage.FilesTooLarge = disc.skippedLarge
	g.Coverage.FilesNotSource = disc.notSource
	if disc.skippedLarge > 0 {
		g.addLimitation("%d file(s) were skipped because they exceed the per-file size limit of %d bytes; their symbols and calls are absent", disc.skippedLarge, limits.MaxFileBytes)
	}
	if disc.notSource > 0 {
		g.addLimitation("%d file(s) are not source code (data formats and tooling descriptors); they are listed as graph nodes but contribute no symbols or calls", disc.notSource)
	}
	if len(disc.unsupported) > 0 {
		g.addLimitation("%d file(s) belong to languages without a registered frontend (%s); they are listed but contribute no symbols or calls",
			countUnsupported(disc.unsupported), strings.Join(sortedKeys(disc.unsupported), ", "))
	}

	notes := map[string]int{}
	units := make([]parsedFile, 0, len(disc.files))
	for _, tf := range disc.files {
		if len(g.Symbols) >= limits.MaxSymbols {
			g.Coverage.SymbolsSkipped++
			continue
		}
		if len(units) >= limits.MaxFiles {
			g.addLimitation("the file budget of %d was reached; later files were not parsed", limits.MaxFiles)
			break
		}
		pf := b.parseFile(ctx, snapshotID, tf, limits)
		for _, note := range pf.notes {
			notes[note]++
		}
		units = append(units, pf)
		g.Files = append(g.Files, pf.file)
		g.Symbols = append(g.Symbols, pf.symbols...)
		switch pf.file.ParseStatus {
		case ParseOK:
			g.Coverage.FilesParsed++
		case ParsePartial:
			g.Coverage.FilesParsed++
			g.Coverage.FilesPartial++
		case ParseUnparsed:
			g.Coverage.FilesUnparsed++
		case ParseUnsupported:
			g.Coverage.FilesUnsupported++
		case ParseNotSource:
			// counted in discovery; not a coverage gap
		}
	}

	for _, note := range sortedKeys(notes) {
		g.addLimitation("%d file(s) report the same coverage note: %s", notes[note], note)
	}

	index := buildIndex(units)
	edges := newEdgeSet(limits.MaxEdges)
	b.addContainmentEdges(g, units, edges)
	b.resolveCalls(ctx, g, units, index, edges, limits)
	b.addImportEdges(g, units, disc, edges)

	g.Edges = edges.list()
	b.finalizeModules(disc, units)
	g.finalizeCoverage(limits)
	if g.Coverage.SymbolsSkipped > 0 {
		g.addLimitation("%d file(s) were not parsed because the symbol budget of %d was reached", g.Coverage.SymbolsSkipped, limits.MaxSymbols)
	}
	if g.Coverage.CallSitesSkipped > 0 {
		g.addLimitation("%d call site(s) were not recorded because the budget of %d was reached", g.Coverage.CallSitesSkipped, limits.MaxCallSites)
	}
	if edges.dropped > 0 {
		g.addLimitation("%d edge(s) were not recorded because the edge budget of %d was reached", edges.dropped, limits.MaxEdges)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		g.addLimitation("the graph build hit its total time budget of %s and may be incomplete", limits.TotalTimeout)
	}
	g.sortForDeterminism()
	g.BuiltAt = started.Format(time.RFC3339)
	g.BuildDurationMS = b.Now().Sub(started).Milliseconds()
	return g, nil
}

func (b *Builder) applyDefaults() {
	if b.Registry == nil {
		b.Registry = NewRegistry()
	}
	if b.Engine.Name == "" {
		b.Engine = DefaultEngine
	}
	if b.Now == nil {
		b.Now = func() time.Time { return time.Now().UTC() }
	}
	if b.LanguageRules == nil {
		b.LanguageRules = analysis.DefaultLanguageRules()
	}
}

// parsedFile is one file of the snapshot plus the bookkeeping the later passes
// need.
type parsedFile struct {
	file     File
	unit     *FileUnit
	frontend Frontend
	module   Module
	pkgPath  string
	symbols  []Symbol
	// symbolByDecl maps a declaration index to the symbol it produced.
	symbolByDecl map[int]Symbol
	// notes are frontend coverage statements that apply to this file.
	notes []string
}

// parseFile runs the matching frontend over one file.
func (b *Builder) parseFile(ctx context.Context, snapshotID string, tf treeFile, limits BuildLimits) parsedFile {
	pf := parsedFile{
		module:       tf.module,
		pkgPath:      tf.pkgPath,
		symbolByDecl: map[int]Symbol{},
		file: File{
			ID:         tf.fileID,
			SnapshotID: snapshotID,
			ModuleID:   tf.module.ID,
			Path:       tf.path,
			Language:   tf.language,
			Bytes:      tf.size,
			Lines:      tf.lines,
		},
	}
	unit := &FileUnit{Language: tf.language, Declarations: []Declaration{}, Imports: []Import{}, Calls: []CallRef{}, Status: ParseOK}
	if tf.frontend == nil {
		if isSourceLanguage(b.LanguageRules, tf.path, tf.language) {
			unit.Status = ParseUnsupported
			pf.file.ParseError = "no frontend is registered for this language"
		} else {
			unit.Status = ParseNotSource
		}
		pf.file.ParseStatus = unit.Status
		pf.unit = unit
		return pf
	}
	pf.frontend = tf.frontend

	parseCtx, cancel := context.WithTimeout(ctx, limits.PerFileTimeout)
	defer cancel()
	parsed, err := tf.frontend.Parse(parseCtx, FrontendFile{
		Path:        tf.path,
		Language:    tf.language,
		PackagePath: tf.pkgPath,
		ModulePath:  tf.module.Name,
		Content:     tf.content,
	})
	switch {
	case err != nil:
		unit.Status = ParseUnparsed
		unit.Error = err.Error()
	case parsed != nil:
		unit = parsed
		if unit.Status == "" {
			unit.Status = ParseOK
		}
	}
	pf.unit = unit
	pf.file.ParseStatus = unit.Status
	pf.file.ParseError = unit.Error
	pf.notes = append(pf.notes, unit.Notes...)

	for i, decl := range unit.Declarations {
		if decl.Name == "" {
			continue
		}
		sym := b.symbolFromDecl(snapshotID, tf, pf.pkgPath, decl)
		pf.symbols = append(pf.symbols, sym)
		pf.symbolByDecl[i] = sym
	}
	return pf
}

// symbolFromDecl turns a declaration into a symbol with a stable id.
func (b *Builder) symbolFromDecl(snapshotID string, tf treeFile, pkgPath string, decl Declaration) Symbol {
	qualified := qualifiedName(pkgPath, decl)
	loc := Location{File: tf.path, Line: decl.StartLine, Col: decl.StartCol}
	return Symbol{
		ID:            SymbolID(snapshotID, tf.language, tf.path, qualified, decl.Signature, loc),
		SnapshotID:    snapshotID,
		ModuleID:      tf.module.ID,
		FileID:        tf.fileID,
		File:          tf.path,
		Language:      tf.language,
		Kind:          decl.Kind,
		Name:          decl.Name,
		QualifiedName: qualified,
		Signature:     decl.Signature,
		Receiver:      decl.Receiver,
		ResultType:    decl.ResultType,
		Exported:      decl.Exported,
		StartLine:     decl.StartLine,
		EndLine:       decl.EndLine,
		StartCol:      decl.StartCol,
		EndCol:        decl.EndCol,
	}
}

// qualifiedName builds the language-level qualified name of a declaration:
// package, optional receiver type, then the name.
func qualifiedName(pkgPath string, decl Declaration) string {
	parts := make([]string, 0, 3)
	if pkgPath != "" {
		parts = append(parts, pkgPath)
	}
	if decl.Kind == KindMethod && decl.Receiver != "" {
		parts = append(parts, decl.Receiver)
	}
	parts = append(parts, decl.Name)
	return strings.Join(parts, ".")
}

// addContainmentEdges emits CONTAINS edges: module -> file, file -> symbol,
// file -> call site (added when the call site is resolved).
func (b *Builder) addContainmentEdges(g *Graph, units []parsedFile, edges *edgeSet) {
	for _, pf := range units {
		edges.add(Edge{
			SnapshotID:      g.SnapshotID,
			From:            pf.file.ModuleID,
			To:              pf.file.ID,
			Kind:            EdgeContains,
			Resolution:      Resolved,
			Confidence:      Observed,
			SourceLocation:  Location{File: pf.file.Path},
			Analyzer:        b.Engine.Name,
			AnalyzerVersion: b.Engine.Version,
		})
		for _, sym := range pf.symbols {
			edges.add(Edge{
				SnapshotID:      g.SnapshotID,
				From:            sym.FileID,
				To:              sym.ID,
				Kind:            EdgeContains,
				Resolution:      Resolved,
				Confidence:      Observed,
				SourceLocation:  Location{File: sym.File, Line: sym.StartLine, Col: sym.StartCol},
				Analyzer:        b.Engine.Name,
				AnalyzerVersion: b.Engine.Version,
			})
		}
	}
}

// resolveCalls resolves every call reference and records the resulting call
// sites and CALLS/REFERENCES edges.
func (b *Builder) resolveCalls(_ context.Context, g *Graph, units []parsedFile, index *symbolIndex, edges *edgeSet, limits BuildLimits) {
	for _, pf := range units {
		if pf.frontend == nil || pf.unit == nil || len(pf.unit.Calls) == 0 {
			continue
		}
		resolver, ok := pf.frontend.(Resolver)
		if !ok {
			g.addLimitation("frontend %s cannot resolve calls; its files contribute symbols but no CALLS edges", pf.frontend.Name())
			for _, call := range pf.unit.Calls {
				cs := b.baseCallSite(g.SnapshotID, pf, call)
				cs.Resolution = Unsupported
				cs.Confidence = Unresolved
				cs.Detail = "frontend does not implement call resolution"
				g.CallSites = append(g.CallSites, cs)
				g.Resolution.Add(cs.Resolution)
			}
			continue
		}
		for _, call := range pf.unit.Calls {
			if len(g.CallSites) >= limits.MaxCallSites {
				g.Coverage.CallSitesSkipped++
				continue
			}
			cs, target := b.resolveCall(g.SnapshotID, pf, call, resolver, index)
			g.CallSites = append(g.CallSites, cs)
			g.Resolution.Add(cs.Resolution)
			from := cs.CallerSymbolID
			if from == "" {
				from = pf.file.ID
			}
			edges.add(Edge{
				SnapshotID:      g.SnapshotID,
				From:            from,
				To:              cs.ID,
				Kind:            EdgeContains,
				Resolution:      Resolved,
				Confidence:      Observed,
				SourceLocation:  Location{File: cs.File, Line: cs.Line, Col: cs.Col},
				Analyzer:        b.Engine.Name,
				AnalyzerVersion: b.Engine.Version,
			})
			if target == nil {
				continue
			}
			kind := EdgeCalls
			if target.Kind == KindType || target.Kind == KindInterface {
				kind = EdgeReferences
			}
			confidence := Observed
			if cs.Resolution == ResolvedBestEffort {
				confidence = Inferred
			}
			edges.add(Edge{
				SnapshotID:      g.SnapshotID,
				From:            from,
				To:              target.ID,
				Kind:            kind,
				Resolution:      cs.Resolution,
				Confidence:      confidence,
				SourceLocation:  Location{File: cs.File, Line: cs.Line, Col: cs.Col},
				Analyzer:        b.Engine.Name,
				AnalyzerVersion: b.Engine.Version,
				CallSiteID:      cs.ID,
				Detail:          map[string]string{"callee_text": cs.CalleeText},
			})
		}
	}
}

// baseCallSite fills the position and provenance fields of a call site.
func (b *Builder) baseCallSite(snapshotID string, pf parsedFile, call CallRef) CallSite {
	cs := CallSite{
		ID:              CallSiteID(snapshotID, pf.file.Path, call.Line, call.Col, call.Text),
		SnapshotID:      snapshotID,
		FileID:          pf.file.ID,
		File:            pf.file.Path,
		Line:            call.Line,
		Col:             call.Col,
		CalleeText:      call.Text,
		Analyzer:        pf.frontend.Name(),
		AnalyzerVersion: pf.frontend.Version(),
	}
	if call.EnclosingDecl >= 0 {
		if sym, ok := pf.symbolByDecl[call.EnclosingDecl]; ok {
			cs.CallerSymbolID = sym.ID
		}
	}
	return cs
}

// resolveCall turns one call reference into a call site record and, when the
// target is known, the symbol it points at.
func (b *Builder) resolveCall(snapshotID string, pf parsedFile, call CallRef, resolver Resolver, index *symbolIndex) (CallSite, *SymbolRef) {
	cs := b.baseCallSite(snapshotID, pf, call)
	frontendFile := FrontendFile{
		Path:        pf.file.Path,
		Language:    pf.file.Language,
		PackagePath: pf.pkgPath,
		ModulePath:  pf.module.Name,
	}
	res := resolver.ResolveCall(call, frontendFile, pf.unit, index)
	cs.Resolution = res.Resolution
	cs.Confidence = res.Confidence
	cs.Detail = res.Detail
	cs.CalleeQualified = res.TargetQualified
	cs.CalleeSymbolID = res.TargetID
	if res.TargetID == "" {
		return cs, nil
	}
	ref, ok := index.byID[res.TargetID]
	if !ok {
		// A resolver must not invent symbols: an unknown target is downgraded to
		// unresolved rather than trusted.
		cs.Resolution = Unsupported
		cs.Confidence = Unresolved
		cs.CalleeSymbolID = ""
		cs.Detail = "resolver returned a symbol id that is not in the snapshot index"
		return cs, nil
	}
	return cs, &ref
}

// addImportEdges aggregates module-to-module IMPORTS edges.
func (b *Builder) addImportEdges(g *Graph, units []parsedFile, disc *discovery, edges *edgeSet) {
	type key struct{ from, to, imp string }
	tracked := map[key]Edge{}
	for _, pf := range units {
		if pf.unit == nil {
			continue
		}
		for _, imp := range pf.unit.Imports {
			target := disc.moduleForImport(imp.Path)
			if target == "" || target == pf.file.ModuleID {
				continue
			}
			k := key{pf.file.ModuleID, target, imp.Path}
			existing, ok := tracked[k]
			if !ok {
				edge := Edge{
					SnapshotID:      g.SnapshotID,
					From:            pf.file.ModuleID,
					To:              target,
					Kind:            EdgeImports,
					Resolution:      Resolved,
					Confidence:      Observed,
					SourceLocation:  Location{File: pf.file.Path, Line: imp.Line},
					Analyzer:        b.Engine.Name,
					AnalyzerVersion: b.Engine.Version,
					Detail:          map[string]string{"import_path": imp.Path, "count": "1"},
				}
				edges.add(edge)
				tracked[k] = edge
				continue
			}
			count := 1
			fmt.Sscanf(existing.Detail["count"], "%d", &count)
			existing.Detail["count"] = fmt.Sprintf("%d", count+1)
			edges.replace(existing)
			tracked[k] = existing
		}
	}
}

// finalizeModules fills the aggregate counters of each module.
func (b *Builder) finalizeModules(disc *discovery, units []parsedFile) {
	byID := map[string]*Module{}
	for i := range disc.modules {
		byID[disc.modules[i].ID] = &disc.modules[i]
	}
	langByModule := map[string]map[string]int{}
	for _, tf := range disc.files {
		if mod := byID[tf.module.ID]; mod != nil {
			mod.Files++
			mod.Lines += tf.lines
		}
		if tf.language != "" {
			if langByModule[tf.module.ID] == nil {
				langByModule[tf.module.ID] = map[string]int{}
			}
			langByModule[tf.module.ID][tf.language]++
		}
	}
	for _, pf := range units {
		if mod := byID[pf.file.ModuleID]; mod != nil {
			mod.Symbols += len(pf.symbols)
		}
	}
	for id, counts := range langByModule {
		if mod := byID[id]; mod != nil {
			mod.Language = dominantLanguage(counts)
		}
	}
}

// finalizeCoverage states the resolution outcome of the whole build.
func (g *Graph) finalizeCoverage(_ BuildLimits) {
	res := g.Resolution
	total := res.Total()
	if total > 0 {
		g.addLimitation("%d of %d call site(s) are unresolved (%d external, %d dynamic, %d ambiguous, %d builtin, %d unsupported); paths that cross an unresolved call are not represented in the graph",
			total-res.Resolved-res.ResolvedBestEffort, total, res.External, res.Dynamic, res.Ambiguous, res.Builtin, res.Unsupported)
	}
	if res.ResolvedBestEffort > 0 {
		g.addLimitation("%d call edge(s) were resolved by inference (local type assignment) and may point at the wrong method set", res.ResolvedBestEffort)
	}
	if g.Coverage.FilesPartial > 0 || g.Coverage.FilesUnparsed > 0 {
		g.addLimitation("%d file(s) parsed partially and %d file(s) could not be parsed; their symbols and calls are incomplete", g.Coverage.FilesPartial, g.Coverage.FilesUnparsed)
	}
}

// --- discovery --------------------------------------------------------------

// treeFile is one file found in the frozen tree, already attributed to a module
// and (when possible) to a frontend.
type treeFile struct {
	path string
	// dir is repository-relative; relDir is relative to the module root, which is
	// what a package path is built from.
	dir      string
	relDir   string
	base     string
	size     int64
	lines    int
	content  []byte
	language string
	pkgPath  string
	fileID   string
	module   Module
	frontend Frontend
}

// discovery is the result of walking a tree and grouping files into modules.
type discovery struct {
	files          []treeFile
	modules        []Module
	totalFiles     int
	skippedLarge   int
	notSource      int
	unsupported    map[string]int
	moduleByImport map[string]string
	moduleByName   map[string]string
}

// moduleForImport maps an import path to the module that contains it. The
// longest matching module name wins, so nested modules resolve correctly.
func (d *discovery) moduleForImport(importPath string) string {
	if importPath == "" {
		return ""
	}
	if id, ok := d.moduleByName[importPath]; ok {
		return id
	}
	best := ""
	bestLen := -1
	for name, id := range d.moduleByName {
		if name == "" || !strings.HasPrefix(importPath, name+"/") {
			continue
		}
		if len(name) > bestLen {
			best, bestLen = id, len(name)
		}
	}
	return best
}

// discover walks the tree, finds module roots and attributes every file.
func (b *Builder) discover(snapshotID, treeDir string, limits BuildLimits) (*discovery, error) {
	d := &discovery{
		unsupported:    map[string]int{},
		moduleByImport: map[string]string{},
		moduleByName:   map[string]string{},
	}
	type entry struct {
		path string
		size int64
	}
	var entries []entry
	err := filepath.WalkDir(treeDir, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			if de.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if !de.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(treeDir, p)
		if rerr != nil {
			return rerr
		}
		info, ierr := de.Info()
		if ierr != nil {
			return ierr
		}
		entries = append(entries, entry{path: filepath.ToSlash(rel), size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	d.totalFiles = len(entries)

	// The repository root is always a module, so a repository without any
	// manifest still produces a usable module-level graph.
	rootDirs := map[string]string{".": ""}
	for _, e := range entries {
		if !isModuleManifest(path.Base(e.path)) {
			continue
		}
		dir := path.Dir(e.path)
		if dir == "" {
			dir = "."
		}
		rootDirs[dir] = e.path
	}
	dirs := make([]string, 0, len(rootDirs))
	for dir := range rootDirs {
		dirs = append(dirs, dir)
	}
	sort.Slice(dirs, func(i, j int) bool {
		if len(dirs[i]) != len(dirs[j]) {
			return len(dirs[i]) < len(dirs[j]) // shallower first
		}
		return dirs[i] < dirs[j]
	})

	byDir := map[string]Module{}
	for _, dir := range dirs {
		manifest := rootDirs[dir]
		name := ""
		if manifest != "" {
			if content, rerr := readBounded(filepath.Join(treeDir, filepath.FromSlash(manifest)), limits.MaxManifestBytes); rerr == nil {
				name = moduleNameFromManifest(manifest, content)
			}
		}
		mod := Module{
			ID:           ModuleID(snapshotID, dir),
			SnapshotID:   snapshotID,
			Path:         dir,
			Name:         name,
			ManifestFile: manifest,
		}
		byDir[dir] = mod
		d.modules = append(d.modules, mod)
		if name != "" {
			d.moduleByName[name] = mod.ID
		}
	}

	for _, e := range entries {
		dir := path.Dir(e.path)
		if dir == "" {
			dir = "."
		}
		modDir := "."
		for _, candidate := range dirs {
			if candidate == "." {
				continue
			}
			if dir == candidate || strings.HasPrefix(dir, candidate+"/") {
				if len(candidate) > len(modDir) {
					modDir = candidate
				}
			}
		}
		mod := byDir[modDir]
		relDir := dir
		if modDir != "." {
			relDir = strings.TrimPrefix(strings.TrimPrefix(dir, modDir), "/")
			if relDir == "" {
				relDir = "."
			}
		}
		tf := treeFile{
			path:   e.path,
			dir:    dir,
			relDir: relDir,
			base:   path.Base(e.path),
			size:   e.size,
			module: mod,
			fileID: FileID(snapshotID, e.path),
		}
		if e.size > limits.MaxFileBytes {
			d.skippedLarge++
			continue
		}
		tf.language = b.languageOf(e.path)
		tf.content, _ = readBounded(filepath.Join(treeDir, filepath.FromSlash(e.path)), limits.MaxFileBytes)
		tf.lines = linesOf(tf.content)
		tf.frontend, _ = b.Registry.For(tf.language)
		tf.pkgPath = packagePath(tf.frontend, mod, relDir)
		if tf.frontend == nil {
			if isSourceLanguage(b.LanguageRules, e.path, tf.language) {
				d.unsupported[languageLabel(tf.language)]++
			} else {
				d.notSource++
			}
		}
		d.files = append(d.files, tf)
	}
	sort.Slice(d.files, func(i, j int) bool { return d.files[i].path < d.files[j].path })
	return d, nil
}

// packagePath asks the frontend how to name the file's package, falling back to
// the module-local directory path.
func packagePath(f Frontend, mod Module, dir string) string {
	if f != nil {
		if p, ok := f.(Packager); ok {
			if pp := p.PackagePath(mod, dir); pp != "" {
				return pp
			}
		}
	}
	if dir == "." {
		return mod.Name
	}
	if mod.Name == "" {
		return dir
	}
	return mod.Name + "/" + dir
}

// languageOf attributes a file to a language using the analyzer's table.
func (b *Builder) languageOf(file string) string {
	rules := b.LanguageRules
	if rules == nil {
		rules = analysis.DefaultLanguageRules()
	}
	base := path.Base(file)
	if lang, ok := rules.Source[base]; ok {
		return lang
	}
	if lang, ok := rules.Source[strings.ToLower(path.Ext(base))]; ok {
		return lang
	}
	return ""
}

// isSourceLanguage reports whether a file is source code in a language the
// rules understand (even when no frontend handles it) rather than a data format
// or a tooling descriptor.
func isSourceLanguage(rules *analysis.LanguageRules, file, language string) bool {
	if language != "" {
		return true
	}
	if rules == nil {
		return false
	}
	base := path.Base(file)
	if rules.Source[base] != "" {
		return true
	}
	if rules.Source[strings.ToLower(path.Ext(base))] != "" {
		return true
	}
	return false
}

func languageLabel(language string) string {
	if language == "" {
		return "unrecognised"
	}
	return language
}

func countUnsupported(m map[string]int) int {
	total := 0
	for _, n := range m {
		total += n
	}
	return total
}

// readBounded reads at most maxBytes of a file.
func readBounded(p string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

func linesOf(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	return strings.Count(string(content), "\n") + 1
}

func isModuleManifest(base string) bool {
	for _, b := range moduleManifestBases {
		if base == b {
			return true
		}
	}
	return strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".sln")
}

// moduleNameFromManifest extracts the declared module name when the manifest
// format can be read cheaply. Unknown formats return an empty name, which the
// graph reports rather than guesses.
func moduleNameFromManifest(manifest string, content []byte) string {
	switch path.Base(manifest) {
	case "go.mod":
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "module ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "module "))
			}
		}
	case "package.json", "composer.json":
		var doc struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(content, &doc); err == nil {
			return doc.Name
		}
	case "Cargo.toml":
		if name := tomlSectionValue(content, "package", "name"); name != "" {
			return name
		}
	case "pyproject.toml":
		if name := tomlSectionValue(content, "project", "name"); name != "" {
			return name
		}
	}
	return ""
}

// tomlSectionValue reads a simple `key = "value"` line inside a TOML section.
func tomlSectionValue(content []byte, section, key string) string {
	current := ""
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			current = strings.Trim(line, "[]")
			continue
		}
		if current != section {
			continue
		}
		if !strings.HasPrefix(line, key) {
			continue
		}
		if _, value, ok := strings.Cut(line, "="); ok {
			return strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return ""
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dominantLanguage(counts map[string]int) string {
	best := ""
	bestCount := -1
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if counts[name] > bestCount {
			best, bestCount = name, counts[name]
		}
	}
	return best
}
