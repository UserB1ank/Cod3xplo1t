// Package gofrontend implements the first SCG language frontend: Go, parsed
// with the standard library's own AST (go/parser).
//
// The frontend is deliberately honest about what an AST-only analysis can know.
// It resolves calls that are decidable from syntax and the snapshot's symbol
// table, and it marks everything else — interface dispatch, function values,
// reflection, packages outside the snapshot — as unresolved instead of guessing.
// Nothing is type-checked: no build, no dependency download, no code execution.
package gofrontend

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// Language is the language name this frontend handles.
const Language = "Go"

//go:embed frontend.go
var implementationSource []byte

// ImplementationDigest identifies the source compiled into the builtin bundle.
func ImplementationDigest() string { return fmt.Sprintf("%x", sha256.Sum256(implementationSource)) }

// Frontend is the Go frontend.
type Frontend struct{}

// New returns the Go frontend.
func New() *Frontend { return &Frontend{} }

// Name implements scg.Frontend.
func (*Frontend) Name() string { return "golang/ast" }

// Version implements scg.Frontend. Bump it whenever resolution changes.
func (*Frontend) Version() string { return "1" }

// Languages implements scg.Frontend.
func (*Frontend) Languages() []string { return []string{Language} }

// PackagePath implements scg.Packager: the Go import path of a file's directory.
func (*Frontend) PackagePath(module scg.Module, dir string) string {
	base := module.Name
	if base == "" {
		// Without a go.mod there is no import path to speak of. The directory
		// path still groups symbols deterministically, and call resolution is
		// limited to the package itself.
		if dir == "." || dir == "" {
			return ""
		}
		return strings.TrimPrefix(path.Clean(dir), "./")
	}
	if dir == "." || dir == "" {
		return base
	}
	return base + "/" + strings.TrimPrefix(path.Clean(dir), "./")
}

// goBuiltins are the Go predeclared functions. They are not symbols of the
// snapshot, so calls to them are recorded as builtin rather than unresolved.
var goBuiltins = map[string]bool{
	"append": true, "cap": true, "clear": true, "close": true, "complex": true,
	"copy": true, "delete": true, "imag": true, "len": true, "make": true,
	"max": true, "min": true, "new": true, "panic": true, "print": true,
	"println": true, "real": true, "recover": true,
}

// Parse implements scg.Frontend.
func (f *Frontend) Parse(_ context.Context, file scg.FrontendFile) (*scg.FileUnit, error) {
	unit := &scg.FileUnit{
		Language:     Language,
		Declarations: []scg.Declaration{},
		Imports:      []scg.Import{},
		Calls:        []scg.CallRef{},
		Status:       scg.ParseOK,
	}
	if file.ModulePath == "" {
		unit.Notes = append(unit.Notes,
			"no module path is known for this file (no go.mod module directive), so cross-package call resolution is limited to this package")
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file.Path, file.Content, parser.SkipObjectResolution)
	if err != nil {
		unit.Status = scg.ParsePartial
		unit.Error = err.Error()
		if parsed == nil {
			unit.Status = scg.ParseUnparsed
			return unit, nil
		}
	}
	if parsed.Name != nil {
		unit.PackageName = parsed.Name.Name
	}
	for _, imp := range parsed.Imports {
		entry := scg.Import{Path: strings.Trim(imp.Path.Value, `"`), Line: lineOf(fset, imp.Pos())}
		if imp.Name != nil {
			entry.Alias = imp.Name.Name
		}
		unit.Imports = append(unit.Imports, entry)
	}
	w := &walker{fset: fset, unit: unit, file: file}
	for _, decl := range parsed.Decls {
		w.decl(decl)
	}
	return unit, nil
}

// walker collects declarations and calls, tracking the local type bindings that
// make receiver resolution possible.
type walker struct {
	fset *token.FileSet
	unit *scg.FileUnit
	file scg.FrontendFile
	// declIdx is the index of the declaration currently being walked, or -1.
	declIdx int
	// bindings maps local identifiers to a named type, with the evidence class of
	// that knowledge.
	bindings map[string]binding
}

// binding is a local identifier's type, and whether it was observed or inferred.
// When the type could not be named from syntax, fromCall remembers the call the
// value came from, so the resolver can look up that function's result type.
type binding struct {
	typeName string
	observed bool
	fromCall []string
}

func (w *walker) decl(decl ast.Decl) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		w.funcDecl(d)
	case *ast.GenDecl:
		w.genDecl(d)
	}
}

func (w *walker) funcDecl(d *ast.FuncDecl) {
	kind := scg.KindFunction
	receiver := ""
	if d.Recv != nil && len(d.Recv.List) > 0 {
		kind = scg.KindMethod
		receiver = namedTypeName(d.Recv.List[0].Type)
	}
	start := w.fset.Position(d.Pos())
	end := w.fset.Position(d.End())
	decl := scg.Declaration{
		Kind:        kind,
		Name:        d.Name.Name,
		Receiver:    receiver,
		Signature:   signatureOf(d.Type),
		ResultType:  resultTypeName(d.Type),
		Exported:    d.Name.IsExported(),
		StartLine:   start.Line,
		EndLine:     end.Line,
		StartCol:    start.Column,
		EndCol:      end.Column,
		PackageName: w.unit.PackageName,
	}
	index := len(w.unit.Declarations)
	w.unit.Declarations = append(w.unit.Declarations, decl)

	savedIdx, savedBindings := w.declIdx, w.bindings
	w.declIdx = index
	w.bindings = map[string]binding{}
	if d.Recv != nil {
		for _, field := range d.Recv.List {
			w.bindField(field, true)
		}
	}
	w.bindFieldList(d.Type.Params, true)
	w.bindFieldList(d.Type.Results, true)
	if d.Body != nil {
		ast.Inspect(d.Body, w.node)
	}
	w.declIdx, w.bindings = savedIdx, savedBindings
}

func (w *walker) genDecl(d *ast.GenDecl) {
	for _, spec := range d.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			kind := scg.KindType
			if _, ok := s.Type.(*ast.InterfaceType); ok {
				kind = scg.KindInterface
			}
			start := w.fset.Position(s.Pos())
			end := w.fset.Position(s.End())
			w.unit.Declarations = append(w.unit.Declarations, scg.Declaration{
				Kind:        kind,
				Name:        s.Name.Name,
				Signature:   kindSignature(s),
				Exported:    s.Name.IsExported(),
				StartLine:   start.Line,
				EndLine:     end.Line,
				StartCol:    start.Column,
				EndCol:      end.Column,
				PackageName: w.unit.PackageName,
			})
		case *ast.ValueSpec:
			kind := scg.KindVar
			if d.Tok == token.CONST {
				kind = scg.KindConst
			}
			for _, name := range s.Names {
				start := w.fset.Position(name.Pos())
				end := w.fset.Position(name.End())
				sig := ""
				if s.Type != nil {
					sig = types.ExprString(s.Type)
				}
				w.unit.Declarations = append(w.unit.Declarations, scg.Declaration{
					Kind:        kind,
					Name:        name.Name,
					Signature:   sig,
					Exported:    name.IsExported(),
					StartLine:   start.Line,
					EndLine:     end.Line,
					StartCol:    start.Column,
					EndCol:      end.Column,
					PackageName: w.unit.PackageName,
				})
				// Package-level initialisers can call functions; those calls are
				// attributed to the variable they initialise.
				if len(s.Values) > 0 {
					savedIdx, savedBindings := w.declIdx, w.bindings
					w.declIdx = len(w.unit.Declarations) - 1
					if s.Type != nil {
						w.bindings = map[string]binding{name.Name: {typeName: namedTypeName(s.Type), observed: true}}
					} else {
						w.bindings = map[string]binding{}
					}
					for _, value := range s.Values {
						ast.Inspect(value, w.node)
					}
					w.declIdx, w.bindings = savedIdx, savedBindings
				}
			}
		}
	}
}

// bindFieldList binds the names of a parameter or result list.
func (w *walker) bindFieldList(fields *ast.FieldList, observed bool) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		w.bindField(field, observed)
	}
}

// bindField records the declared type of a field's names.
func (w *walker) bindField(field *ast.Field, observed bool) {
	typeName := namedTypeName(field.Type)
	for _, name := range field.Names {
		if name.Name == "" || name.Name == "_" {
			continue
		}
		if typeName == "" {
			delete(w.bindings, name.Name)
			continue
		}
		w.bindings[name.Name] = binding{typeName: typeName, observed: observed}
	}
}

// node walks statements and expressions, collecting calls and the local type
// bindings that later receiver resolution depends on.
func (w *walker) node(n ast.Node) bool {
	switch stmt := n.(type) {
	case *ast.AssignStmt:
		w.assign(stmt)
	case *ast.DeclStmt:
		if gen, ok := stmt.Decl.(*ast.GenDecl); ok {
			for _, spec := range gen.Specs {
				if value, ok := spec.(*ast.ValueSpec); ok {
					w.bindValueSpec(value, gen.Tok == token.CONST)
				}
			}
		}
	case *ast.RangeStmt:
		// A range value's type is not inferred: leaving it unknown keeps the
		// resolver from guessing a receiver type.
		if stmt.Key != nil {
			if ident, ok := stmt.Key.(*ast.Ident); ok {
				delete(w.bindings, ident.Name)
			}
		}
		if stmt.Value != nil {
			if ident, ok := stmt.Value.(*ast.Ident); ok {
				delete(w.bindings, ident.Name)
			}
		}
	case *ast.CallExpr:
		w.call(stmt)
	}
	return true
}

// bindValueSpec handles `var x T` and `var x = expr` inside a function body.
func (w *walker) bindValueSpec(spec *ast.ValueSpec, isConst bool) {
	for i, name := range spec.Names {
		if name.Name == "" || name.Name == "_" {
			continue
		}
		if spec.Type != nil {
			if typeName := namedTypeName(spec.Type); typeName != "" {
				w.bindings[name.Name] = binding{typeName: typeName, observed: true}
				continue
			}
		}
		if i < len(spec.Values) {
			if typeName, ok := inferredTypeName(spec.Values[i]); ok {
				w.bindings[name.Name] = binding{typeName: typeName, observed: false}
				continue
			}
		}
		delete(w.bindings, name.Name)
	}
}

// assign handles `:=` definitions, which are the main source of inferred
// receiver types.
func (w *walker) assign(stmt *ast.AssignStmt) {
	if stmt.Tok != token.DEFINE {
		return
	}
	for i, lhs := range stmt.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		if i >= len(stmt.Rhs) {
			delete(w.bindings, ident.Name)
			continue
		}
		if typeName, ok := inferredTypeName(stmt.Rhs[i]); ok {
			w.bindings[ident.Name] = binding{typeName: typeName, observed: false}
			continue
		}
		if parts, ok := callTargetParts(stmt.Rhs[i]); ok {
			w.bindings[ident.Name] = binding{fromCall: parts}
			continue
		}
		delete(w.bindings, ident.Name)
	}
}

// call records one call expression.
// maxArgFacts bounds how many arguments of one call are described. Beyond that
// the call is still recorded; only the per-argument detail stops, so a generated
// call with hundreds of arguments cannot inflate the graph.
const maxArgFacts = 8

// maxArgText bounds the source text kept for one argument.
const maxArgText = 120

func (w *walker) call(call *ast.CallExpr) {
	fun := unwrap(call.Fun)
	ref := scg.CallRef{
		EnclosingDecl: w.declIdx,
		Line:          lineOf(w.fset, call.Lparen),
		Col:           colOf(w.fset, call.Lparen),
		Form:          scg.FormIdent,
		Args:          len(call.Args),
	}
	ref.ArgExprs = w.argExprs(call.Args)
	if ref.Line == 0 {
		ref.Line = lineOf(w.fset, call.Pos())
		ref.Col = colOf(w.fset, call.Pos())
	}
	switch f := fun.(type) {
	case *ast.Ident:
		ref.Parts = []string{f.Name}
		ref.Text = f.Name
	case *ast.SelectorExpr:
		base, ok := unwrap(f.X).(*ast.Ident)
		if !ok {
			ref.Form = scg.FormSelector
			ref.Text = types.ExprString(fun)
			ref.Parts = []string{types.ExprString(f.X), f.Sel.Name}
			ref.Hint = "selector_base_not_identifier"
			// A chained call (pkg.New().Method()) has the same receiver question
			// as `x := pkg.New(); x.Method()`: the inner call's declared result
			// type answers it.
			if parts, ok := callTargetParts(f.X); ok {
				ref.InferTargetParts = parts
				ref.Hint = "receiver_from_chained_call"
			}
			break
		}
		ref.Form = scg.FormSelector
		ref.Parts = []string{base.Name, f.Sel.Name}
		ref.Text = base.Name + "." + f.Sel.Name
		if bound, ok := w.bindings[base.Name]; ok {
			switch {
			case bound.typeName != "":
				ref.ReceiverType = bound.typeName
				if bound.observed {
					ref.Hint = scg.HintReceiverParameter
				} else {
					ref.Hint = scg.HintReceiverInferred
				}
			case len(bound.fromCall) > 0:
				ref.InferTargetParts = bound.fromCall
			}
			// The binding is also the receiver's provenance, which is what
			// attributes `r.GET(...)` to the constructor that made r.
			ref.ReceiverFrom = bound.fromCall
		}
	case *ast.FuncLit:
		ref.Form = scg.FormFuncLiteral
		ref.Text = "func literal"
		ref.Parts = []string{}
	default:
		// A parenthesised type, a generic instantiation or an expression whose
		// callee is itself a call: record it with its printed form so the call is
		// not lost.
		text := types.ExprString(fun)
		ref.Text = text
		ref.Parts = []string{text}
		if text == "" {
			return
		}
	}
	if call.Ellipsis.IsValid() {
		ref.Hint = strings.TrimSpace(ref.Hint + " variadic")
	}
	w.unit.Calls = append(w.unit.Calls, ref)
}

// argExprs describes the arguments of a call as far as syntax allows: string
// literals with their unquoted value (route paths, SQL prefixes, file paths),
// other literals with their source form, and identifiers/selectors that may name
// a symbol (handlers, sinks, controls).
func (w *walker) argExprs(args []ast.Expr) []scg.ArgExpr {
	out := make([]scg.ArgExpr, 0, len(args))
	for i, arg := range args {
		if i >= maxArgFacts {
			break
		}
		expr := unwrap(arg)
		entry := scg.ArgExpr{Position: i, Kind: scg.ArgExpression}
		switch e := expr.(type) {
		case *ast.BasicLit:
			entry.Text = truncateText(e.Value)
			if e.Kind == token.STRING {
				entry.Kind = scg.ArgStringLiteral
				if value, err := strconv.Unquote(e.Value); err == nil {
					entry.StringValue = value
					entry.Text = truncateText(value)
				}
				break
			}
			entry.Kind = scg.ArgLiteral
		case *ast.Ident:
			entry.Kind = scg.ArgSymbolRef
			entry.Text = e.Name
			entry.Parts = []string{e.Name}
			entry.Form = scg.FormIdent
		case *ast.SelectorExpr:
			entry.Kind = scg.ArgSymbolRef
			entry.Text = truncateText(types.ExprString(expr))
			entry.Form = scg.FormSelector
			if base, ok := unwrap(e.X).(*ast.Ident); ok {
				entry.Parts = []string{base.Name, e.Sel.Name}
				if bound, ok := w.bindings[base.Name]; ok {
					switch {
					case bound.typeName != "":
						entry.ReceiverType = bound.typeName
						entry.Hint = scg.HintReceiverParameter
					case len(bound.fromCall) > 0:
						entry.InferTargetParts = bound.fromCall
					}
				}
			} else {
				entry.Kind = scg.ArgExpression
			}
		default:
			entry.Text = truncateText(types.ExprString(expr))
			if entry.Text == "" {
				entry.Kind = scg.ArgExpression
			}
		}
		out = append(out, entry)
	}
	return out
}

// truncateText bounds the source text kept for an argument.
func truncateText(text string) string {
	if len(text) <= maxArgText {
		return text
	}
	return text[:maxArgText]
}

// unwrap removes the wrappers that do not change what is being called:
// parentheses and generic type arguments.
func unwrap(expr ast.Expr) ast.Expr {
	for {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		default:
			return expr
		}
	}
}

// ResolveCall implements scg.Resolver.
func (f *Frontend) ResolveCall(call scg.CallRef, file scg.FrontendFile, unit *scg.FileUnit, idx scg.SymbolIndex) scg.CallResolution {
	if call.Form == scg.FormFuncLiteral {
		return scg.CallResolution{
			Resolution: scg.Dynamic,
			Confidence: scg.Unresolved,
			Detail:     "immediately invoked function literal",
		}
	}
	if len(call.Parts) == 0 {
		return scg.CallResolution{
			Resolution: scg.Unsupported,
			Confidence: scg.Unresolved,
			Detail:     "call shape not understood by the Go frontend",
		}
	}
	name := call.Parts[len(call.Parts)-1]

	if len(call.Parts) == 1 {
		if goBuiltins[name] {
			return scg.CallResolution{Resolution: scg.Builtin, Confidence: scg.Observed, TargetQualified: "builtin:" + name, Detail: "predeclared Go function"}
		}
		return f.resolveIdent(name, file, unit, idx, call)
	}

	base := call.Parts[0]
	qualified := base + "." + name

	// 1. A selector whose receiver type is known: a method call on a local type.
	if call.ReceiverType != "" {
		conf := scg.Observed
		if call.Hint == scg.HintReceiverInferred {
			conf = scg.Inferred
		}
		ref, outcome := idx.LookupMethod(file.PackagePath, call.ReceiverType, name)
		switch outcome {
		case scg.LookupFound:
			return resolved(ref, conf, "method on "+call.ReceiverType)
		case scg.LookupAmbiguous:
			return ambiguous(file.PackagePath+"."+call.ReceiverType+"."+name, "several methods share this name")
		}
		qualifiedReceiver := qualify(file.PackagePath, call.ReceiverType)
		if tref, toutcome := idx.LookupPackageSymbol(file.PackagePath, call.ReceiverType); toutcome == scg.LookupFound && tref.Kind == scg.KindInterface {
			return scg.CallResolution{
				Resolution: scg.Dynamic, Confidence: scg.Unresolved,
				TargetQualified: qualifiedReceiver + "." + name,
				Detail:          "interface dispatch on " + call.ReceiverType + ": the implementation is chosen at run time",
			}
		}
		// The receiver's type is known but the method is not: either the type is
		// declared outside the snapshot (its method set is unknowable here) or the
		// receiver type was inferred wrongly. Both are unresolved, and the detail
		// says which one it looks like.
		if tref, toutcome := idx.LookupPackageSymbol(file.PackagePath, call.ReceiverType); toutcome != scg.LookupFound || (tref.Kind != scg.KindType && tref.Kind != scg.KindInterface) {
			return scg.CallResolution{
				Resolution: scg.Dynamic, Confidence: conf, TargetQualified: qualifiedReceiver + "." + name,
				Detail: "receiver type " + call.ReceiverType + " is not declared in this snapshot; the method set of an external type is unknown here",
			}
		}
		return scg.CallResolution{
			Resolution: scg.Dynamic, Confidence: conf, TargetQualified: qualifiedReceiver + "." + name,
			Detail: "no method " + name + " on the snapshot type " + call.ReceiverType,
		}
	}

	// 2. The receiver was assigned from a call: use that function's declared
	// result type. This is inference, so the resulting edge is best effort.
	if len(call.InferTargetParts) > 0 {
		if ref, outcome := lookupCallTarget(call.InferTargetParts, file, unit, idx); outcome == scg.LookupFound && ref.ResultType != "" {
			if mref, moutcome := idx.LookupMethod(ref.PackagePath, ref.ResultType, name); moutcome == scg.LookupFound {
				return resolved(mref, scg.Inferred,
					"method on "+ref.PackagePath+"."+ref.ResultType+" returned by "+strings.Join(call.InferTargetParts, "."))
			}
		}
	}

	// 3. A method expression on a type of this package: T.Method(...).
	if ref, outcome := idx.LookupPackageSymbol(file.PackagePath, base); outcome == scg.LookupFound && (ref.Kind == scg.KindType || ref.Kind == scg.KindInterface) {
		mref, moutcome := idx.LookupMethod(file.PackagePath, base, name)
		switch moutcome {
		case scg.LookupFound:
			return resolved(mref, scg.Observed, "method expression on "+base)
		case scg.LookupAmbiguous:
			return ambiguous(file.PackagePath+"."+base+"."+name, "several methods share this name")
		}
	}

	// 3. A package selector: pkg.Function(...).
	if importPath, outcome := importPathFor(base, file, unit, idx); outcome != scg.LookupNotFound {
		if outcome == scg.LookupAmbiguous {
			return ambiguous(qualified, "several packages match this name; the import list does not disambiguate")
		}
		ref, lookup := idx.LookupPackageSymbol(importPath, name)
		switch lookup {
		case scg.LookupFound:
			conf := scg.Observed
			if call.Hint == "package_by_name" {
				// Matched by base name instead of an explicit import: this is a
				// heuristic, so the edge is best effort.
				conf = scg.Inferred
			}
			if callThroughValue(ref) {
				return scg.CallResolution{
					Resolution: scg.Dynamic, Confidence: scg.Unresolved, TargetQualified: ref.QualifiedName,
					Detail: "call through a package-level variable of function type; the target is assigned at run time",
				}
			}
			return resolved(ref, conf, "package "+importPath)
		case scg.LookupAmbiguous:
			return ambiguous(importPath+"."+name, "several symbols share this name")
		}
		if idx.PackageExists(importPath) {
			return scg.CallResolution{
				Resolution: scg.Unsupported, Confidence: scg.Unresolved, TargetQualified: importPath + "." + name,
				Detail: "package is in the snapshot but the symbol was not indexed (unexported, build-tagged or unparsed file)",
			}
		}
		return scg.CallResolution{
			Resolution: scg.External, Confidence: scg.Unresolved, TargetQualified: importPath + "." + name,
			Detail: "package is outside the snapshot",
		}
	}

	// 4. An interface value, a field of unknown type or a shadowed identifier.
	return scg.CallResolution{
		Resolution: scg.Dynamic, Confidence: scg.Unresolved, TargetQualified: qualified,
		Detail: "receiver type is unknown (interface value, field or shadowed identifier)",
	}
}

// resolveIdent resolves a bare identifier call: a package-level declaration, a
// dot-imported symbol, a type conversion or a local function value.
func (f *Frontend) resolveIdent(name string, file scg.FrontendFile, unit *scg.FileUnit, idx scg.SymbolIndex, call scg.CallRef) scg.CallResolution {
	ref, outcome := idx.LookupPackageSymbol(file.PackagePath, name)
	switch outcome {
	case scg.LookupFound:
		if callThroughValue(ref) {
			return scg.CallResolution{
				Resolution: scg.Dynamic, Confidence: scg.Unresolved, TargetQualified: ref.QualifiedName,
				Detail: "call through a package-level variable of function type; the target is assigned at run time",
			}
		}
		return resolved(ref, scg.Observed, "package-level declaration")
	case scg.LookupAmbiguous:
		return ambiguous(file.PackagePath+"."+name, "several declarations share this name")
	}
	// Dot imports place another package's identifiers in this file's scope.
	var dotPackages []string
	for _, imp := range unit.Imports {
		if imp.Alias != "." {
			continue
		}
		dotPackages = append(dotPackages, imp.Path)
	}
	sort.Strings(dotPackages)
	for _, pkg := range dotPackages {
		if ref, out := idx.LookupPackageSymbol(pkg, name); out == scg.LookupFound {
			return resolved(ref, scg.Inferred, "dot-imported from "+pkg)
		}
	}
	if strings.Contains(call.Hint, scg.HintTypeConversion) {
		return scg.CallResolution{
			Resolution: scg.Unsupported, Confidence: scg.Unresolved,
			Detail: "conversion-shaped call whose type is not in the snapshot index",
		}
	}
	return scg.CallResolution{
		Resolution: scg.Dynamic, Confidence: scg.Unresolved, TargetQualified: name,
		Detail: "identifier is not a package-level declaration (local function value, parameter, or a file that failed to parse)",
	}
}

// importPathFor maps a selector base name to an import path.
func importPathFor(base string, file scg.FrontendFile, unit *scg.FileUnit, idx scg.SymbolIndex) (string, scg.LookupOutcome) {
	// An explicit alias wins.
	for _, imp := range unit.Imports {
		if imp.Alias == base && imp.Alias != "." && imp.Alias != "_" {
			return imp.Path, scg.LookupFound
		}
	}
	// Then an unaliased import whose path base matches. The import statement is
	// direct evidence of the path whether or not the package is in the snapshot;
	// the caller decides between external and internal afterwards.
	var candidates []string
	for _, imp := range unit.Imports {
		if imp.Alias != "" {
			continue
		}
		if path.Base(imp.Path) == base {
			candidates = appendUnique(candidates, imp.Path)
		}
	}
	sort.Strings(candidates)
	switch len(candidates) {
	case 1:
		return candidates[0], scg.LookupFound
	case 0:
	default:
		return candidates[0], scg.LookupAmbiguous
	}
	// Finally an import whose package name differs from its path base, matched by
	// base name inside the snapshot. That is a heuristic.
	if pkg, outcome := idx.PackageByBaseName(base); outcome != scg.LookupNotFound {
		return pkg, outcome
	}
	return "", scg.LookupNotFound
}

func resolved(ref scg.SymbolRef, conf scg.Confidence, detail string) scg.CallResolution {
	res := scg.CallResolution{
		TargetID:        ref.ID,
		TargetQualified: ref.QualifiedName,
		Resolution:      scg.Resolved,
		Confidence:      conf,
		Detail:          detail,
	}
	if conf == scg.Inferred {
		res.Resolution = scg.ResolvedBestEffort
	}
	return res
}

// lookupCallTarget resolves the call an inferred receiver came from, so its
// result type can be read from the symbol table.
func lookupCallTarget(parts []string, file scg.FrontendFile, unit *scg.FileUnit, idx scg.SymbolIndex) (scg.SymbolRef, scg.LookupOutcome) {
	switch len(parts) {
	case 1:
		if ref, outcome := idx.LookupPackageSymbol(file.PackagePath, parts[0]); outcome == scg.LookupFound {
			return ref, outcome
		}
		for _, imp := range unit.Imports {
			if imp.Alias != "." {
				continue
			}
			if ref, outcome := idx.LookupPackageSymbol(imp.Path, parts[0]); outcome == scg.LookupFound {
				return ref, outcome
			}
		}
		return scg.SymbolRef{}, scg.LookupNotFound
	case 2:
		importPath, outcome := importPathFor(parts[0], file, unit, idx)
		if outcome != scg.LookupFound {
			return scg.SymbolRef{}, outcome
		}
		return idx.LookupPackageSymbol(importPath, parts[1])
	default:
		return scg.SymbolRef{}, scg.LookupNotFound
	}
}

// callTargetParts describes the callee of a call expression in a form the
// resolver can look up later: ["New"] or ["store", "New"].
func callTargetParts(expr ast.Expr) ([]string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	switch fun := unwrap(call.Fun).(type) {
	case *ast.Ident:
		return []string{fun.Name}, true
	case *ast.SelectorExpr:
		if base, ok := unwrap(fun.X).(*ast.Ident); ok {
			return []string{base.Name, fun.Sel.Name}, true
		}
	}
	return nil, false
}

// qualify prefixes a type name with its package path when one is known.
func qualify(pkgPath, name string) string {
	if pkgPath == "" {
		return name
	}
	return pkgPath + "." + name
}

// resultTypeName returns the named type of a single result, if there is one.
// Multiple results, unnamed composite results and builtin types return "".
func resultTypeName(ft *ast.FuncType) string {
	if ft == nil || ft.Results == nil || len(ft.Results.List) != 1 {
		return ""
	}
	field := ft.Results.List[0]
	if len(field.Names) > 1 {
		return ""
	}
	return namedTypeName(field.Type)
}

// callThroughValue reports whether a symbol names a value rather than code.
// Calling a function-typed variable is dynamic dispatch, not a direct call.
func callThroughValue(ref scg.SymbolRef) bool {
	return ref.Kind == scg.KindVar || ref.Kind == scg.KindConst
}

func ambiguous(qualified, detail string) scg.CallResolution {
	return scg.CallResolution{Resolution: scg.Ambiguous, Confidence: scg.Unresolved, TargetQualified: qualified, Detail: detail}
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

// namedTypeName returns the type name of an expression only when it is
// unambiguously a named type (T, *T, pkg.T, *pkg.T). Composite types such as
// []T or map[K]V return "", because binding them would produce false method
// resolutions.
func namedTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		if goBuiltins[e.Name] {
			return ""
		}
		switch e.Name {
		case "string", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64",
			"float32", "float64", "bool", "byte", "rune", "error", "any", "uintptr", "complex64", "complex128":
			return ""
		}
		return e.Name
	case *ast.StarExpr:
		return namedTypeName(e.X)
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.ParenExpr:
		return namedTypeName(e.X)
	default:
		return ""
	}
}

// inferredTypeName tries to name the type of an expression from its shape, for
// `x := expr` and `var x = expr`. The result is used as a hint only, and edges
// derived from it are marked best effort.
func inferredTypeName(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return inferredTypeName(e.X)
		}
	case *ast.CompositeLit:
		if name := namedTypeName(e.Type); name != "" {
			return name, true
		}
		return "", false
	case *ast.CallExpr:
		// Only new(T) is treated as a type source. A bare call could be a
		// conversion or a constructor, and guessing wrongly would create edges to
		// methods that do not exist.
		fun := unwrap(e.Fun)
		if ident, ok := fun.(*ast.Ident); ok && ident.Name == "new" && len(e.Args) == 1 {
			if name := namedTypeName(e.Args[0]); name != "" {
				return name, true
			}
		}
	case *ast.Ident:
		return "", false
	}
	return "", false
}

// signatureOf renders a function signature without type checking.
func signatureOf(ft *ast.FuncType) string {
	if ft == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("func(")
	if ft.Params != nil {
		params := make([]string, 0, len(ft.Params.List))
		for _, field := range ft.Params.List {
			typeName := types.ExprString(field.Type)
			if len(field.Names) == 0 {
				params = append(params, typeName)
				continue
			}
			for _, name := range field.Names {
				params = append(params, name.Name+" "+typeName)
			}
		}
		b.WriteString(strings.Join(params, ", "))
	}
	b.WriteString(")")
	if ft.Results != nil && len(ft.Results.List) > 0 {
		results := make([]string, 0, len(ft.Results.List))
		for _, field := range ft.Results.List {
			typeName := types.ExprString(field.Type)
			for range field.Names {
				results = append(results, typeName)
			}
			if len(field.Names) == 0 {
				results = append(results, typeName)
			}
		}
		if len(results) == 1 {
			b.WriteString(" " + results[0])
		} else {
			b.WriteString(" (" + strings.Join(results, ", ") + ")")
		}
	}
	return b.String()
}

// kindSignature renders a type declaration's right-hand side.
func kindSignature(spec *ast.TypeSpec) string {
	if spec.Type == nil {
		return ""
	}
	if _, ok := spec.Type.(*ast.InterfaceType); ok {
		return "interface"
	}
	return types.ExprString(spec.Type)
}

func lineOf(fset *token.FileSet, pos token.Pos) int { return fset.Position(pos).Line }

func colOf(fset *token.FileSet, pos token.Pos) int { return fset.Position(pos).Column }
