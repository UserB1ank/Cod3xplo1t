package scg

import (
	"context"
	"sort"
	"strings"
)

// Frontend is a language analyzer. Frontends are pluggable: adding a language
// means implementing this interface, not editing the builder.
type Frontend interface {
	// Name identifies the frontend in graph metadata and cache keys.
	Name() string
	// Version changes whenever the frontend's output could change.
	Version() string
	// Languages lists the language names this frontend handles, using the same
	// names as the repository analyzer's language table.
	Languages() []string
	// Parse analyses one file. It must not fail for malformed input: a file that
	// cannot be parsed is returned with a partial or unparsed status so the
	// failure becomes visible coverage, not an error that hides the file.
	Parse(ctx context.Context, file FrontendFile) (*FileUnit, error)
}

// Packager is an optional frontend capability: mapping a file's directory to the
// language's package/module path, which is what cross-package resolution needs.
type Packager interface {
	PackagePath(module Module, dir string) string
}

// Resolver is an optional frontend capability: turning a call reference into a
// target symbol using the snapshot-wide index.
type Resolver interface {
	ResolveCall(call CallRef, file FrontendFile, unit *FileUnit, idx SymbolIndex) CallResolution
}

// FrontendFile is the input to a frontend: one file of the frozen snapshot.
type FrontendFile struct {
	Path string // repository-relative, slash separated
	// Language is the language attributed by the repository analyzer's table.
	Language string
	// PackagePath is the frontend's package identifier for this file's directory
	// (a Go import path, a Python dotted module, ...). Empty when unknown.
	PackagePath string
	// ModulePath is the module name declared by the module manifest, when any.
	ModulePath string
	Content    []byte
}

// CallForm classifies the syntactic shape of a call.
type CallForm string

const (
	// FormIdent is a bare identifier: f(...).
	FormIdent CallForm = "identifier"
	// FormSelector is a selector: pkg.F(...) or x.M(...).
	FormSelector CallForm = "selector"
	// FormGeneric is an instantiated call: F[T](...) or pkg.F[T](...).
	FormGeneric CallForm = "generic"
	// FormFuncLiteral is an immediately invoked function literal.
	FormFuncLiteral CallForm = "func_literal"
)

// CallRef is one call expression found by a frontend.
type CallRef struct {
	// EnclosingDecl indexes into FileUnit.Declarations; -1 means file scope.
	EnclosingDecl int
	Line          int
	Col           int
	// Text is the callee as written.
	Text string
	// Parts is the selector chain: ["saveFile"], ["gin", "Default"], ["x", "M"].
	Parts []string
	Form  CallForm
	// ReceiverType is the inferred type name of a selector base, when the
	// frontend could infer one. Hint explains how reliable that inference is.
	ReceiverType string
	// Hint carries frontend-specific evidence, for example
	// "receiver_parameter" (observed) or "receiver_inferred" (best effort).
	Hint string
	// InferTargetParts names the call whose result type the receiver was
	// assigned from (for example ["store", "New"] for `s := store.New()`).
	// Resolving it is a second, evidence-based step: look up that function's
	// declared result type, then the method on it.
	InferTargetParts []string
	// ReceiverFrom names the call a selector's receiver was bound from, which is
	// how route registrations are attributed to a framework without type
	// checking: `r := gin.Default()` makes `r.GET(...)` a gin route.
	ReceiverFrom []string
	Args         int
	// ArgExprs describes the arguments the frontend could describe. Symbolic
	// arguments are resolved later against the snapshot-wide index.
	ArgExprs []ArgExpr
}

// ArgExpr is one argument as the frontend sees it.
type ArgExpr struct {
	Position    int
	Kind        ArgKind
	Text        string
	StringValue string
	// Parts/Form/Hint describe a symbol-shaped argument so the builder can
	// resolve it exactly like a call target.
	Parts            []string
	Form             CallForm
	ReceiverType     string
	Hint             string
	InferTargetParts []string
}

// Hint values shared by frontends.
const (
	// HintReceiverParameter means the receiver's type came from a declared
	// parameter or variable type: an observed fact.
	HintReceiverParameter = "receiver_parameter"
	// HintReceiverInferred means the receiver's type came from a `:=` heuristic:
	// an inferred fact.
	HintReceiverInferred = "receiver_inferred"
	// HintTypeConversion marks a call-shaped expression whose target is a type.
	HintTypeConversion = "type_conversion"
)

// Import is one import declaration of a file.
type Import struct {
	// Alias is the local name, which may be a real alias, "_" or ".".
	Alias string
	// Path is the imported package path as written.
	Path string
	Line int
}

// Declaration is one symbol declaration found by a frontend.
type Declaration struct {
	Kind      SymbolKind
	Name      string
	Receiver  string
	Signature string
	// ResultType is the named type of the single result, when there is exactly
	// one. It is what makes `x := pkg.New()` resolvable without type checking.
	ResultType string
	Exported   bool
	StartLine  int
	EndLine    int
	StartCol   int
	EndCol     int
	// PackageName is the language-level package of the file (Go: package foo).
	PackageName string
}

// FileUnit is the parsed content of one file.
type FileUnit struct {
	Language     string
	PackageName  string
	Imports      []Import
	Declarations []Declaration
	Calls        []CallRef
	// Status is ok, partial or unparsed.
	Status string
	// Error describes a parse failure in the frontend's own words.
	Error string
	// Notes are frontend-specific coverage statements.
	Notes []string
}

// Parse statuses for File.ParseStatus.
const (
	ParseOK = "ok"
	// ParseNotSource marks a file that is not source code at all: a data format
	// or a tooling descriptor. It is a node for traceability, not a gap.
	ParseNotSource   = "not_source"
	ParsePartial     = "partial"
	ParseUnparsed    = "unparsed"
	ParseUnsupported = "unsupported_language"
)

// Registry holds the available frontends.
type Registry struct {
	frontends []Frontend
}

// NewRegistry builds a registry from the given frontends.
func NewRegistry(frontends ...Frontend) *Registry {
	r := &Registry{}
	for _, f := range frontends {
		r.Register(f)
	}
	return r
}

// Register adds a frontend, ignoring a duplicate name.
func (r *Registry) Register(f Frontend) {
	if f == nil {
		return
	}
	for _, existing := range r.frontends {
		if existing.Name() == f.Name() {
			return
		}
	}
	r.frontends = append(r.frontends, f)
}

// Frontends returns the registered frontends in evaluation order.
func (r *Registry) Frontends() []Frontend {
	return append([]Frontend(nil), r.frontends...)
}

// For returns the frontend that handles a language, if any.
func (r *Registry) For(language string) (Frontend, bool) {
	for _, f := range r.frontends {
		for _, l := range f.Languages() {
			if strings.EqualFold(l, language) {
				return f, true
			}
		}
	}
	return nil, false
}

// Info lists every registered frontend, sorted by name for stable metadata.
func (r *Registry) Info() []FrontendInfo {
	out := make([]FrontendInfo, 0, len(r.frontends))
	for _, f := range r.frontends {
		langs := append([]string(nil), f.Languages()...)
		sort.Strings(langs)
		out = append(out, FrontendInfo{Name: f.Name(), Version: f.Version(), Language: langs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LookupOutcome distinguishes the three answers an index lookup can give. The
// difference matters: "not found" and "several candidates" lead to different
// resolution statuses.
type LookupOutcome string

const (
	// LookupFound means exactly one candidate matched.
	LookupFound LookupOutcome = "found"
	// LookupNotFound means nothing matched.
	LookupNotFound LookupOutcome = "not_found"
	// LookupAmbiguous means more than one candidate matched.
	LookupAmbiguous LookupOutcome = "ambiguous"
)

// SymbolRef is what the index returns about a symbol.
type SymbolRef struct {
	ID            string
	QualifiedName string
	Kind          SymbolKind
	PackagePath   string
	TypeName      string
	ResultType    string
	File          string
	Line          int
}

// SymbolIndex is the snapshot-wide symbol table a resolver consults. It is
// read-only: frontends cannot add to or mutate the index.
type SymbolIndex interface {
	// LookupPackageSymbol finds a package-level (non-method) symbol.
	LookupPackageSymbol(pkgPath, name string) (SymbolRef, LookupOutcome)
	// LookupMethod finds a method of a named type.
	LookupMethod(pkgPath, typeName, method string) (SymbolRef, LookupOutcome)
	// PackageExists reports whether a package path is inside the snapshot.
	PackageExists(pkgPath string) bool
	// PackageByBaseName resolves a bare package name (an import's local name)
	// to a package path inside the snapshot, when that is unambiguous.
	PackageByBaseName(base string) (string, LookupOutcome)
}

// CallResolution is the outcome of resolving one call reference.
type CallResolution struct {
	TargetID        string
	TargetQualified string
	Resolution      Resolution
	Confidence      Confidence
	Detail          string
}

// resolved builds a resolution for a found symbol, choosing REFERENCES for
// type-shaped targets (conversions, type uses) and CALLS otherwise.
func resolvedTarget(ref SymbolRef, conf Confidence, detail string) CallResolution {
	res := CallResolution{
		TargetID:        ref.ID,
		TargetQualified: ref.QualifiedName,
		Resolution:      Resolved,
		Confidence:      conf,
		Detail:          detail,
	}
	if conf == Inferred {
		res.Resolution = ResolvedBestEffort
	}
	return res
}

// unresolved builds a resolution that records why no target was found.
func unresolved(r Resolution, conf Confidence, qualified, detail string) CallResolution {
	return CallResolution{Resolution: r, Confidence: conf, TargetQualified: qualified, Detail: detail}
}
