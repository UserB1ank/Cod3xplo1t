package scg

import (
	"sort"
	"strings"
)

// symbolIndex is the snapshot-wide symbol table built before call resolution.
// It answers the three questions a resolver asks, and it distinguishes "not
// found" from "several candidates" because those lead to different resolution
// statuses.
type symbolIndex struct {
	byID      map[string]SymbolRef
	qualified map[string][]SymbolRef
	pkgSymbol map[string]map[string][]SymbolRef // pkgPath -> name -> refs
	method    map[string]map[string][]SymbolRef // pkgPath|type -> method -> refs
	packages  map[string]bool
	byBase    map[string][]string // package base name -> package paths
}

func newSymbolIndex() *symbolIndex {
	return &symbolIndex{
		byID:      map[string]SymbolRef{},
		qualified: map[string][]SymbolRef{},
		pkgSymbol: map[string]map[string][]SymbolRef{},
		method:    map[string]map[string][]SymbolRef{},
		packages:  map[string]bool{},
		byBase:    map[string][]string{},
	}
}

// add registers one symbol under its qualified name and its package.
func (ix *symbolIndex) add(pkgPath string, sym Symbol) {
	ref := SymbolRef{
		ID:            sym.ID,
		QualifiedName: sym.QualifiedName,
		Kind:          sym.Kind,
		PackagePath:   pkgPath,
		TypeName:      sym.Receiver,
		ResultType:    sym.ResultType,
		File:          sym.File,
		Line:          sym.StartLine,
	}
	ix.byID[sym.ID] = ref
	ix.qualified[sym.QualifiedName] = append(ix.qualified[sym.QualifiedName], ref)
	if pkgPath != "" {
		ix.packages[pkgPath] = true
		base := pkgPath
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		ix.byBase[base] = appendUnique(ix.byBase[base], pkgPath)
	}
	if sym.Kind == KindMethod && sym.Receiver != "" {
		key := methodKey(pkgPath, sym.Receiver)
		if ix.method[key] == nil {
			ix.method[key] = map[string][]SymbolRef{}
		}
		ix.method[key][sym.Name] = append(ix.method[key][sym.Name], ref)
		return
	}
	if pkgPath == "" {
		return
	}
	if ix.pkgSymbol[pkgPath] == nil {
		ix.pkgSymbol[pkgPath] = map[string][]SymbolRef{}
	}
	ix.pkgSymbol[pkgPath][sym.Name] = append(ix.pkgSymbol[pkgPath][sym.Name], ref)
}

// LookupPackageSymbol implements SymbolIndex.
func (ix *symbolIndex) LookupPackageSymbol(pkgPath, name string) (SymbolRef, LookupOutcome) {
	byName, ok := ix.pkgSymbol[pkgPath]
	if !ok {
		return SymbolRef{}, LookupNotFound
	}
	return pick(byName[name])
}

// LookupMethod implements SymbolIndex.
func (ix *symbolIndex) LookupMethod(pkgPath, typeName, method string) (SymbolRef, LookupOutcome) {
	byMethod, ok := ix.method[methodKey(pkgPath, typeName)]
	if !ok {
		return SymbolRef{}, LookupNotFound
	}
	return pick(byMethod[method])
}

// PackageExists implements SymbolIndex.
func (ix *symbolIndex) PackageExists(pkgPath string) bool { return ix.packages[pkgPath] }

// PackageByBaseName implements SymbolIndex. Several packages can share a base
// name (for example two "config" directories), so ambiguity is reported instead
// of a guess.
func (ix *symbolIndex) PackageByBaseName(base string) (string, LookupOutcome) {
	paths := ix.byBase[base]
	switch len(paths) {
	case 0:
		return "", LookupNotFound
	case 1:
		return paths[0], LookupFound
	default:
		sorted := append([]string(nil), paths...)
		sort.Strings(sorted)
		return sorted[0], LookupAmbiguous
	}
}

func methodKey(pkgPath, typeName string) string { return pkgPath + "|" + typeName }

// pick converts candidate refs into a lookup outcome: exactly one candidate is
// a hit, several candidates are ambiguous, none is a miss.
func pick(refs []SymbolRef) (SymbolRef, LookupOutcome) {
	switch len(refs) {
	case 0:
		return SymbolRef{}, LookupNotFound
	case 1:
		return refs[0], LookupFound
	default:
		return refs[0], LookupAmbiguous
	}
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

// buildIndex assembles the index from every parsed file.
func buildIndex(units []parsedFile) *symbolIndex {
	ix := newSymbolIndex()
	for _, pf := range units {
		for _, sym := range pf.symbols {
			ix.add(pf.pkgPath, sym)
		}
	}
	return ix
}
