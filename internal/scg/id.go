package scg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Identifier layout: a short prefix that says what the id points at, followed by
// a 128-bit digest. Ids are content-derived, so the same snapshot always yields
// the same ids and two different facts never share one.
const (
	moduleIDPrefix   = "mod-"
	fileIDPrefix     = "file-"
	symbolIDPrefix   = "sym-"
	callSiteIDPrefix = "cs-"
	edgeIDPrefix     = "edge-"
	graphIDPrefix    = "graph-"
	idBytes          = 16
)

func digest(fields ...string) string {
	h := sha256.New()
	for _, f := range fields {
		writeField(h, f)
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:idBytes])
}

func writeField(h io.Writer, s string) {
	fmt.Fprintf(h, "%d:%s", len(s), s)
}

// ModuleID identifies a module inside a snapshot.
func ModuleID(snapshotID, path string) string {
	return moduleIDPrefix + digest("codexploit/scg/module/v1", snapshotID, canonicalPath(path))
}

// FileID identifies a file inside a snapshot.
func FileID(snapshotID, path string) string {
	return fileIDPrefix + digest("codexploit/scg/file/v1", snapshotID, canonicalPath(path))
}

// SymbolID follows docs/codexploit_implementation_guide.md §4.1:
//
//	symbol_id = hash(snapshot_id, language, canonical_file, qualified_name, signature, location)
//
// Only the declaration's start position participates, so editing a function body
// does not change its id. Ids are stable within one snapshot; across versions
// they are matched, not assumed equal.
func SymbolID(snapshotID, language, file, qualifiedName, signature string, loc Location) string {
	return symbolIDPrefix + digest(
		"codexploit/scg/symbol/v1",
		snapshotID,
		language,
		canonicalPath(file),
		qualifiedName,
		signature,
		fmt.Sprintf("%d:%d", loc.Line, loc.Col),
	)
}

// CallSiteID identifies a call expression by position and callee text.
func CallSiteID(snapshotID, file string, line, col int, calleeText string) string {
	return callSiteIDPrefix + digest(
		"codexploit/scg/call_site/v1",
		snapshotID,
		canonicalPath(file),
		fmt.Sprintf("%d:%d", line, col),
		calleeText,
	)
}

// EdgeID identifies a relationship. Two CALLS edges from the same caller to the
// same callee at different call sites stay distinct.
func EdgeID(from, to string, kind EdgeKind, loc Location, callSiteID string) string {
	return edgeIDPrefix + digest(
		"codexploit/scg/edge/v1",
		from,
		to,
		string(kind),
		canonicalPath(loc.File),
		fmt.Sprintf("%d:%d", loc.Line, loc.Col),
		callSiteID,
	)
}

// GraphVersion follows the cache-key shape in design doc §9: the snapshot plus
// the engine and the exact rule set (here: the frontend set) that produced it.
// A graph built by different frontends is a different graph.
func GraphVersion(snapshotID string, engine Engine, frontends []FrontendInfo) string {
	lines := make([]string, 0, len(frontends))
	for _, f := range frontends {
		lines = append(lines, fmt.Sprintf("%s@%s[%s]", f.Name, f.Version, strings.Join(f.Language, ",")))
	}
	sort.Strings(lines)
	return graphIDPrefix + digest(
		"codexploit/scg/graph/v1",
		snapshotID,
		engine.Name,
		engine.Version,
		strings.Join(lines, ";"),
	)
}

// canonicalPath normalises a repository-relative path for hashing.
func canonicalPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return p
}
