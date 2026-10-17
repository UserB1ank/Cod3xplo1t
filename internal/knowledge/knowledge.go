// Package knowledge exposes a pinned, project-scoped read view over the code
// graph, the attack surface and the path queue.
//
// A view records the exact layer versions of one snapshot. Every read is
// answered from that pin, so two tasks that share a snapshot read the same
// facts, and a rebuild never changes an already-open view silently: the next
// read reports ErrViewSuperseded instead.
package knowledge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

var (
	// ErrNotFound reports that the view, project or snapshot is not part of the
	// requested scope. It deliberately does not distinguish the three.
	ErrNotFound = errors.New("knowledge: view or scope not found")
	// ErrNoGraph reports that the snapshot has no code graph yet.
	ErrNoGraph = errors.New("knowledge: snapshot has no code graph")
	// ErrLayerUnavailable reports a query against a layer the view did not pin.
	ErrLayerUnavailable = errors.New("knowledge: layer is not part of this view")
	// ErrViewSuperseded reports that a layer was rebuilt after the view opened.
	ErrViewSuperseded = errors.New("knowledge: view was superseded by a rebuild")
	// ErrInvalid reports a malformed view id, cursor or query.
	ErrInvalid = errors.New("knowledge: invalid view or query")
)

// Layer names of the unified graph, as defined by the v1 interface design.
const (
	LayerSCG   = "scg"
	LayerASG   = "asg"
	LayerPaths = "paths"
)

// Layer states. A missing capability is stated, never silently skipped.
const (
	StatusAvailable   = "available"
	StatusNotBuilt    = "not_built"
	StatusUnavailable = "unavailable"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// Scope is the data boundary of a view: one project and one immutable snapshot.
type Scope struct {
	ProjectID  string `json:"project_id"`
	SnapshotID string `json:"snapshot_id"`
}

// LayerInfo is the pinned state of one layer.
type LayerInfo struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	BuiltAt string `json:"built_at,omitempty"`
	Detail  string `json:"detail,omitempty"`
	// Tasks and Items count the path layer's audits and paths for this pin.
	Tasks int `json:"tasks,omitempty"`
	Items int `json:"items,omitempty"`
}

// View is one immutable pin of a scope's layer versions.
type View struct {
	ID          string               `json:"view_id"`
	Revision    string               `json:"revision"`
	Scope       Scope                `json:"scope"`
	Layers      map[string]LayerInfo `json:"layers"`
	Engine      scg.Engine           `json:"engine"`
	Coverage    scg.Coverage         `json:"coverage"`
	Limitations []string             `json:"limitations"`
}

// Has reports whether the view pinned a layer.
func (v *View) Has(layer string) bool {
	_, ok := v.Layers[layer]
	return ok
}

// ScopeStore resolves a snapshot's project ownership.
type ScopeStore interface {
	GetSnapshot(ctx context.Context, id string) (*repository.Snapshot, error)
	ListSnapshots(ctx context.Context, projectID string) ([]storage.SnapshotRecord, error)
}

// GraphReader is the code-graph port the view reads through.
type GraphReader interface {
	Summary(ctx context.Context, snapshotID string) (*scg.Summary, error)
	Symbols(ctx context.Context, snapshotID string, q graph.SymbolQuery) (*graph.SymbolPage, error)
	Symbol(ctx context.Context, snapshotID, symbolID string, opt graph.Options) (*scg.Symbol, graph.Meta, error)
	Callers(ctx context.Context, snapshotID, symbolID string, opt graph.Options) (*graph.Neighborhood, error)
	Callees(ctx context.Context, snapshotID, symbolID string, opt graph.Options) (*graph.Neighborhood, error)
	Slice(ctx context.Context, snapshotID string, req graph.SliceRequest) (*graph.CodeSlice, error)
}

// SurfaceReader is the attack-surface port. A deployment may serve the SCG
// without it, which is reported as an unavailable layer.
type SurfaceReader interface {
	Summary(ctx context.Context, snapshotID string) (*asg.Summary, error)
	Nodes(ctx context.Context, snapshotID string, q graph.ASGNodeQuery) (*graph.ASGNodePage, error)
	Node(ctx context.Context, snapshotID, nodeID string) (*graph.ASGNodeView, error)
}

// ArtifactReader resolves the raw artifacts provenance points at. It is
// optional: a deployment without artifact storage simply reports none.
type ArtifactReader interface {
	ArtifactScope(ctx context.Context, project, snapshot string) (artifact.Scope, error)
	ListArtifacts(ctx context.Context, scope artifact.Scope, cursor string, limit int) ([]artifact.Ref, error)
}

// PathReader is the path-engine read port.
type PathReader interface {
	Audits(q path.AuditQuery) ([]path.Audit, int, error)
	Paths(q path.PathQuery) ([]path.Path, int, error)
}

// Deps are the ports a reader is wired from.
type Deps struct {
	Store     ScopeStore
	Graph     GraphReader
	ASG       SurfaceReader
	Queue     PathReader
	Artifacts ArtifactReader
}

// Reader answers view-scoped knowledge queries.
type Reader struct {
	Store     ScopeStore
	Graph     GraphReader
	ASG       SurfaceReader
	Queue     PathReader
	Artifacts ArtifactReader
}

// New builds a reader. Graph is required; ASG, Queue and Artifacts may be nil,
// in which case the corresponding capability is reported unavailable instead of
// skipped.
func New(deps Deps) *Reader {
	return &Reader{Store: deps.Store, Graph: deps.Graph, ASG: deps.ASG, Queue: deps.Queue, Artifacts: deps.Artifacts}
}

// descriptor is the self-describing view pin. view_id is its encoding, so a
// view survives restarts without mutable server state and the pin is always
// verifiable against the store.
type descriptor struct {
	Project    string   `json:"p"`
	Snapshot   string   `json:"s"`
	SCG        string   `json:"g"`
	SCGBuiltAt string   `json:"gb"`
	ASG        string   `json:"a,omitempty"`
	ASGBuiltAt string   `json:"ab,omitempty"`
	Layers     []string `json:"l"`
}

// normalizeLayers always includes the code graph: every other layer is derived
// from it, so a view without the SCG would be a view of nothing.
func normalizeLayers(layers []string) ([]string, error) {
	if len(layers) == 0 {
		layers = []string{LayerSCG, LayerASG, LayerPaths}
	}
	seen := map[string]bool{LayerSCG: true}
	out := []string{LayerSCG}
	for _, layer := range layers {
		switch layer {
		case LayerSCG, LayerASG, LayerPaths:
		default:
			return nil, fmt.Errorf("%w: unknown layer %q", ErrInvalid, layer)
		}
		if !seen[layer] {
			seen[layer] = true
			out = append(out, layer)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ScopeOf resolves the scope a view id belongs to and refuses a project that
// does not own it, so a project-scoped route can answer a view-scoped query.
func (r *Reader) ScopeOf(ctx context.Context, projectID, viewID string) (Scope, error) {
	d, err := decodeDescriptor(viewID)
	if err != nil {
		return Scope{}, err
	}
	if d.Project != projectID {
		return Scope{}, ErrNotFound
	}
	scope := Scope{ProjectID: d.Project, SnapshotID: d.Snapshot}
	if err := r.checkScope(ctx, scope); err != nil {
		return Scope{}, err
	}
	return scope, nil
}

func encodeDescriptor(d descriptor) (string, string, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return "", "", err
	}
	id := "view-" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	return id, hex.EncodeToString(sum[:8]), nil
}

func decodeDescriptor(viewID string) (descriptor, error) {
	var d descriptor
	if !strings.HasPrefix(viewID, "view-") {
		return d, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(viewID, "view-"))
	if err != nil {
		return d, ErrInvalid
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, ErrInvalid
	}
	if d.Project == "" || d.Snapshot == "" || d.SCG == "" {
		return d, ErrInvalid
	}
	if _, err := normalizeLayers(d.Layers); err != nil {
		return d, ErrInvalid
	}
	return d, nil
}

// checkScope proves that the snapshot exists, belongs to the project and has
// not been retired. A mismatch is a not-found answer on purpose: the API must
// not reveal that another project owns the id.
func (r *Reader) checkScope(ctx context.Context, scope Scope) error {
	if scope.ProjectID == "" || scope.SnapshotID == "" {
		return ErrInvalid
	}
	if _, err := r.Store.GetSnapshot(ctx, scope.SnapshotID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	records, err := r.Store.ListSnapshots(ctx, scope.ProjectID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	for _, record := range records {
		if record.SnapshotID == scope.SnapshotID {
			return nil
		}
	}
	return ErrNotFound
}

// OpenView pins the current layer versions of a scope. Requesting no layers
// means all three; a requested layer that is missing is reported with its state
// rather than silently dropped.
func (r *Reader) OpenView(ctx context.Context, scope Scope, layers []string) (*View, error) {
	if err := r.checkScope(ctx, scope); err != nil {
		return nil, err
	}
	requested, err := normalizeLayers(layers)
	if err != nil {
		return nil, err
	}
	if r.Graph == nil {
		return nil, ErrNoGraph
	}
	summary, err := r.Graph.Summary(ctx, scope.SnapshotID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, graph.ErrNoGraph) {
			return nil, ErrNoGraph
		}
		return nil, err
	}
	d := descriptor{Project: scope.ProjectID, Snapshot: scope.SnapshotID, SCG: summary.GraphVersion, SCGBuiltAt: summary.BuiltAt, Layers: requested}
	info := map[string]LayerInfo{
		LayerSCG: {Status: StatusAvailable, Version: summary.GraphVersion, BuiltAt: summary.BuiltAt},
	}
	for _, layer := range requested {
		switch layer {
		case LayerSCG:
			continue
		case LayerASG:
			info[LayerASG] = r.surfaceState(ctx, scope.SnapshotID, &d)
		case LayerPaths:
			info[LayerPaths] = r.pathsState(ctx, scope.SnapshotID, summary.GraphVersion, d.ASG)
		}
	}
	id, revision, err := encodeDescriptor(d)
	if err != nil {
		return nil, err
	}
	return &View{
		ID:          id,
		Revision:    revision,
		Scope:       scope,
		Layers:      info,
		Engine:      summary.Engine,
		Coverage:    summary.Coverage,
		Limitations: summary.Limitations,
	}, nil
}

// surfaceState reports the attack-surface layer and records its version in the
// view pin when it is available.
func (r *Reader) surfaceState(ctx context.Context, snapshotID string, d *descriptor) LayerInfo {
	if r.ASG == nil {
		return LayerInfo{Status: StatusUnavailable, Detail: "this deployment does not serve the attack surface"}
	}
	summary, err := r.ASG.Summary(ctx, snapshotID)
	if err != nil {
		if errors.Is(err, graph.ErrNoASG) || errors.Is(err, storage.ErrNotFound) {
			return LayerInfo{Status: StatusNotBuilt, Detail: "this snapshot has no attack surface yet"}
		}
		return LayerInfo{Status: StatusUnavailable, Detail: "the attack surface is unavailable"}
	}
	d.ASG = summary.ASGVersion
	d.ASGBuiltAt = summary.BuiltAt
	return LayerInfo{Status: StatusAvailable, Version: summary.ASGVersion, BuiltAt: summary.BuiltAt}
}

// pathsState counts the audits and paths pinned to the view's versions.
func (r *Reader) pathsState(ctx context.Context, snapshotID, scgVersion, asgVersion string) LayerInfo {
	if r.Queue == nil {
		return LayerInfo{Status: StatusUnavailable, Detail: "this deployment does not serve the path engine"}
	}
	audits, _, err := r.Queue.Audits(path.AuditQuery{SnapshotID: snapshotID, Limit: 1000})
	if err != nil {
		return LayerInfo{Status: StatusUnavailable, Detail: "the path engine is unavailable"}
	}
	count := 0
	for _, audit := range audits {
		if !pinnedAudit(audit, scgVersion, asgVersion) {
			continue
		}
		count++
	}
	return LayerInfo{Status: StatusAvailable, Tasks: count}
}

func pinnedAudit(audit path.Audit, scgVersion, asgVersion string) bool {
	if audit.SCGVersion != scgVersion {
		return false
	}
	return asgVersion == "" || audit.ASGVersion == asgVersion
}

// loadView decodes a view id, proves it belongs to the requested scope and that
// its pin is still the stored version.
func (r *Reader) loadView(ctx context.Context, scope Scope, viewID string) (*View, descriptor, error) {
	d, err := decodeDescriptor(viewID)
	if err != nil {
		return nil, descriptor{}, err
	}
	if d.Project != scope.ProjectID || d.Snapshot != scope.SnapshotID {
		return nil, descriptor{}, ErrNotFound
	}
	if err := r.checkScope(ctx, scope); err != nil {
		return nil, descriptor{}, err
	}
	summary, err := r.Graph.Summary(ctx, scope.SnapshotID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, graph.ErrNoGraph) {
			return nil, descriptor{}, ErrViewSuperseded
		}
		return nil, descriptor{}, err
	}
	// BuiltAt is part of the pin because GraphVersion names the snapshot,
	// engine and frontends, not the document: a rebuild of the same snapshot
	// keeps the version but must still supersede an open view.
	if summary.GraphVersion != d.SCG || summary.BuiltAt != d.SCGBuiltAt {
		return nil, descriptor{}, fmt.Errorf("%w: code graph %s@%s is now %s@%s", ErrViewSuperseded, d.SCG, d.SCGBuiltAt, summary.GraphVersion, summary.BuiltAt)
	}
	if d.ASG != "" {
		if r.ASG == nil {
			return nil, descriptor{}, ErrViewSuperseded
		}
		current, err := r.ASG.Summary(ctx, scope.SnapshotID)
		if err != nil || current.ASGVersion != d.ASG || current.BuiltAt != d.ASGBuiltAt {
			return nil, descriptor{}, fmt.Errorf("%w: attack surface %s changed", ErrViewSuperseded, d.ASG)
		}
	}
	id, revision, err := encodeDescriptor(d)
	if err != nil {
		return nil, descriptor{}, err
	}
	info := map[string]LayerInfo{LayerSCG: {Status: StatusAvailable, Version: summary.GraphVersion, BuiltAt: summary.BuiltAt}}
	for _, layer := range d.Layers {
		switch layer {
		case LayerSCG:
		case LayerASG:
			if d.ASG == "" {
				info[LayerASG] = LayerInfo{Status: StatusNotBuilt, Detail: "this view did not pin an attack surface"}
				continue
			}
			info[LayerASG] = LayerInfo{Status: StatusAvailable, Version: d.ASG}
		case LayerPaths:
			info[LayerPaths] = r.pathsState(ctx, scope.SnapshotID, d.SCG, d.ASG)
		}
	}
	return &View{
		ID:          id,
		Revision:    revision,
		Scope:       scope,
		Layers:      info,
		Engine:      summary.Engine,
		Coverage:    summary.Coverage,
		Limitations: summary.Limitations,
	}, d, nil
}

// requireLayer rejects a query against a layer the view did not pin.
func requireLayer(view *View, layer string) error {
	if !view.Has(layer) {
		return fmt.Errorf("%w: %s", ErrLayerUnavailable, layer)
	}
	if info := view.Layers[layer]; info.Status != StatusAvailable {
		return fmt.Errorf("%w: %s is %s", ErrLayerUnavailable, layer, info.Status)
	}
	return nil
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

func encodeCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("o:%d", offset)))
}

func decodeCursor(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, ErrInvalid
	}
	var offset int
	if _, err := fmt.Sscanf(string(raw), "o:%d", &offset); err != nil || offset < 0 {
		return 0, ErrInvalid
	}
	return offset, nil
}
